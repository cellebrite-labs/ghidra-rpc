"""Integration tests for ghidra-rpc against a real Ghidra headless instance.

These tests start a real Ghidra daemon in headless mode, load
``tests/fixtures/testapp`` (a small purpose-built x86-64 ELF binary that
lives in the repository), and exercise the full RPC API surface to verify
correctness.

Prerequisites
-------------
- ``GHIDRA_INSTALL_DIR`` environment variable must point to a valid Ghidra
  installation.

Running
-------
    # From the project root:
    GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py -v

    # With a generous timeout for slow machines:
    GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py -v \
        --timeout=600

All tests are automatically skipped when ``GHIDRA_INSTALL_DIR`` is not set.

Architecture
------------
A single module-scoped ``daemon`` fixture starts Ghidra once and loads the
test binary with full analysis.  All test classes share this fixture so the
expensive Ghidra + JVM startup only happens once per pytest invocation.

Write operations (rename, comment, bookmark, etc.) clean up after themselves
so they don't pollute later read tests.

Test binary
-----------
``tests/fixtures/testapp`` is compiled from ``tests/fixtures/testapp.c``:

    gcc -O0 -m64 -o tests/fixtures/testapp tests/fixtures/testapp.c

It is committed to the repository so tests are fully reproducible without
a C compiler on the test machine.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import pytest

# ── Availability guards ───────────────────────────────────────────────────────

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR")

# The test binary lives alongside this file in tests/fixtures/
_TEST_BINARY = Path(__file__).parent / "fixtures" / "testapp"

# A small real-world DEX (Dalvik) fixture, used to exercise DEX/Android-loader
# specific behavior (class-hierarchy namespaces) that a native ELF can't.
# See tests/fixtures/README.md for provenance and re-download instructions.
_DEX_BINARY = Path(__file__).parent / "fixtures" / "dex" / "detectresolution-classes.dex"

pytestmark = pytest.mark.skipif(
    not GHIDRA_DIR,
    reason=(
        "Integration tests require GHIDRA_INSTALL_DIR to be set. "
        "Run with: GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py"
    ),
)

# ── Constants ─────────────────────────────────────────────────────────────────

# Generous timeouts: Ghidra JVM startup + analysis can take several minutes.
_DAEMON_START_TIMEOUT = 300   # seconds to wait for the daemon to become responsive
_LOAD_TIMEOUT         = 600   # socket timeout for the initial load + analysis call
_RPC_TIMEOUT          = 120   # default socket timeout for regular RPC calls


# ── Shared module-level fixture ───────────────────────────────────────────────

@pytest.fixture(scope="module")
def daemon(tmp_path_factory):
    """Start a headless Ghidra daemon, load tests/fixtures/testapp, and yield context.

    The daemon and loaded binary are shared across all tests in this module.
    Teardown stops the daemon after all tests complete.

    Yields a dict:
        sock        -- Path to the daemon's Unix socket
        binary      -- the binary key returned by ``load`` (full path key)
        short_name  -- ``"testapp"`` (short alias accepted by ``get_program``)
        gpr         -- Path to the temp Ghidra project
        main_addr   -- hex address of the ``main`` function (or a known function)
        main_name   -- name of the chosen entry-point function
    """
    from ghidra_rpc.client import DaemonError, send_request
    from ghidra_rpc.daemon import start_background, stop_daemon
    from ghidra_rpc.session import Session, socket_path_for_project

    tmp = tmp_path_factory.mktemp("ghidra_int")
    gpr_path = tmp / "test_project.gpr"
    sock = socket_path_for_project(gpr_path)

    session = Session(
        mode="headless",
        project_gpr=gpr_path,
        socket_path=sock,
        ghidra_install_dir=Path(GHIDRA_DIR),
    )

    # ── Start daemon ──────────────────────────────────────────────────────────
    start_background(session, timeout=_DAEMON_START_TIMEOUT)

    # ── Load tests/fixtures/testapp with full analysis ──────────────────────
    load_resp = send_request(
        sock,
        "load",
        {"path": str(_TEST_BINARY), "analyze": True},
        socket_timeout=_LOAD_TIMEOUT,
    )
    assert load_resp["ok"] is True, f"load failed: {load_resp}"
    binary_key   = load_resp["result"]["binary"]
    short_name   = load_resp["result"]["short_name"]   # "testapp"

    # ── Discover the main function (or a reliable substitute) ─────────────────
    fns_resp = send_request(
        sock, "functions", {"binary": short_name},
        socket_timeout=_RPC_TIMEOUT,
    )
    assert fns_resp["ok"] is True
    all_funcs = fns_resp["result"]["functions"]

    # Prefer "main"; fall back to "_start" / "entry" / first function.
    main_func = next(
        (f for f in all_funcs if f["name"].lower() == "main"),
        None,
    )
    if main_func is None:
        main_func = next(
            (f for f in all_funcs if f["name"].lower() in ("_start", "entry", "start")),
            all_funcs[0] if all_funcs else None,
        )

    assert main_func is not None, "No functions found in testapp — analysis may have failed"

    ctx = {
        "sock":       sock,
        "binary":     binary_key,
        "short_name": short_name,
        "gpr":        gpr_path,
        "main_addr":  main_func["address"],
        "main_name":  main_func["name"],
        "all_funcs":  all_funcs,
    }

    yield ctx

    # ── Teardown ──────────────────────────────────────────────────────────────
    try:
        stop_daemon(sock)
    except Exception:
        pass


# ── Test helpers ──────────────────────────────────────────────────────────────

def rpc(sock: Path, cmd: str, args: dict | None = None,
        *, timeout: float = _RPC_TIMEOUT) -> dict:
    """Send an RPC request; return the full response dict on success.

    Raises ``pytest.fail`` with a descriptive message on daemon errors so
    test failures are clear and don't show raw exception tracebacks.
    """
    from ghidra_rpc.client import DaemonError, send_request
    try:
        return send_request(sock, cmd, args or {}, socket_timeout=timeout)
    except DaemonError as exc:
        pytest.fail(
            f"RPC command '{cmd}' failed with error '{exc.error}': {exc}"
        )


# ── Daemon restart / reopen-from-saved-project branch ─────────────────────────

def test_reopen_from_saved_project_survives_abort_then_write(tmp_path):
    """Covers the 'existing_df' reopen branch in HeadlessContext.load_binary,
    which _take_ownership must also handle correctly. Not exercised by the
    shared ``daemon`` fixture, so this starts its own daemon and restarts it
    on the same project.
    """
    import shutil

    from ghidra_rpc.client import DaemonError, send_request
    from ghidra_rpc.daemon import start_background, stop_daemon
    from ghidra_rpc.session import Session, socket_path_for_project

    gpr = tmp_path / "reopen_test_project.gpr"
    sock = socket_path_for_project(gpr)
    session = Session(
        mode="headless", project_gpr=gpr, socket_path=sock,
        ghidra_install_dir=Path(GHIDRA_DIR),
    )
    binary_path = tmp_path / "testapp"
    shutil.copy(_TEST_BINARY, binary_path)

    start_background(session, timeout=_DAEMON_START_TIMEOUT)
    try:
        first = send_request(sock, "load", {"path": str(binary_path), "analyze": True},
                              socket_timeout=_LOAD_TIMEOUT)
        assert first["ok"] is True, first
        short_name = first["result"]["short_name"]
    finally:
        stop_daemon(sock)

    # stop_daemon() returns on the "stopping" ack, but the old daemon's socket
    # can stay bound for ~1s afterward -- wait for it to vanish before starting
    # a new one on the same project.
    deadline = time.time() + 10
    while sock.exists() and time.time() < deadline:
        time.sleep(0.2)

    start_background(session, timeout=_DAEMON_START_TIMEOUT)
    try:
        # Same .gpr, same path -> hits the existing_df/already_analyzed=True
        # reopen branch, not the fresh-import branch.
        reopened = send_request(sock, "load", {"path": str(binary_path), "analyze": True},
                                 socket_timeout=_LOAD_TIMEOUT)
        assert reopened["ok"] is True, reopened
        assert reopened["result"]["short_name"] == short_name

        try:
            send_request(sock, "create_struct", {
                "binary": short_name, "name": "ReopenAbortStruct",
                "fields": [
                    {"type": "int", "name": "ok_field"},
                    {"type": "string", "name": "bad_dynamic_field"},
                ],
            }, socket_timeout=_RPC_TIMEOUT)
            pytest.fail("Expected create_struct to fail on a dynamic-length field")
        except DaemonError:
            pass

        good = send_request(sock, "create_enum", {
            "binary": short_name, "name": "ReopenAbortEnum",
            "values": [{"name": "X", "value": 1}],
        }, socket_timeout=_RPC_TIMEOUT)
        assert good["ok"] is True, good

        check = send_request(sock, "list_data_types", {
            "binary": short_name, "query": "ReopenAbortEnum",
        }, socket_timeout=_RPC_TIMEOUT)
        assert check["result"]["count"] == 1, (
            "the write immediately following a failed write, on a REOPENED "
            f"program, was silently lost: {check['result']}"
        )
    finally:
        stop_daemon(sock)


# ── 1. Daemon connectivity ────────────────────────────────────────────────────

class TestConnectivity:
    """Basic smoke tests: the daemon is up, responsive, and reports sane metadata."""

    def test_ping_returns_alive(self, daemon):
        resp = rpc(daemon["sock"], "ping")
        assert resp["result"]["status"] == "alive"

    def test_ping_includes_session_metadata(self, daemon):
        result = rpc(daemon["sock"], "ping")["result"]
        assert result["mode"] == "headless"
        assert isinstance(result["pid"], int) and result["pid"] > 0
        assert "project_gpr" in result

    def test_unknown_command_returns_error(self, daemon):
        from ghidra_rpc import transport

        # Call raw without going through our helper to check the error response
        import json
        import uuid
        request = {"id": str(uuid.uuid4()), "cmd": "_nonexistent_cmd_", "args": {}}
        s, auth_token = transport.connect(daemon["sock"], 10)
        if auth_token is not None:
            request["auth"] = auth_token
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode().strip())
        assert resp["ok"] is False
        assert resp["error"] == "UnknownCommand"


# ── 2. Binary analysis ────────────────────────────────────────────────────────

class TestBinaryAnalysis:
    """Tests for analysis-level queries: list, metadata, functions, imports, exports."""

    def test_list_binaries_shows_loaded_binary(self, daemon):
        result = rpc(daemon["sock"], "list_binaries")["result"]
        assert result["binaries"], "No binaries reported — load must have failed"
        names = [b["name"] for b in result["binaries"]]
        # The binary name is derived from the filename; "testapp" should be in it.
        assert any("testapp" in n for n in names), (
            f"Expected 'testapp' in binary names, got: {names}"
        )

    def test_list_binaries_shows_analysis_complete(self, daemon):
        result = rpc(daemon["sock"], "list_binaries")["result"]
        entry = next(
            (b for b in result["binaries"] if "testapp" in b["name"]), None
        )
        assert entry is not None
        assert entry["analysis_complete"] is True

    def test_metadata_arch_and_format(self, daemon):
        result = rpc(daemon["sock"], "metadata", {"binary": daemon["short_name"]})["result"]
        # testapp is an x86-64 ELF binary
        assert result["format"].upper() in ("ELF", "ELF64", "ELF32", "EXECUTABLE AND LINKING FORMAT (ELF)"), (
            f"Unexpected format: {result['format']}"
        )
        # Should be some x86/ARM/MIPS/etc. processor
        assert result["arch"], f"arch should be non-empty, got: {result['arch']}"
        assert result["bits"] in (32, 64), f"Expected 32 or 64 bits, got: {result['bits']}"
        assert result["endian"].upper() in ("BIG", "LITTLE"), (
            f"Unexpected endian: {result['endian']}"
        )

    def test_metadata_base_address_is_hex(self, daemon):
        result = rpc(daemon["sock"], "metadata", {"binary": daemon["short_name"]})["result"]
        # base_address should be parseable as a hex address
        base = result["base_address"]
        assert base, "base_address should be non-empty"
        int(base, 16)  # raises ValueError if not valid hex

    def test_metadata_has_functions(self, daemon):
        result = rpc(daemon["sock"], "metadata", {"binary": daemon["short_name"]})["result"]
        assert result["num_functions"] > 10, (
            f"Expected >10 functions in testapp (user + CRT + PLT stubs), "
            f"got: {result['num_functions']}"
        )

    def test_functions_returns_many_entries(self, daemon):
        result = rpc(daemon["sock"], "functions", {"binary": daemon["short_name"]})["result"]
        assert result["count"] > 10, (
            f"Expected many functions, got {result['count']}"
        )
        assert result["total"] == result["count"]  # no pagination by default
        # Each entry must have name, address, signature
        for fn in result["functions"][:5]:
            assert "name" in fn
            assert "address" in fn
            assert "signature" in fn

    def test_functions_includes_main(self, daemon):
        result = rpc(daemon["sock"], "functions", {"binary": daemon["short_name"]})["result"]
        names = [f["name"].lower() for f in result["functions"]]
        assert "main" in names, (
            f"'main' not found in function names. Sample: {names[:20]}"
        )

    def test_functions_pagination_limit(self, daemon):
        result = rpc(daemon["sock"], "functions",
                     {"binary": daemon["short_name"], "limit": 5, "offset": 0})["result"]
        assert result["count"] == 5
        assert len(result["functions"]) == 5
        assert result["total"] > 5   # total reflects the full untruncated count

    def test_functions_pagination_offset(self, daemon):
        r0 = rpc(daemon["sock"], "functions",
                 {"binary": daemon["short_name"], "limit": 5, "offset": 0})["result"]
        r1 = rpc(daemon["sock"], "functions",
                 {"binary": daemon["short_name"], "limit": 5, "offset": 5})["result"]
        addrs0 = {f["address"] for f in r0["functions"]}
        addrs1 = {f["address"] for f in r1["functions"]}
        assert addrs0.isdisjoint(addrs1), (
            "Paginated results must not overlap"
        )

    def test_functions_with_body(self, daemon):
        result = rpc(daemon["sock"], "functions",
                     {"binary": daemon["short_name"], "limit": 3, "with_body": True})["result"]
        for fn in result["functions"]:
            assert "body_min" in fn, f"Missing body_min in {fn}"
            assert "body_max" in fn, f"Missing body_max in {fn}"
            assert isinstance(fn["body_size"], int) and fn["body_size"] > 0

    def test_functions_address_range_filter(self, daemon):
        """Range filter must return a strict subset of all functions."""
        all_result = rpc(daemon["sock"], "functions",
                         {"binary": daemon["short_name"]})["result"]
        all_addrs = sorted(f["address"] for f in all_result["functions"])
        if len(all_addrs) < 4:
            pytest.skip("Not enough functions for range test")

        lo = all_addrs[len(all_addrs) // 4]
        hi = all_addrs[3 * len(all_addrs) // 4]
        range_result = rpc(daemon["sock"], "functions", {
            "binary": daemon["short_name"],
            "address_min": lo,
            "address_max": hi,
        })["result"]
        assert 0 < range_result["count"] <= all_result["count"]
        for fn in range_result["functions"]:
            assert lo <= fn["address"] <= hi, (
                f"Function {fn['name']} @ {fn['address']} outside [{lo}, {hi}]"
            )

    def test_imports_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "imports", {"binary": daemon["short_name"]})["result"]
        assert result["count"] > 0, "Expected imports in a dynamically linked testapp binary"
        # Each entry must have name, address, library
        for imp in result["imports"][:5]:
            assert "name" in imp
            assert "address" in imp

    def test_imports_contains_common_libc_symbol(self, daemon):
        result = rpc(daemon["sock"], "imports", {"binary": daemon["short_name"]})["result"]
        import_names = {i["name"].lower() for i in result["imports"]}
        # At least one of these very common symbols should be present
        common = {"malloc", "free", "printf", "fprintf", "strlen", "strcmp",
                  "exit", "open", "close", "write", "read", "stat", "fopen"}
        found = import_names & common
        assert found, (
            f"Expected at least one common libc symbol; imports: {sorted(import_names)[:30]}"
        )

    def test_list_calling_conventions(self, daemon):
        result = rpc(daemon["sock"], "list_calling_conventions",
                     {"binary": daemon["short_name"]})["result"]
        assert result["count"] > 0, "Expected at least one calling convention"
        assert result["default"], "Default calling convention should be non-empty"
        assert isinstance(result["conventions"], list)

    def test_relocations_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "relocations",
                     {"binary": daemon["short_name"]})["result"]
        # Dynamically linked testapp will have PLT / GOT relocations
        assert result["total"] > 0, (
            "Expected relocations in testapp; got 0 (is this statically linked?)"
        )
        assert result["count"] > 0
        for rel in result["relocations"][:5]:
            assert "address" in rel
            assert "type" in rel

    def test_list_project_programs(self, daemon):
        result = rpc(daemon["sock"], "list_project_programs")["result"]
        assert result["count"] > 0, "Expected at least one program in the project"
        names = [p["name"] for p in result["programs"]]
        assert any("testapp" in n for n in names), (
            f"Expected 'testapp' in project programs, got: {names}"
        )


# ── 3. Search ─────────────────────────────────────────────────────────────────

class TestSearch:
    """Tests for strings, symbols, and byte-pattern search."""

    def test_strings_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "strings",
                     {"binary": daemon["short_name"], "query": "", "limit": 50})["result"]
        assert "strings" in result
        assert len(result["strings"]) > 0, "Expected strings in testapp"

    def test_strings_query_filter(self, daemon):
        # testapp has multiple format strings containing "hello" (case-insensitive):
        # "Hello, %s. Welcome to the integration test.\n" and
        # "Hello %s! Running integration tests now.\n"
        result = rpc(daemon["sock"], "strings",
                     {"binary": daemon["short_name"], "query": "hello", "limit": 20})["result"]
        assert len(result["strings"]) > 0, (
            "Expected at least one string containing 'hello'"
        )
        for s in result["strings"]:
            assert "hello" in s["value"].lower(), (
                f"String '{s['value']}' does not contain 'hello'"
            )

    def test_strings_entry_has_address(self, daemon):
        result = rpc(daemon["sock"], "strings",
                     {"binary": daemon["short_name"], "query": "", "limit": 5})["result"]
        for s in result["strings"]:
            assert "address" in s, f"String entry missing address: {s}"
            assert "value" in s, f"String entry missing value field: {s}"

    def test_symbols_search_main(self, daemon):
        result = rpc(daemon["sock"], "symbols",
                     {"binary": daemon["short_name"], "query": "main", "limit": 10})["result"]
        assert "symbols" in result
        # "main" symbol should be found
        sym_names = [s["name"].lower() for s in result["symbols"]]
        assert any("main" in n for n in sym_names), (
            f"Expected 'main' in symbol search results; got: {sym_names}"
        )

    def test_symbols_entry_has_required_fields(self, daemon):
        result = rpc(daemon["sock"], "symbols",
                     {"binary": daemon["short_name"], "query": "main", "limit": 5})["result"]
        for sym in result["symbols"]:
            assert "name" in sym
            assert "address" in sym

    def test_find_bytes_finds_pattern(self, daemon):
        """Search for existing and non-existing byte patterns (x86-64 ELF)."""
        result = rpc(daemon["sock"], "find_bytes",
                     {"binary": daemon["short_name"],
                      "pattern": "7f 45 4c 46", "limit": 5})["result"]
        assert "matches" in result
        assert "pattern" in result
        assert "count" in result
        assert result["count"] >= 1, (
            "ELF magic bytes 7f 45 4c 46 must be found in an ELF binary — "
            f"got count={result['count']}.  Bug: findBytes regex encoding wrong."
        )
        for match in result["matches"]:
            assert "address" in match
            assert "context_hex" in match
            assert "7f454c46" in match["context_hex"], (
                f"context_hex {match['context_hex']!r} should contain the matched bytes"
            )

        # 0x55 = PUSH RBP — every function prologue in an -O0 x86-64 binary.
        result55 = rpc(daemon["sock"], "find_bytes",
                       {"binary": daemon["short_name"],
                        "pattern": "55", "limit": 5})["result"]
        assert result55["count"] >= 1, (
            "Byte 0x55 (PUSH RBP) must be present in testapp — "
            f"got count={result55['count']}.  Bug: findBytes regex encoding wrong."
        )

        # 48 85 c0 = TEST RAX,RAX — emitted for NULL pointer checks (e.g. after malloc).
        result_test = rpc(daemon["sock"], "find_bytes",
                          {"binary": daemon["short_name"],
                           "pattern": "48 85 c0", "limit": 5})["result"]
        assert result_test["count"] >= 1, (
            "Bytes 48 85 c0 (TEST RAX,RAX) must be present in testapp — "
            f"got count={result_test['count']}."
        )

        result_absent = rpc(daemon["sock"], "find_bytes",
                            {"binary": daemon["short_name"],
                             "pattern": "f1 a4 9d b0 fc fc a3 6e e4 9a 53 2b b4 ab 8b ff",
                             "limit": 5})["result"]
        assert result_absent["count"] == 0, (
            "16-byte random pattern must not appear in testapp"
        )


    def test_find_bytes_wildcard_pattern(self, daemon):
        """Wildcard ('??') patterns must match wherever the non-wildcard bytes fit."""
        result = rpc(daemon["sock"], "find_bytes",
                     {"binary": daemon["short_name"],
                      "pattern": "55 ??", "limit": 10})["result"]
        assert "matches" in result
        assert result["count"] >= 1, (
            "55 ?? must match at least one location given that 0x55 is present"
        )


# ── 4. Decompiler and disassembly ─────────────────────────────────────────────

class TestDecompilerAndDisassembly:
    """Tests for decompile and disassemble commands."""

    def test_decompile_main_returns_code(self, daemon):
        result = rpc(daemon["sock"], "decompile",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"], "timeout": 60})["result"]
        assert "c_code" in result, f"Missing 'c_code' in decompile result: {result}"
        # Decompiled C should contain at least one of these common C constructs
        code = result["c_code"]
        assert len(code) > 50, f"Decompiled code seems too short: {code!r}"
        assert any(kw in code for kw in ("(", ")", "{", "}", "int", "void", "char", "long")), (
            f"Decompiled code doesn't look like C: {code[:200]}"
        )

    def test_decompile_by_address(self, daemon):
        """Decompile should also work when target is given as a hex address."""
        result = rpc(daemon["sock"], "decompile",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_addr"], "timeout": 60})["result"]
        assert "c_code" in result
        assert len(result["c_code"]) > 20

    def test_decompile_returns_function_name(self, daemon):
        result = rpc(daemon["sock"], "decompile",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"], "timeout": 60})["result"]
        assert "name" in result
        assert result["name"].lower() == daemon["main_name"].lower()

    def test_decompile_nonexistent_function_errors(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request
        try:
            send_request(
                daemon["sock"], "decompile",
                {"binary": daemon["short_name"],
                 "func": "_nonexistent_function_xyz_"},
                socket_timeout=30,
            )
            pytest.fail("Expected DaemonError for nonexistent function")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )

    def test_disassemble_at_main(self, daemon):
        # Default: instructions array is hidden, listing string is present
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": daemon["short_name"],
                      "address": daemon["main_addr"], "count": 10})["result"]
        assert "listing" in result
        assert "instructions" not in result
        assert result["count"] > 0

        # With with_instructions=True: instructions array is included, and the
        # listing is byte-identical to the default response.
        result_verbose = rpc(daemon["sock"], "disassemble",
                             {"binary": daemon["short_name"],
                              "address": daemon["main_addr"],
                              "count": 10,
                              "with_instructions": True})["result"]
        assert result_verbose["listing"] == result["listing"]
        assert "instructions" in result_verbose
        assert len(result_verbose["instructions"]) > 0
        for insn in result_verbose["instructions"]:
            assert "address" in insn
            assert "mnemonic" in insn

    def test_disassemble_default_count(self, daemon):
        """Default 20-instruction listing must return count up to 20."""
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": daemon["short_name"],
                      "address": daemon["main_addr"]})["result"]
        assert 0 < result["count"] <= 20
        assert "listing" in result

    def test_search_decompiled_finds_caller_by_callee_name(self, daemon):
        """stack_push() calls node_alloc(); searching for that callee name
        should surface stack_push without decompiling it by name directly."""
        result = rpc(daemon["sock"], "search_decompiled", {
            "binary": daemon["short_name"], "pattern": "node_alloc",
        })["result"]
        names = [m["function"].lower() for m in result["matches"]]
        assert any("stack_push" in n for n in names), (
            f"Expected stack_push among matches: {result['matches']}"
        )
        for match in result["matches"]:
            assert match["matching_lines"], "match with no matching_lines entries"
            for line in match["matching_lines"]:
                assert "line" in line and "text" in line

    def test_search_decompiled_is_case_insensitive_by_default(self, daemon):
        result = rpc(daemon["sock"], "search_decompiled", {
            "binary": daemon["short_name"], "pattern": "NODE_ALLOC",
        })["result"]
        assert result["count"] > 0

    def test_search_decompiled_respects_limit(self, daemon):
        result = rpc(daemon["sock"], "search_decompiled", {
            "binary": daemon["short_name"], "pattern": ".",  # matches almost everything
            "limit": 1,
        })["result"]
        assert result["count"] <= 1
        assert result["truncated"] is True

    def test_search_decompiled_pages_by_next_unscanned_address(self, daemon):
        """Windows chained via next_unscanned_address cover every function
        exactly once -- i.e. Ghidra's address strings round-trip as address_min."""
        args = {"binary": daemon["short_name"], "pattern": "zz_no_match_zz",
                "max_functions": 2}
        full = rpc(daemon["sock"], "search_decompiled",
                   {**args, "max_functions": 5000})["result"]
        assert full["next_unscanned_address"] is None

        searched = 0
        windows = 0
        next_addr = None
        while True:
            window_args = dict(args, address_min=next_addr) if next_addr else args
            result = rpc(daemon["sock"], "search_decompiled", window_args)["result"]
            searched += result["functions_searched"]
            windows += 1
            next_addr = result["next_unscanned_address"]
            if next_addr is None:
                break
            assert int(next_addr, 16) > int(result["scanned_range"]["max"], 16)
        assert windows > 1, "fixture too small to exercise paging"
        assert searched == full["functions_total"]

    def test_search_decompiled_invalid_regex_errors(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request
        try:
            send_request(
                daemon["sock"], "search_decompiled",
                {"binary": daemon["short_name"], "pattern": "("},
                socket_timeout=30,
            )
            pytest.fail("Expected DaemonError for invalid regex")
        except DaemonError as exc:
            assert exc.error == "ValueError"


# ── 5. Memory ─────────────────────────────────────────────────────────────────

class TestMemory:
    """Tests for read_bytes and memory_map."""

    def test_read_bytes_at_main(self, daemon):
        result = rpc(daemon["sock"], "read_bytes",
                     {"binary": daemon["short_name"],
                      "address": daemon["main_addr"], "length": 16})["result"]
        assert "hex" in result
        hex_val = result["hex"].replace(" ", "")
        # 16 bytes = 32 hex chars
        assert len(hex_val) == 32, (
            f"Expected 32 hex chars for 16 bytes, got: {result['hex']!r}"
        )
        int(hex_val, 16)   # must be valid hex

    def test_read_bytes_length_variants(self, daemon):
        for length in (1, 4, 8, 32):
            result = rpc(daemon["sock"], "read_bytes",
                         {"binary": daemon["short_name"],
                          "address": daemon["main_addr"], "length": length})["result"]
            hex_val = result["hex"].replace(" ", "")
            assert len(hex_val) == length * 2, (
                f"length={length}: expected {length*2} hex chars, got {len(hex_val)}"
            )

    def test_memory_map_returns_segments(self, daemon):
        result = rpc(daemon["sock"], "memory_map",
                     {"binary": daemon["short_name"]})["result"]
        assert "segments" in result
        assert len(result["segments"]) > 0, "Expected at least one memory segment"

    def test_memory_map_segment_fields(self, daemon):
        result = rpc(daemon["sock"], "memory_map",
                     {"binary": daemon["short_name"]})["result"]
        required_fields = {"name", "start", "end", "size"}
        for seg in result["segments"]:
            missing = required_fields - seg.keys()
            assert not missing, (
                f"Memory segment missing fields {missing}: {seg}"
            )

    def test_memory_map_includes_text_segment(self, daemon):
        result = rpc(daemon["sock"], "memory_map",
                     {"binary": daemon["short_name"]})["result"]
        seg_names = {s["name"] for s in result["segments"]}
        # At least one of these sections must be present in a standard ELF
        text_like = {".text", "text", ".code", "CODE", ".init", ".plt"}
        assert seg_names & text_like, (
            f"Expected a code segment (.text/.code/etc.), got: {seg_names}"
        )


# ── 6. Cross-references ───────────────────────────────────────────────────────

class TestXrefs:
    """Tests for xrefs_to and xrefs_from."""

    def test_xrefs_from_main_has_calls(self, daemon):
        result = rpc(daemon["sock"], "xrefs_from",
                     {"binary": daemon["short_name"],
                      "target": daemon["main_name"], "limit": 50})["result"]
        assert "xrefs" in result
        # main should call other functions
        assert result["count"] > 0, (
            "Expected main to have outgoing references (calls)"
        )

    def test_xrefs_from_entry_fields(self, daemon):
        result = rpc(daemon["sock"], "xrefs_from",
                     {"binary": daemon["short_name"],
                      "target": daemon["main_name"], "limit": 10})["result"]
        for xref in result["xrefs"]:
            assert "to_address" in xref
            assert "type" in xref

    def test_xrefs_to_import_has_callers(self, daemon):
        """An imported function called by testapp must have at least one xref_to."""
        from ghidra_rpc.client import DaemonError, send_request

        # Find a well-known import that ls definitely calls
        imports_result = rpc(daemon["sock"], "imports",
                             {"binary": daemon["short_name"]})["result"]
        import_names = [i["name"] for i in imports_result["imports"]]

        target = "malloc"
        assert target in import_names, (
            f"Expected {target} in imports, got: {import_names[:30]}"
        )

        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"],
                      "target": target, "limit": 20})["result"]
        assert result["count"] > 0, (
            f"Expected at least one xref to '{target}'"
        )

    def test_xrefs_to_external_address_follows_thunk_chain(self, daemon):
        """xrefs_to on an import's EXTERNAL address finds the same callers as by name.

        Callers reach the EXTERNAL function through a chain of thunks (PLT stub
        -> EXTERNAL-block thunk -> EXTERNAL function on x86-64 ELF), so only
        following the first hop misses every real call site.
        """
        imports = rpc(daemon["sock"], "imports",
                      {"binary": daemon["short_name"]})["result"]["imports"]
        imp = next((i for i in imports if i["name"] == "malloc"), None)
        assert imp is not None, "Expected malloc in imports"
        assert imp["address"].startswith("EXTERNAL:"), imp

        by_name = rpc(daemon["sock"], "xrefs_to",
                      {"binary": daemon["short_name"],
                       "target": "malloc", "limit": 500})["result"]["xrefs"]
        by_addr = rpc(daemon["sock"], "xrefs_to",
                      {"binary": daemon["short_name"],
                       "target": imp["address"], "limit": 500})["result"]["xrefs"]

        callers = {x["from_address"] for x in by_name if x["type"].endswith("CALL")}
        assert callers, f"Expected call xrefs to malloc by name; got {by_name}"
        missing = callers - {x["from_address"] for x in by_addr}
        assert not missing, (
            f"xrefs_to {imp['address']} missed callers found by name: {sorted(missing)}"
        )

    def test_xrefs_to_entry_fields(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request

        imports_result = rpc(daemon["sock"], "imports",
                             {"binary": daemon["short_name"]})["result"]
        if not imports_result["imports"]:
            pytest.skip("No imports available for xrefs_to field test")

        target = imports_result["imports"][0]["name"]
        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"],
                      "target": target, "limit": 5})["result"]
        for xref in result["xrefs"]:
            assert "from_address" in xref
            assert "type" in xref

    def test_xrefs_by_address(self, daemon):
        """xrefs_to should also accept a hex address as target."""
        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"],
                      "target": daemon["main_addr"], "limit": 10})["result"]
        # Just verify the response has the right shape (main may or may not
        # have incoming refs depending on how the binary is built)
        assert "xrefs" in result
        assert "count" in result

    def test_xrefs_to_all_binaries_merges_second_program(self, daemon, tmp_path):
        """--all-binaries should find and tag real callers in every other loaded
        binary that has a symbol with the same fully-qualified name -- the
        general form of the DEX cross-dex-call gap (Ghidra's ReferenceManager
        is per-Program, so a caller in a different loaded binary is otherwise
        invisible to xrefs_to). Uses a second copy of testapp -- under a name
        that can't substring-collide with 'testapp' in later get_program()
        lookups -- as a stand-in for "another loaded binary with a matching
        symbol", since that's all the merge logic actually depends on.
        """
        import shutil

        copy_path = tmp_path / "xrefs_probe_binary"
        shutil.copy(_TEST_BINARY, copy_path)

        load_result = rpc(daemon["sock"], "load", {"path": str(copy_path)},
                          timeout=_LOAD_TIMEOUT)["result"]
        copy_key = load_result["binary"]
        assert copy_key != daemon["binary"]

        result = rpc(daemon["sock"], "xrefs_to",
                     {"binary": daemon["short_name"], "target": daemon["main_name"],
                      "limit": 50, "all_binaries": True})["result"]

        binaries_seen = {x["binary"] for x in result["xrefs"]}
        assert daemon["binary"] in binaries_seen, (
            f"Expected own-binary xrefs tagged with '{daemon['binary']}'; got: {binaries_seen}"
        )
        assert copy_key in binaries_seen, (
            f"Expected the identical second binary '{copy_key}' to be searched "
            f"and its real callers merged in; got: {binaries_seen}"
        )


# ── 7. Control-flow graph ─────────────────────────────────────────────────────

class TestCFG:
    """Tests for basic_blocks and pcode."""

    def test_basic_blocks_main(self, daemon):
        result = rpc(daemon["sock"], "basic_blocks",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        assert "blocks" in result
        assert result["num_blocks"] > 0
        assert "name" in result
        assert "address" in result

    def test_basic_blocks_fields(self, daemon):
        result = rpc(daemon["sock"], "basic_blocks",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        required = {"start", "end", "size", "instructions"}
        for block in result["blocks"][:5]:
            missing = required - block.keys()
            assert not missing, (
                f"Basic block missing fields {missing}: {block}"
            )
            assert block["instructions"] >= 1
            assert block["size"] >= 1

    def test_basic_blocks_successors(self, daemon):
        """All but terminal blocks should have successors."""
        result = rpc(daemon["sock"], "basic_blocks",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        # At least one block should have a successor
        blocks_with_succ = [b for b in result["blocks"] if b.get("successors")]
        assert blocks_with_succ, "Expected at least one block with successors"

    def test_pcode_main(self, daemon):
        result = rpc(daemon["sock"], "pcode",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        assert "ops" in result
        assert len(result["ops"]) > 0, "Expected P-code ops for main"

    def test_pcode_entry_fields(self, daemon):
        result = rpc(daemon["sock"], "pcode",
                     {"binary": daemon["short_name"],
                      "func": daemon["main_name"]})["result"]
        for op in result["ops"][:5]:
            assert "opcode" in op, (
                f"P-code op missing opcode field: {op}"
            )


# ── 8. Bookmarks ──────────────────────────────────────────────────────────────

class TestBookmarks:
    """Tests for set_bookmark, list_bookmarks, remove_bookmark.

    These are write operations; each test cleans up after itself.
    """

    def test_set_and_list_bookmark(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        category = f"test-{uid}"
        comment  = f"integration-test bookmark {uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary":   daemon["short_name"],
            "address":  addr,
            "type":     "Note",
            "category": category,
            "comment":  comment,
        })

        list_result = rpc(daemon["sock"], "list_bookmarks",
                          {"binary": daemon["short_name"]})["result"]
        bmarks = list_result["bookmarks"]
        match = next(
            (b for b in bmarks if b.get("category") == category), None
        )
        assert match is not None, (
            f"Bookmark with category '{category}' not found; all: {bmarks}"
        )
        assert match["comment"] == comment

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary":   daemon["short_name"],
            "address":  addr,
            "type":     "Note",
            "category": category,
        })

    def test_list_bookmarks_by_address(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        category = f"addr-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category, "comment": "addr filter test",
        })

        result = rpc(daemon["sock"], "list_bookmarks", {
            "binary": daemon["short_name"], "address": addr,
        })["result"]
        categories = [b.get("category") for b in result["bookmarks"]]
        assert category in categories, (
            f"Bookmark not found when filtering by address {addr}: {result['bookmarks']}"
        )

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category,
        })

    def test_list_bookmarks_by_type(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        category = f"type-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Warning", "category": category, "comment": "type filter test",
        })

        result = rpc(daemon["sock"], "list_bookmarks", {
            "binary": daemon["short_name"], "type": "Warning",
        })["result"]
        categories = [b.get("category") for b in result["bookmarks"]]
        assert category in categories

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Warning", "category": category,
        })

    def test_list_bookmarks_by_category(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        category = f"category-filter-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category, "comment": "category filter test",
        })
        # A second, unrelated bookmark that must NOT show up in the filtered results.
        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Warning", "category": f"other-{uid}", "comment": "should be excluded",
        })

        result = rpc(daemon["sock"], "list_bookmarks", {
            "binary": daemon["short_name"], "category": category,
        })["result"]
        categories = [b.get("category") for b in result["bookmarks"]]
        assert categories == [category], (
            f"Expected only '{category}', got: {result['bookmarks']}"
        )

        # Substring match should also work.
        result = rpc(daemon["sock"], "list_bookmarks", {
            "binary": daemon["short_name"], "category": "category-filter-test",
        })["result"]
        assert category in [b.get("category") for b in result["bookmarks"]]

        # Cleanup
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category,
        })
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Warning", "category": f"other-{uid}",
        })

    def test_remove_bookmark_removes_it(self, daemon):
        uid = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        category = f"remove-test-{uid}"

        rpc(daemon["sock"], "set_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category, "comment": "to be removed",
        })
        rpc(daemon["sock"], "remove_bookmark", {
            "binary": daemon["short_name"], "address": addr,
            "type": "Note", "category": category,
        })

        list_result = rpc(daemon["sock"], "list_bookmarks",
                          {"binary": daemon["short_name"]})["result"]
        categories = [b.get("category") for b in list_result["bookmarks"]]
        assert category not in categories, (
            f"Bookmark with category '{category}' still present after removal"
        )


# ── 9. Comments and labels ────────────────────────────────────────────────────

class TestCommentsAndLabels:
    """Tests for set_comment and create_label.

    These are write operations; tests verify the annotation persists and
    then clean it up (overwrite with empty string / unlabel).
    """

    def test_set_eol_comment(self, daemon):
        addr    = daemon["main_addr"]
        uid     = uuid.uuid4().hex[:8]
        comment = f"eol-comment-{uid}"

        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": comment, "comment_type": "eol",
        })

        # Verify via disassemble.  Assert against the default response shape:
        # `listing` is what callers get without --with-instructions, so this
        # also pins the claim that it carries EOL comments losslessly.
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": daemon["short_name"],
                      "address": addr, "count": 1})["result"]
        assert comment in result["listing"], (
            f"EOL comment missing from listing: {result['listing']!r}"
        )

        # Cleanup: clear the comment
        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": "", "comment_type": "eol",
        })

    def test_set_plate_comment(self, daemon):
        """Plate comments annotate a function header."""
        addr    = daemon["main_addr"]
        uid     = uuid.uuid4().hex[:8]
        comment = f"plate-comment-{uid}"

        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": comment, "comment_type": "plate",
        })

        # Cleanup
        rpc(daemon["sock"], "set_comment", {
            "binary": daemon["short_name"], "address": addr,
            "comment": "", "comment_type": "plate",
        })

    def test_create_label(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        name = f"_test_label_{uid}"

        result = rpc(daemon["sock"], "create_label", {
            "binary": daemon["short_name"],
            "address": addr,
            "name": name,
        })["result"]
        assert "address" in result or "name" in result, (
            f"Unexpected create_label response: {result}"
        )

        # Verify via symbols search
        sym_result = rpc(daemon["sock"], "symbols",
                         {"binary": daemon["short_name"],
                          "query": name, "limit": 5})["result"]
        sym_names = [s["name"] for s in sym_result["symbols"]]
        assert name in sym_names, (
            f"Created label '{name}' not found via symbols search; got: {sym_names}"
        )

        # Cleanup: restore the original name so later tests can find the function
        # by name.  _handle_create_label renames USER_DEFINED symbols in-place,
        # so without this the function at main_addr would keep the test label name.
        orig_name = result.get("old_name") or daemon["main_name"]
        if orig_name:
            rpc(daemon["sock"], "create_label", {
                "binary":  daemon["short_name"],
                "address": addr,
                "name":    orig_name,
            })

    def test_symbols_search_matches_space_for_underscore(self, daemon):
        """Ghidra's SymbolUtilities replaces literal spaces (and only spaces --
        not other punctuation, not non-ASCII text) with underscores when it
        auto-generates a label from string content, e.g. DEX ``strings::``/
        ``string_data::`` labels. A query copied verbatim from `strings`
        output -- with real spaces -- must still match such labels."""
        uid  = uuid.uuid4().hex[:8]
        addr = daemon["main_addr"]
        name = f"space_norm_{uid}_two_words"

        result = rpc(daemon["sock"], "create_label", {
            "binary":  daemon["short_name"],
            "address": addr,
            "name":    name,
        })["result"]

        sym_result = rpc(daemon["sock"], "symbols",
                         {"binary": daemon["short_name"],
                          "query": f"space norm {uid} two words", "limit": 5})["result"]
        sym_names = [s["name"] for s in sym_result["symbols"]]
        assert name in sym_names, (
            f"Query with spaces should match underscore-containing label "
            f"'{name}'; got: {sym_names}"
        )

        # Cleanup: restore the original name
        orig_name = result.get("old_name") or daemon["main_name"]
        if orig_name:
            rpc(daemon["sock"], "create_label", {
                "binary":  daemon["short_name"],
                "address": addr,
                "name":    orig_name,
            })


# ── 10. Function rename ───────────────────────────────────────────────────────

class TestRenameFunction:
    """Tests for rename_function.

    Uses a non-critical function so renaming doesn't break later tests.
    """

    def _pick_rename_target(self, daemon) -> tuple[str, str]:
        """Return (current_name, address) of a safe function to rename."""
        # Pick the second function in the list (avoid main / _start)
        funcs = daemon["all_funcs"]
        for fn in funcs:
            name = fn["name"].lower()
            if name not in ("main", "_start", "entry", "start", "_init", "_fini"):
                return fn["name"], fn["address"]
        pytest.skip("No suitable function found for rename test")

    def test_rename_function_and_verify(self, daemon):
        orig_name, addr = self._pick_rename_target(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"_renamed_fn_{uid}"

        rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   addr,
            "new_name": new_name,
        })

        # Verify the new name appears in the function list
        result = rpc(daemon["sock"], "functions",
                     {"binary": daemon["short_name"]})["result"]
        names = [f["name"] for f in result["functions"]]
        assert new_name in names, (
            f"Renamed function '{new_name}' not found; sample: {names[:20]}"
        )

        # Cleanup: rename back to original
        rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   addr,
            "new_name": orig_name,
        })

    def test_rename_function_response_fields(self, daemon):
        orig_name, addr = self._pick_rename_target(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"_renamed_fn2_{uid}"

        result = rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   addr,
            "new_name": new_name,
        })["result"]

        assert "old_name" in result or "name" in result, (
            f"Expected old_name or name in response: {result}"
        )

        # Cleanup
        rpc(daemon["sock"], "rename_function", {
            "binary":   daemon["short_name"],
            "target":   addr,
            "new_name": orig_name,
        })


# ── 11. Data types ────────────────────────────────────────────────────────────

class TestDataTypes:
    """Tests for list_data_types, create_struct, create_enum."""

    def test_list_data_types_returns_entries(self, daemon):
        result = rpc(daemon["sock"], "list_data_types",
                     {"binary": daemon["short_name"],
                      "category": "all", "limit": 50})["result"]
        assert "data_types" in result
        assert result["count"] > 0, "Expected built-in data types to be listed"

    def test_list_data_types_includes_builtins(self, daemon):
        result = rpc(daemon["sock"], "list_data_types",
                     {"binary": daemon["short_name"],
                      "category": "all", "limit": 200})["result"]
        type_names = {dt["name"].lower() for dt in result["data_types"]}
        # Ghidra always has basic types
        basic = {"byte", "word", "dword", "qword", "char", "int", "uint"}
        found = type_names & basic
        assert found, (
            f"Expected basic built-in types; got sample: {sorted(type_names)[:30]}"
        )

    def test_list_data_types_category_filter(self, daemon):
        result = rpc(daemon["sock"], "list_data_types",
                     {"binary": daemon["short_name"],
                      "category": "struct", "limit": 50})["result"]
        assert "data_types" in result
        for dt in result["data_types"]:
            assert dt["category"].lower() == "struct", (
                f"Expected struct category, got: {dt['category']}"
            )

    def test_create_struct(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"TestStruct_{uid}"

        result = rpc(daemon["sock"], "create_struct", {
            "binary": daemon["short_name"],
            "name":   name,
            "fields": [
                {"type": "int",   "name": "field_a"},
                {"type": "int",   "name": "field_b"},
                {"type": "char",  "name": "flag"},
            ],
        })["result"]

        assert "name" in result, f"Expected 'name' in create_struct result: {result}"
        assert result["name"] == name

        # Verify it appears in list_data_types
        list_result = rpc(daemon["sock"], "list_data_types", {
            "binary": daemon["short_name"],
            "category": "struct", "query": uid, "limit": 10,
        })["result"]
        struct_names = [dt["name"] for dt in list_result["data_types"]]
        assert name in struct_names, (
            f"Newly created struct '{name}' not found; got: {struct_names}"
        )

    def test_create_struct_if_not_exists_idempotent(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"IdempotentStruct_{uid}"

        for _ in range(2):
            result = rpc(daemon["sock"], "create_struct", {
                "binary":       daemon["short_name"],
                "name":         name,
                "fields":       [{"type": "int", "name": "x"}],
                "if_not_exists": True,
            })["result"]
            assert result["name"] == name

    def test_create_struct_explicit_offsets(self, daemon):
        """Fields at explicit offsets auto-pad the gaps; only real fields listed."""
        uid  = uuid.uuid4().hex[:8]
        name = f"OffsetStruct_{uid}"

        result = rpc(daemon["sock"], "create_struct", {
            "binary": daemon["short_name"], "name": name,
            "fields": [
                {"offset": 0,    "type": "int", "name": "time"},
                {"offset": 0x10, "type": "int", "name": "watts"},
            ],
        })["result"]

        # Gap between the two fields is auto-padded, not reported as a field.
        assert len(result["fields"]) == 2, result
        by_off = {f["offset"]: f for f in result["fields"]}
        assert set(by_off) == {0, 16}, result
        assert by_off[0]["name"] == "time"
        assert by_off[16]["name"] == "watts"
        # Struct spans through the last field: 0x10 + sizeof(int) = 0x14.
        assert result["size"] == 0x14, result

    def test_create_struct_explicit_hex_string_offset(self, daemon):
        """Offsets may be 0x-hex strings (as the CLI passes them)."""
        uid  = uuid.uuid4().hex[:8]
        name = f"HexOffStruct_{uid}"

        result = rpc(daemon["sock"], "create_struct", {
            "binary": daemon["short_name"], "name": name,
            "fields": [
                {"offset": "0x0", "type": "int",    "name": "a"},
                {"offset": "0x8", "type": "char *", "name": "p"},
            ],
        })["result"]

        by_off = {f["offset"]: f for f in result["fields"]}
        assert set(by_off) == {0, 8}, result
        assert by_off[8]["name"] == "p"

    def test_create_struct_explicit_self_referential(self, daemon):
        """A pointer to the struct being defined resolves (deferred resolution)."""
        uid  = uuid.uuid4().hex[:8]
        name = f"Node_{uid}"

        result = rpc(daemon["sock"], "create_struct", {
            "binary": daemon["short_name"], "name": name,
            "fields": [
                {"offset": 0, "type": "int",       "name": "val"},
                {"offset": 8, "type": f"{name} *", "name": "next"},
            ],
        })["result"]

        by_off = {f["offset"]: f for f in result["fields"]}
        assert set(by_off) == {0, 8}, result
        assert by_off[8]["name"] == "next", result
        assert "*" in by_off[8]["data_type"], result  # a pointer type
        assert result["size"] == 0x10, result

    def test_create_struct_explicit_overlap_rejected(self, daemon):
        """Overlapping explicit offsets must fail loudly, not clobber silently."""
        from ghidra_rpc.client import DaemonError, send_request
        uid  = uuid.uuid4().hex[:8]
        name = f"OverlapStruct_{uid}"

        try:
            send_request(daemon["sock"], "create_struct", {
                "binary": daemon["short_name"], "name": name,
                "fields": [
                    {"offset": 0, "type": "int", "name": "a"},   # bytes 0..3
                    {"offset": 2, "type": "int", "name": "b"},   # bytes 2..5 — overlaps a
                ],
            }, socket_timeout=_RPC_TIMEOUT)
            pytest.fail("Expected DaemonError for overlapping fields")
        except DaemonError as exc:
            assert exc.error == "ValueError", exc
            assert "overlap" in str(exc).lower(), exc

    def test_create_enum(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"TestEnum_{uid}"

        result = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"],
            "name":   name,
            "values": [
                {"name": "VAL_A", "value": 0},
                {"name": "VAL_B", "value": 1},
                {"name": "VAL_C", "value": 2},
            ],
            "size":  4,
        })["result"]

        assert "name" in result, f"Expected 'name' in create_enum result: {result}"
        assert result["name"] == name

        # Verify it shows up in list_data_types
        list_result = rpc(daemon["sock"], "list_data_types", {
            "binary": daemon["short_name"],
            "category": "enum", "query": uid, "limit": 10,
        })["result"]
        enum_names = [dt["name"] for dt in list_result["data_types"]]
        assert name in enum_names, (
            f"Newly created enum '{name}' not found; got: {enum_names}"
        )

    def test_create_enum_values_preserved(self, daemon):
        uid  = uuid.uuid4().hex[:8]
        name = f"ValueEnum_{uid}"

        result = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"],
            "name":   name,
            "values": [
                {"name": "FIRST",  "value": 10},
                {"name": "SECOND", "value": 20},
            ],
            "size": 4,
        })["result"]

        assert "values" in result, f"Expected 'values' in create_enum result: {result}"
        val_map = {v["name"]: v["value"] for v in result["values"]}
        assert val_map.get("FIRST")  == 10
        assert val_map.get("SECOND") == 20

    def test_create_enum_negative_values(self, daemon):
        """Error-code enums need negative values (the CLI passes `-1` through)."""
        name = f"NegEnum_{uuid.uuid4().hex[:8]}"
        result = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"],
            "name":   name,
            "values": [{"name": "FAIL", "value": -1}, {"name": "OK", "value": 0}],
            "size": 4,
        })["result"]
        val_map = {v["name"]: v["value"] for v in result["values"]}
        assert val_map == {"FAIL": -1, "OK": 0}

    def test_failed_write_does_not_wedge_next_write(self, daemon):
        """A write that aborts mid-transaction must not corrupt the next write.

        See https://github.com/NationalSecurityAgency/ghidra/issues/9347 --
        GhidraProject kept a permanently-open outer transaction on every
        managed program, so an aborted nested transaction rolled back the
        whole intertwined group on the next save(), silently discarding a
        later, unrelated write.
        """
        uid = uuid.uuid4().hex[:8]

        # Trigger a real abort: a dynamic-length field placed after a valid
        # one makes create_struct mutate the DTM before raising ValueError.
        from ghidra_rpc.client import DaemonError, send_request
        try:
            send_request(daemon["sock"], "create_struct", {
                "binary": daemon["short_name"],
                "name": f"AbortWedgeRegressionStruct_{uid}",
                "fields": [
                    {"type": "int", "name": "ok_field"},
                    {"type": "string", "name": "bad_dynamic_field"},
                ],
            }, socket_timeout=_RPC_TIMEOUT)
            pytest.fail("Expected create_struct to fail on a dynamic-length field")
        except DaemonError:
            pass

        # 2. Immediately (no other commands in between) issue a real, valid write.
        enum_name = f"AbortWedgeRegressionEnum_{uid}"
        good = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"],
            "name": enum_name,
            "values": [{"name": "X", "value": 1}],
        })
        assert good["ok"] is True

        # 3. Verify via an INDEPENDENT read (not the write's own response) that
        #    it actually persisted -- this is the crux of the bug: the write's
        #    own response looks fine either way.
        check = rpc(daemon["sock"], "list_data_types", {
            "binary": daemon["short_name"], "query": enum_name,
        })["result"]
        assert check["count"] == 1, (
            "the write immediately following a failed write was silently "
            f"lost: {check}"
        )


    @pytest.mark.parametrize("cmd, good, bad, key", [
        ("create_struct",
         {"fields": [{"type": "int", "name": "kept"}]},
         {"fields": [{"type": "int", "name": "x"}, {"type": "NoSuchType_zz", "name": "y"}]},
         "fields"),
        ("create_union",
         {"fields": [{"type": "int", "name": "kept"}]},
         {"fields": [{"type": "int", "name": "x"}, {"type": "NoSuchType_zz", "name": "y"}]},
         "fields"),
        ("create_enum",
         {"values": [{"name": "kept", "value": 1}], "size": 1},
         {"values": [{"name": "x", "value": 1}, {"name": "x", "value": 2}], "size": 1},
         "values"),
    ])
    def test_failed_or_replace_keeps_the_existing_type(self, daemon, cmd, good, bad, key):
        """--or-replace removes the old type in the same transaction as the
        rebuild, so a definition that fails leaves the original intact."""
        sock, binary = daemon["sock"], daemon["short_name"]
        name = f"OrReplace_{cmd}_{uuid.uuid4().hex[:8]}"
        rpc(sock, cmd, {"binary": binary, "name": name, **good})

        rpc_error(sock, cmd, {"binary": binary, "name": name, "or_replace": True, **bad})

        existing = rpc(sock, cmd, {"binary": binary, "name": name,
                                   "if_not_exists": True, **good})["result"]
        assert existing["already_existed"] is True
        assert [f["name"] for f in existing[key]] == ["kept"]

        replaced = rpc(sock, cmd, {"binary": binary, "name": name, "or_replace": True,
                                   **{key: good[key]}, **({"size": 1} if cmd == "create_enum" else {})})["result"]
        assert replaced["already_existed"] is False


# ── 12. Function tags ─────────────────────────────────────────────────────────

class TestTags:
    """Tests for tag_function, untag_function, list_tags, functions_by_tag."""

    def test_tag_function_and_list(self, daemon):
        uid = uuid.uuid4().hex[:8]
        tag = f"test-tag-{uid}"

        rpc(daemon["sock"], "tag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

        list_result = rpc(daemon["sock"], "list_tags",
                          {"binary": daemon["short_name"]})["result"]
        tag_names = [t["name"] for t in list_result["tags"]]
        assert tag in tag_names, (
            f"Tag '{tag}' not found in list_tags; got: {tag_names}"
        )

        # Cleanup
        rpc(daemon["sock"], "untag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

    def test_functions_by_tag(self, daemon):
        uid = uuid.uuid4().hex[:8]
        tag = f"by-tag-test-{uid}"

        rpc(daemon["sock"], "tag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

        result = rpc(daemon["sock"], "functions_by_tag", {
            "binary": daemon["short_name"],
            "tag":    tag,
        })["result"]
        fn_names = [f["name"] for f in result["functions"]]
        assert daemon["main_name"] in fn_names, (
            f"Expected '{daemon['main_name']}' in functions_by_tag; got: {fn_names}"
        )

        # Cleanup
        rpc(daemon["sock"], "untag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

    def test_untag_function_removes_tag(self, daemon):
        uid = uuid.uuid4().hex[:8]
        tag = f"untag-test-{uid}"

        rpc(daemon["sock"], "tag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })
        rpc(daemon["sock"], "untag_function", {
            "binary": daemon["short_name"],
            "target": daemon["main_name"],
            "tag":    tag,
        })

        result = rpc(daemon["sock"], "functions_by_tag", {
            "binary": daemon["short_name"],
            "tag":    tag,
        })["result"]
        assert result["functions"] == [], (
            f"Expected no functions with tag '{tag}' after untagging; "
            f"got: {result['functions']}"
        )


    def test_tag_with_surrounding_whitespace_is_trimmed(self, daemon):
        """The tag that is created is the one attached: no orphan 'x ' tag."""
        tag = f"ws-tag-{uuid.uuid4().hex[:8]}"
        base = {"binary": daemon["short_name"], "target": daemon["main_name"]}
        try:
            result = rpc(daemon["sock"], "tag_function", {**base, "tag": f"  {tag} "})["result"]
            assert tag in result["all_tags"]
            tags = {t["name"]: t["count"]
                    for t in rpc(daemon["sock"], "list_tags",
                                 {"binary": daemon["short_name"]})["result"]["tags"]}
            assert tags.get(tag) == 1
            assert not [n for n in tags if n != tag and n.strip() == tag], tags
            found = rpc(daemon["sock"], "functions_by_tag", {
                "binary": daemon["short_name"], "tag": f"{tag} "})["result"]
            assert daemon["main_name"] in [f["name"] for f in found["functions"]]
        finally:
            rpc(daemon["sock"], "untag_function", {**base, "tag": tag})


# ── Variable-discovery helper ───────────────────────────────────────────────

def _discover_variables(sock, binary, func_name, timeout=_RPC_TIMEOUT):
    """Return list of high-variable names visible in *func_name*'s decompiler view.

    Works by sending ``retype_variable`` with a sentinel name that will never
    match any real symbol.  The resulting ``DaemonError`` message always
    contains ``"Available: [...]"`` which is parsed with ``ast.literal_eval``.
    Returns ``[]`` if the function has no decompiler variables or parsing fails.
    """
    import ast
    import re
    from ghidra_rpc.client import DaemonError, send_request

    try:
        send_request(
            sock,
            "retype_variable",
            {
                "binary":    binary,
                "func":      func_name,
                "variable":  "__ghidra_rpc_probe_xyz__",
                "data_type": "int",
            },
            socket_timeout=timeout,
        )
        return []   # shouldn't happen — probe name is deliberately bogus
    except DaemonError as exc:
        m = re.search(r"Available:\s*(\[.*\])", str(exc), re.DOTALL)
        if m:
            try:
                return ast.literal_eval(m.group(1))
            except Exception:
                pass
    return []


# ── 13. Save ──────────────────────────────────────────────────────────────────

class TestSave:
    """Tests for the save command."""

    def test_save_named_binary(self, daemon):
        result = rpc(daemon["sock"], "save",
                     {"binary": daemon["short_name"]})["result"]
        assert "saved" in result
        assert any("testapp" in s for s in result["saved"]), (
            f"Expected 'testapp' in saved list; got: {result['saved']}"
        )

    def test_save_all(self, daemon):
        result = rpc(daemon["sock"], "save", {})["result"]
        assert "saved" in result
        assert len(result["saved"]) > 0


# ── 14. Retype variable ─────────────────────────────────────────────────────────

class TestRetypeVariable:
    """Integration tests for ``retype_variable``.

    Uses ``sum_array`` (two int parameters plus int locals compiled at -O0),
    which provides a reliable set of typed stack variables.

    Each test restores the original type after itself so daemon state stays
    clean for subsequent tests.
    """

    _FUNC = "sum_array"

    # ---- Helpers -------------------------------------------------------

    def _get_variable_names(self, daemon):
        """Return sorted list of variable names visible in _FUNC, or skip."""
        names = _discover_variables(
            daemon["sock"], daemon["short_name"], self._FUNC
        )
        if not names:
            pytest.skip(
                f"No decompiler variables found in '{self._FUNC}' "
                f"(Ghidra analysis may not have produced high variables)"
            )
        return names

    def _pick_variable(self, daemon):
        """Return a suitable variable name for type-change tests.

        Prefers ``param_*`` names (int-typed integer parameters) since those
        are the most stable across Ghidra versions.  Falls back to the first
        available variable.
        """
        names = self._get_variable_names(daemon)
        return next(
            (n for n in names if n.startswith("param_")),
            names[0],
        )

    # ---- Tests ---------------------------------------------------------

    def test_retype_variable_response_fields(self, daemon):
        """retype_variable response must contain all expected fields."""
        var_name = self._pick_variable(daemon)

        # Retype to ``long``; record old_type so we can restore below.
        result = rpc(daemon["sock"], "retype_variable", {
            "binary":    daemon["short_name"],
            "func":      self._FUNC,
            "variable":  var_name,
            "data_type": "long",
        })["result"]

        required = {"function", "variable", "old_type", "new_type", "verified"}
        missing = required - result.keys()
        assert not missing, (
            f"retype_variable response missing fields {missing}: {result}"
        )
        assert result["function"] == self._FUNC, (
            f"Expected function='{self._FUNC}', got: {result['function']!r}"
        )
        assert result["variable"] == var_name, (
            f"Expected variable='{var_name}', got: {result['variable']!r}"
        )
        assert isinstance(result["new_type"], str) and result["new_type"], (
            f"new_type should be a non-empty string, got: {result['new_type']!r}"
        )
        assert isinstance(result["old_type"], str), (
            f"old_type should be a string, got: {result['old_type']!r}"
        )

        # Cleanup: restore to original type; fall back to 'int' if restore fails.
        old_type = result["old_type"]
        for restore_type in (old_type, "int"):
            try:
                rpc(daemon["sock"], "retype_variable", {
                    "binary":    daemon["short_name"],
                    "func":      self._FUNC,
                    "variable":  var_name,
                    "data_type": restore_type,
                })
                break
            except Exception:
                continue

    def test_retype_variable_changes_type(self, daemon):
        """Retyping to a different type must produce a different new_type.

        Steps:
        1. Retype to ``int``   (known baseline; records old_type).
        2. Retype to ``long``  (the actual change under test).
        3. Verify new_type from step 2 differs from the ``int`` baseline.
        4. Cleanup: retype back to ``int``.
        """
        var_name = self._pick_variable(daemon)

        # Step 1: normalise to int so we have a known-good before state.
        rpc(daemon["sock"], "retype_variable", {
            "binary":    daemon["short_name"],
            "func":      self._FUNC,
            "variable":  var_name,
            "data_type": "int",
        })

        # Step 2: retype to long.
        result = rpc(daemon["sock"], "retype_variable", {
            "binary":    daemon["short_name"],
            "func":      self._FUNC,
            "variable":  var_name,
            "data_type": "long",
        })["result"]

        # old_type is whatever step 1 produced (likely "int");
        # new_type must differ since int (4 bytes) ≠ long (8 bytes) on x86-64.
        assert result["old_type"] != result["new_type"], (
            f"Retype int → long should produce different types; "
            f"old_type={result['old_type']!r}, new_type={result['new_type']!r}"
        )

        # Cleanup.
        try:
            rpc(daemon["sock"], "retype_variable", {
                "binary":    daemon["short_name"],
                "func":      self._FUNC,
                "variable":  var_name,
                "data_type": "int",
            })
        except Exception:
            pass

    def test_retype_variable_nonexistent_variable_errors(self, daemon):
        """Retyping a variable that doesn't exist must raise a clear error."""
        from ghidra_rpc.client import DaemonError, send_request

        try:
            send_request(
                daemon["sock"], "retype_variable",
                {
                    "binary":    daemon["short_name"],
                    "func":      self._FUNC,
                    "variable":  "_no_such_variable_xyz_",
                    "data_type": "int",
                },
                socket_timeout=_RPC_TIMEOUT,
            )
            pytest.fail("Expected DaemonError for nonexistent variable")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )
            # The error message should name the missing variable.
            assert "_no_such_variable_xyz_" in str(exc), (
                f"Expected variable name in error message: {exc}"
            )

    def test_retype_variable_unknown_type_errors(self, daemon):
        """Retyping to a completely unknown type must raise a clear error."""
        from ghidra_rpc.client import DaemonError, send_request

        names = _discover_variables(
            daemon["sock"], daemon["short_name"], self._FUNC
        )
        if not names:
            pytest.skip(f"No decompiler variables found in '{self._FUNC}'")

        try:
            send_request(
                daemon["sock"], "retype_variable",
                {
                    "binary":    daemon["short_name"],
                    "func":      self._FUNC,
                    "variable":  names[0],
                    "data_type": "_completely_bogus_type_xyz_",
                },
                socket_timeout=_RPC_TIMEOUT,
            )
            pytest.fail("Expected DaemonError for unknown type")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )

    def test_retype_variable_nonexistent_function_errors(self, daemon):
        """Retyping a variable in a nonexistent function must raise a clear error."""
        from ghidra_rpc.client import DaemonError, send_request

        try:
            send_request(
                daemon["sock"], "retype_variable",
                {
                    "binary":   daemon["short_name"],
                    "func":     "_nonexistent_func_xyz_",
                    "variable": "param_1",
                    "data_type": "int",
                },
                socket_timeout=_RPC_TIMEOUT,
            )
            pytest.fail("Expected DaemonError for nonexistent function")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )


# ── 15. Rename variable ─────────────────────────────────────────────────────────

class TestRenameVariable:
    """Integration tests for ``rename_variable``.

    Uses ``factorial`` (one int parameter; simple recursive structure at -O0)
    so the decompiler consistently exposes at least one renaming target.

    Every test renames the variable back to its original name as cleanup so
    subsequent tests and functions see a consistent state.
    """

    _FUNC = "factorial"

    # ---- Helpers -------------------------------------------------------

    def _pick_variable(self, daemon):
        """Return a stable variable name to rename in _FUNC, or skip.

        Prefers ``param_*`` names (the most deterministic across Ghidra versions)
        and falls back to the first available name.
        """
        names = _discover_variables(
            daemon["sock"], daemon["short_name"], self._FUNC
        )
        if not names:
            pytest.skip(
                f"No decompiler variables found in '{self._FUNC}' "
                f"(Ghidra analysis may not have produced high variables)"
            )
        return next(
            (n for n in names if n.startswith("param_")),
            names[0],
        )

    # ---- Tests ---------------------------------------------------------

    def test_rename_variable_response_fields(self, daemon):
        """rename_variable response must contain all expected fields."""
        var_name = self._pick_variable(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"_rnvar_{uid}"

        result = rpc(daemon["sock"], "rename_variable", {
            "binary":   daemon["short_name"],
            "func":     self._FUNC,
            "variable": var_name,
            "new_name": new_name,
        })["result"]

        required = {"function", "variable", "new_name", "verified"}
        missing = required - result.keys()
        assert not missing, (
            f"rename_variable response missing fields {missing}: {result}"
        )
        assert result["function"] == self._FUNC, (
            f"Expected function='{self._FUNC}', got: {result['function']!r}"
        )
        assert result["variable"] == var_name, (
            f"Expected variable='{var_name}', got: {result['variable']!r}"
        )
        assert result["new_name"] == new_name, (
            f"Expected new_name='{new_name}', got: {result['new_name']!r}"
        )

        # Cleanup: rename back to the original name.
        rpc(daemon["sock"], "rename_variable", {
            "binary":   daemon["short_name"],
            "func":     self._FUNC,
            "variable": new_name,
            "new_name": var_name,
        })

    def test_rename_variable_verified_true_on_success(self, daemon):
        """verified must be True when the rename succeeds."""
        var_name = self._pick_variable(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"_rnverified_{uid}"

        result = rpc(daemon["sock"], "rename_variable", {
            "binary":   daemon["short_name"],
            "func":     self._FUNC,
            "variable": var_name,
            "new_name": new_name,
        })["result"]

        assert result["verified"] is True, (
            f"Expected verified=True after rename; got: {result}"
        )

        # Cleanup.
        rpc(daemon["sock"], "rename_variable", {
            "binary":   daemon["short_name"],
            "func":     self._FUNC,
            "variable": new_name,
            "new_name": var_name,
        })

    def test_rename_variable_persists_in_decompile(self, daemon):
        """After renaming, the new variable name must appear in re-decompiled code.

        The ``rename_variable`` handler calls ``decompiler_pool.invalidate_all()``
        so the very next ``decompile`` call should reflect the updated symbol.
        """
        var_name = self._pick_variable(daemon)
        uid      = uuid.uuid4().hex[:8]
        new_name = f"rnpersist_{uid}"

        rpc(daemon["sock"], "rename_variable", {
            "binary":   daemon["short_name"],
            "func":     self._FUNC,
            "variable": var_name,
            "new_name": new_name,
        })

        # Re-decompile and check the new name appears in the output.
        c_code = rpc(daemon["sock"], "decompile", {
            "binary":  daemon["short_name"],
            "func":    self._FUNC,
            "timeout": 60,
        })["result"]["c_code"]

        assert new_name in c_code, (
            f"Renamed variable '{new_name}' not found in decompiled code:\n{c_code}"
        )

        # Cleanup: rename back to original.
        rpc(daemon["sock"], "rename_variable", {
            "binary":   daemon["short_name"],
            "func":     self._FUNC,
            "variable": new_name,
            "new_name": var_name,
        })

    def test_rename_variable_nonexistent_variable_errors(self, daemon):
        """Renaming a variable that doesn't exist must raise a clear error."""
        from ghidra_rpc.client import DaemonError, send_request

        try:
            send_request(
                daemon["sock"], "rename_variable",
                {
                    "binary":   daemon["short_name"],
                    "func":     self._FUNC,
                    "variable": "_no_such_var_xyz_",
                    "new_name": "something",
                },
                socket_timeout=_RPC_TIMEOUT,
            )
            pytest.fail("Expected DaemonError for nonexistent variable")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )
            assert "_no_such_var_xyz_" in str(exc), (
                f"Expected variable name in error message: {exc}"
            )

    def test_rename_variable_nonexistent_function_errors(self, daemon):
        """Renaming a variable in a nonexistent function must raise a clear error."""
        from ghidra_rpc.client import DaemonError, send_request

        try:
            send_request(
                daemon["sock"], "rename_variable",
                {
                    "binary":   daemon["short_name"],
                    "func":     "_nonexistent_func_xyz_",
                    "variable": "param_1",
                    "new_name": "something",
                },
                socket_timeout=_RPC_TIMEOUT,
            )
            pytest.fail("Expected DaemonError for nonexistent function")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), (
                f"Unexpected error type: {exc.error}"
            )


# ── 16. Batch edit variables ──────────────────────────────────────────────────

class TestBatchEditVariable:
    """Integration tests for ``batch_edit_variables``.

    Uses ``str_dup_upper`` (one ``const char *`` param plus several -O0 locals)
    so the decompiler exposes at least two editable variables.  Each test
    restores the variables it touches so the shared module-scoped daemon stays
    consistent for other tests.
    """

    _FUNC = "str_dup_upper"

    def _variable_names(self, daemon, minimum=2):
        names = _discover_variables(
            daemon["sock"], daemon["short_name"], self._FUNC
        )
        if len(names) < minimum:
            pytest.skip(
                f"Need >= {minimum} decompiler variables in '{self._FUNC}'; "
                f"found {names}"
            )
        return names

    def test_batch_rename_two_vars_single_snapshot(self, daemon):
        """Two renames in one call both succeed and verify — the core #1 fix."""
        names = self._variable_names(daemon)
        v1, v2 = names[0], names[1]
        uid = uuid.uuid4().hex[:8]
        n1, n2 = f"ba_{uid}", f"bb_{uid}"

        result = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"],
            "func":   self._FUNC,
            "operations": [
                {"variable": v1, "new_name": n1},
                {"variable": v2, "new_name": n2},
            ],
        })["result"]

        assert result["count"] == 2, result
        assert result["ok_count"] == 2, result
        assert result["error_count"] == 0, result
        assert result["verified_count"] == 2, (
            f"Both renames should verify in a single snapshot; got: {result}"
        )
        new_names = {r["new_name"] for r in result["results"]}
        assert new_names == {n1, n2}, result

        # Cleanup: rename both back in one batch.
        rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [
                {"variable": n1, "new_name": v1},
                {"variable": n2, "new_name": v2},
            ],
        })

    def test_batch_rename_and_retype_combined(self, daemon):
        """A single op may set both new_name and data_type; both must apply."""
        names = self._variable_names(daemon)
        target = next((n for n in names if n.startswith("param_")), names[0])
        uid = uuid.uuid4().hex[:8]
        new_name = f"combo_{uid}"

        result = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"],
            "func":   self._FUNC,
            "operations": [
                {"variable": target, "new_name": new_name, "data_type": "long"},
            ],
        })["result"]

        item = result["results"][0]
        assert item["ok"] is True, item
        assert item["new_name"] == new_name, item
        assert item["verified"] is True, (
            f"Combined rename+retype should verify; got: {item}"
        )
        assert "long" in item["new_type"].lower(), item

        # Cleanup: restore original name.
        rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [{"variable": new_name, "new_name": target}],
        })

    def test_batch_edit_by_storage(self, daemon):
        """A variable can be addressed by its (stable) storage string."""
        names = self._variable_names(daemon)
        v1 = names[0]
        uid = uuid.uuid4().hex[:8]
        n1 = f"stg_{uid}"

        # First edit by name; the response carries the variable's storage.
        first = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [{"variable": v1, "new_name": n1}],
        })["result"]["results"][0]
        storage = first.get("storage")
        assert storage, f"expected a storage string in result: {first}"

        # Now retype the same variable addressed purely by storage.
        by_storage = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [{"storage": storage, "data_type": "long"}],
        })["result"]["results"][0]

        assert by_storage["ok"] is True, by_storage
        assert by_storage["storage"] == storage, by_storage
        assert by_storage["verified"] is True, (
            f"Storage-addressed retype should verify; got: {by_storage}"
        )

        # Cleanup: rename back by name.
        rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [{"variable": n1, "new_name": v1}],
        })

    def test_batch_partial_failure_reports_per_item(self, daemon):
        """A bogus variable fails per-item (with Available:) without aborting others."""
        names = self._variable_names(daemon)
        good = names[0]
        uid = uuid.uuid4().hex[:8]
        good_new = f"ok_{uid}"

        result = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [
                {"variable": good, "new_name": good_new},
                {"variable": "__no_such_var__", "new_name": "nope"},
            ],
        })["result"]

        assert result["ok_count"] == 1, result
        assert result["error_count"] == 1, result
        bad = next(r for r in result["results"] if not r["ok"])
        assert "__no_such_var__" in bad["message"], bad
        assert "Available:" in bad["message"], (
            f"error should list available variables (issue #3): {bad}"
        )

        # Cleanup: rename the good one back.
        rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [{"variable": good_new, "new_name": good}],
        })

    def test_batch_op_without_edit_is_rejected(self, daemon):
        """An op with neither new_name nor data_type is a per-item error."""
        names = self._variable_names(daemon)
        result = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": self._FUNC,
            "operations": [{"variable": names[0]}],
        })["result"]

        assert result["ok_count"] == 0, result
        assert result["error_count"] == 1, result
        assert "new_name" in result["results"][0]["message"], result

    def test_batch_overlapping_retype_reports_unverified(self, daemon):
        """A retype whose new storage overlaps a neighbour is applied but reverts;
        the per-item ``verified`` flag must report that it did not stick.

        This exercises the documented sharp edge (a storage conflict silently
        reverts the edit) and locks in the guarantee that ``verified`` catches it.
        Runs against ``main`` — which has a block of adjacent 4-byte stack locals —
        so it does not disturb the other tests' target function.
        """
        import re

        func = "main"
        names = _discover_variables(daemon["sock"], daemon["short_name"], func)
        if len(names) < 2:
            pytest.skip(f"need >= 2 vars in '{func}'; found {names}")

        # Probe: rename every local to read back its storage + current type.
        probe = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": func,
            "operations": [{"variable": n, "new_name": f"{n}__p"} for n in names],
        })["result"]

        # Collect 4-byte stack slots as (offset, current_name).
        slots = []
        for r in probe["results"]:
            if not r.get("ok"):
                continue
            m = re.match(r"Stack\[(-?0x[0-9a-fA-F]+)\]:(\d+)", r.get("storage", ""))
            if m and int(m.group(2)) == 4 and r.get("old_type") == "undefined4":
                slots.append((int(m.group(1), 16), r["new_name"]))

        # Find an adjacent pair (stack offsets exactly 4 apart).
        slots.sort()
        pair = next(
            ((slots[i][1], slots[i + 1][1])
             for i in range(len(slots) - 1)
             if slots[i + 1][0] - slots[i][0] == 4),
            None,
        )
        if pair is None:
            pytest.skip("no adjacent 4-byte stack slots available to force an overlap")

        lower, upper = pair
        # Grow both adjacent 4-byte slots to 8-byte types -> they must collide.
        result = rpc(daemon["sock"], "batch_edit_variables", {
            "binary": daemon["short_name"], "func": func,
            "operations": [
                {"variable": lower, "new_name": "ov_a", "data_type": "double"},
                {"variable": upper, "new_name": "ov_b", "data_type": "double"},
            ],
        })["result"]

        assert result["ok_count"] == 2, (
            f"overlapping retypes apply without exception (silent revert): {result}"
        )
        assert result["verified_count"] < 2, (
            f"an overlapping retype must revert and report verified=false: {result}"
        )
        assert any(r.get("verified") is False for r in result["results"]), result


# ── Memory-block helper ─────────────────────────────────────────────────────

class TestAddressFormat:
    """Every address the daemon emits is 0x-prefixed and accepted back as-is."""

    def test_output_addresses_are_0x_prefixed(self, daemon):
        b = daemon["short_name"]
        funcs = rpc(daemon["sock"], "functions",
                    {"binary": b, "with_body": True})["result"]["functions"]
        xrefs = rpc(daemon["sock"], "xrefs_from",
                    {"binary": b, "target": daemon["main_name"], "limit": 10})["result"]["xrefs"]
        segs = rpc(daemon["sock"], "memory_map", {"binary": b})["result"]["segments"]
        meta = rpc(daemon["sock"], "metadata", {"binary": b})["result"]
        emitted = (
            [f[k] for f in funcs for k in ("address", "body_min", "body_max")]
            + [x[k] for x in xrefs for k in ("from_address", "to_address")
               if not x[k].startswith("Stack[")]
            + [s[k] for s in segs for k in ("start", "end")]
            + [meta["base_address"]]
        )
        bad = [a for a in emitted if "0x" not in a]
        assert not bad, f"addresses missing 0x prefix: {bad[:10]}"

    def test_function_addresses_round_trip_through_decompile(self, daemon):
        b = daemon["short_name"]
        local = [f for f in daemon["all_funcs"] if f["address"].startswith("0x")]
        for f in local[:5]:
            result = rpc(daemon["sock"], "decompile",
                         {"binary": b, "func": f["address"], "timeout": 60})["result"]
            assert result["address"] == f["address"], (f, result["address"])

    def test_xref_address_round_trips_through_disassemble(self, daemon):
        b = daemon["short_name"]
        xref = rpc(daemon["sock"], "xrefs_from",
                   {"binary": b, "target": daemon["main_name"], "limit": 1})["result"]["xrefs"][0]
        result = rpc(daemon["sock"], "disassemble",
                     {"binary": b, "address": xref["from_address"], "count": 1})["result"]
        assert result["address"] == xref["from_address"]
        assert result["listing"].startswith(xref["from_address"])

    def test_bare_hex_does_not_resolve_to_fun_name(self, daemon):
        """Bare hex is a name query; it must not partial-match FUN_<hex>."""
        from ghidra_rpc.client import DaemonError, send_request
        fun = next((f for f in daemon["all_funcs"] if f["name"].startswith("FUN_")), None)
        if fun is None:
            pytest.skip("no auto-named FUN_ function in testapp")
        with pytest.raises(DaemonError, match="0x prefix"):
            send_request(daemon["sock"], "decompile",
                         {"binary": daemon["short_name"], "func": fun["name"][4:]})


def _find_block(daemon, name, binary=None):
    """Return the memory_map segment dict named *name*, or skip if absent.

    *binary* defaults to the shared ``testapp``.
    """
    segs = rpc(daemon["sock"], "memory_map",
               {"binary": binary or daemon["short_name"]})["result"]["segments"]
    blk = next((s for s in segs if s["name"] == name), None)
    if blk is None:
        pytest.skip(f"binary has no '{name}' block; available: "
                    f"{[s['name'] for s in segs]}")
    return blk


# ── 17. Read pointers ───────────────────────────────────────────────────────

class TestReadPointers:
    """Integration tests for ``read_pointers``.

    Uses ``.got.plt`` — after relocation Ghidra fills it with a mix of a data
    symbol (``_DYNAMIC``), zero slots, and resolved libc function pointers
    (``free``/``strlen``/``printf``/``malloc``/``fwrite`` from testapp.c).
    """

    _LIBC = {"free", "strlen", "printf", "malloc", "fwrite"}

    def test_read_pointers_structure(self, daemon):
        blk = _find_block(daemon, ".got.plt")
        n = blk["size"] // 8
        result = rpc(daemon["sock"], "read_pointers", {
            "binary": daemon["short_name"], "address": blk["start"], "count": n,
        })["result"]

        assert result["pointer_size"] == 8, result
        assert result["endian"] == "little", result
        assert result["count"] == n, result
        assert len(result["pointers"]) == n, result
        required = {"index", "offset", "slot_address", "value",
                    "target_address", "target_name", "target_kind"}
        for p in result["pointers"]:
            assert required <= p.keys(), p

    def test_read_pointers_resolves_functions(self, daemon):
        blk = _find_block(daemon, ".got.plt")
        n = blk["size"] // 8
        pointers = rpc(daemon["sock"], "read_pointers", {
            "binary": daemon["short_name"], "address": blk["start"], "count": n,
        })["result"]["pointers"]

        names = {p["target_name"] for p in pointers if p["target_name"]}
        assert names & self._LIBC, (
            f"expected a resolved libc import among {self._LIBC}; got {names}"
        )
        # .got.plt has NULL slots — they must be reported unresolved, not crash.
        zeros = [p for p in pointers if p["value"] == "0x0"]
        assert zeros, f"expected at least one NULL slot in .got.plt: {pointers}"
        assert all(p["target_address"] is None for p in zeros), zeros

    def test_read_pointers_pointer_size_override(self, daemon):
        blk = _find_block(daemon, ".got.plt")
        result = rpc(daemon["sock"], "read_pointers", {
            "binary": daemon["short_name"], "address": blk["start"],
            "count": 4, "pointer_size": 4,
        })["result"]
        assert result["pointer_size"] == 4, result
        assert result["count"] == 4, result

    def test_read_pointers_unmapped_errors(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request
        try:
            send_request(daemon["sock"], "read_pointers", {
                "binary": daemon["short_name"],
                "address": "0x7ffffff00000", "count": 4,
            }, socket_timeout=_RPC_TIMEOUT)
            pytest.fail("Expected DaemonError for unmapped address")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), exc


# ── 18. List vtable ─────────────────────────────────────────────────────────

class TestListVtable:
    """Integration tests for ``list_vtable``.

    testapp is C (no real C++ vtables), so these exercise the mechanics against
    ``.got.plt`` — a genuine table of function pointers — plus start-address
    resolution and termination behaviour.
    """

    _LIBC = {"free", "strlen", "printf", "malloc", "fwrite"}

    def _first_function_slot(self, daemon):
        """Return the (0x-prefixed) address of the first function pointer in
        .got.plt, using read_pointers to locate it."""
        blk = _find_block(daemon, ".got.plt")
        n = blk["size"] // 8
        pointers = rpc(daemon["sock"], "read_pointers", {
            "binary": daemon["short_name"], "address": blk["start"], "count": n,
        })["result"]["pointers"]
        slot = next((p for p in pointers if p["target_kind"] == "function"), None)
        if slot is None:
            pytest.skip("no function pointer found in .got.plt")
        return slot["slot_address"]

    def test_list_vtable_count_path(self, daemon):
        """With --count, read exactly N slots and stop with reason 'count'."""
        blk = _find_block(daemon, ".got.plt")
        n = blk["size"] // 8
        result = rpc(daemon["sock"], "list_vtable", {
            "binary": daemon["short_name"], "address": blk["start"],
            "count": n,
        })["result"]

        assert result["stopped_reason"] == "count", result
        assert result["count"] == n, result
        names = {s["target_name"] for s in result["slots"] if s["target_name"]}
        assert names & self._LIBC, (
            f"expected resolved libc functions in the table; got {names}"
        )

    def test_list_vtable_auto_termination(self, daemon):
        """Without --count, walk function pointers and stop at a boundary."""
        start = self._first_function_slot(daemon)
        result = rpc(daemon["sock"], "list_vtable", {
            "binary": daemon["short_name"], "address": start,
        })["result"]

        assert result["count"] >= 1, result
        assert result["slots"][0]["target_kind"] == "function", result
        assert result["stopped_reason"] in (
            "non_function_pointer", "next_vtable_symbol", "unreadable", "cap",
        ), result

    def test_list_vtable_resolves_start_by_name(self, daemon):
        """The start argument may be a function/symbol name, not just an address."""
        # 'main' resolves via the function table to its entry point.
        main_addr = rpc(daemon["sock"], "decompile", {
            "binary": daemon["short_name"], "func": "main",
        })["result"]["address"]

        result = rpc(daemon["sock"], "list_vtable", {
            "binary": daemon["short_name"], "address": "main",
        })["result"]
        assert result["vtable_address"] == main_addr, (
            f"start-by-name should resolve to main's entry {main_addr}; "
            f"got {result['vtable_address']}"
        )

    def test_list_vtable_bad_target_errors(self, daemon):
        from ghidra_rpc.client import DaemonError, send_request
        try:
            send_request(daemon["sock"], "list_vtable", {
                "binary": daemon["short_name"],
                "address": "__no_such_symbol_or_addr__",
            }, socket_timeout=_RPC_TIMEOUT)
            pytest.fail("Expected DaemonError for unresolvable target")
        except DaemonError as exc:
            assert exc.error in ("ValueError", "RuntimeError", "Exception"), exc


# ── Version Tracking ───────────────────────────────────────────────────────────

class TestVersionTracking:
    """version_track, and that _restore_daemon_programs re-applies
    HeadlessContext._take_ownership after handing the program back."""

    def test_version_track_and_restore(self, daemon, tmp_path):
        """version_track succeeds and the source binary's handle stays usable
        afterward, including surviving an abort immediately followed by a
        real write."""
        import shutil
        from ghidra_rpc.client import DaemonError, send_request

        copy_path = tmp_path / "vt_probe_binary"
        shutil.copy(_TEST_BINARY, copy_path)
        load_result = rpc(daemon["sock"], "load", {"path": str(copy_path)},
                          timeout=_LOAD_TIMEOUT)["result"]
        other_short_name = load_result["short_name"]

        vt_result = rpc(daemon["sock"], "version_track", {
            "source": daemon["short_name"], "destination": other_short_name,
            "limit": 5,
        }, timeout=_LOAD_TIMEOUT)
        assert vt_result["ok"] is True, vt_result
        # The two binaries are byte-identical copies of testapp -- nearly every
        # function should match. A non-zero match count (not just ok=True)
        # proves VT actually got writable access to real program data, not a
        # degraded/no-op correlator run against a handle it couldn't use.
        matched = vt_result["result"]["summary"]["source_functions_matched"]
        assert matched > 0, (
            f"expected matches between identical binaries, got 0: {vt_result['result']}"
        )

        # The daemon's handle to the source binary must still work post-restore.
        fns = rpc(daemon["sock"], "functions", {"binary": daemon["short_name"]})["result"]
        assert fns["functions"], "source binary unusable after version_track restore"

        # And its ownership must have been correctly re-taken: an abort
        # immediately followed by a real write must not wedge the latter.
        uid = uuid.uuid4().hex[:8]
        try:
            send_request(daemon["sock"], "create_struct", {
                "binary": daemon["short_name"],
                "name": f"VTPostAbortStruct_{uid}",
                "fields": [
                    {"type": "int", "name": "ok_field"},
                    {"type": "string", "name": "bad_dynamic_field"},
                ],
            }, socket_timeout=_RPC_TIMEOUT)
            pytest.fail("Expected create_struct to fail on a dynamic-length field")
        except DaemonError:
            pass

        enum_name = f"VTPostAbortEnum_{uid}"
        good = rpc(daemon["sock"], "create_enum", {
            "binary": daemon["short_name"], "name": enum_name,
            "values": [{"name": "X", "value": 1}],
        })
        assert good["ok"] is True

        check = rpc(daemon["sock"], "list_data_types", {
            "binary": daemon["short_name"], "query": enum_name,
        })["result"]
        assert check["count"] == 1, (
            f"write after version_track restore was silently lost: {check}"
        )


# ── DEX / Dalvik (Android) loader behavior ────────────────────────────────────

@pytest.fixture(scope="module")
def dex_binary(daemon):
    """Load the DEX fixture into the shared daemon; yield its short name.

    The daemon can hold several programs at once, so we reuse the module-scoped
    daemon (which already has ``testapp`` loaded) and add the DEX alongside it.
    Skips the dependent tests if the fixture file is missing.
    """
    if not _DEX_BINARY.exists():
        pytest.skip(f"DEX fixture not found: {_DEX_BINARY}")

    resp = rpc(
        daemon["sock"], "load",
        {"path": str(_DEX_BINARY), "analyze": True},
        timeout=_LOAD_TIMEOUT,
    )
    assert resp["ok"] is True, f"DEX load failed: {resp}"
    return resp["result"]["short_name"]  # "detectresolution-classes.dex"


class TestDexNamespaces:
    """list-namespaces must work on DEX/Dalvik programs.

    Regression test for the bug where ``list-namespaces`` returned an empty
    list for every DEX program: the old implementation scanned
    ``getSymbolIterator()``, which only yields memory-location labels and thus
    misses DEX package (``createNameSpace``) and class (``createClass``)
    namespaces, none of which are memory labels.  The fix walks the namespace
    tree from the global namespace via ``getChildren()`` instead.
    """

    def test_metadata_reports_dalvik(self, daemon, dex_binary):
        result = rpc(daemon["sock"], "metadata", {"binary": dex_binary})["result"]
        assert result["arch"] == "Dalvik", result
        assert "DEX" in result["format"].upper() or "DALVIK" in result["format"].upper(), result

    def test_list_namespaces_not_empty(self, daemon, dex_binary):
        result = rpc(
            daemon["sock"], "list_namespaces",
            {"binary": dex_binary, "limit": 100000},
        )["result"]
        assert result["count"] > 0, (
            "list-namespaces returned no namespaces for a DEX program; "
            "the getChildren() tree walk regressed back to the broken "
            "getSymbolIterator() scan."
        )
        assert len(result["namespaces"]) == result["count"]

    def test_list_namespaces_includes_class_and_package(self, daemon, dex_binary):
        result = rpc(
            daemon["sock"], "list_namespaces",
            {"binary": dex_binary, "limit": 100000},
        )["result"]
        types = {n["type"] for n in result["namespaces"]}
        # DEX produces both package Namespaces and class-hierarchy Classes.
        assert "Class" in types, f"Expected Class namespaces, got types: {types}"
        assert "Namespace" in types, f"Expected package Namespaces, got types: {types}"

        # The app's own MainActivity class must be discoverable, as a Class,
        # with its fully-qualified '::'-separated path.
        paths = {n["path"] for n in result["namespaces"]}
        assert any(
            p.endswith("MainActivity") and p.startswith("com::")
            for p in paths
        ), "Expected a com::...::MainActivity Class namespace in the results"

    def test_list_namespaces_entries_well_formed(self, daemon, dex_binary):
        result = rpc(
            daemon["sock"], "list_namespaces",
            {"binary": dex_binary, "limit": 50},
        )["result"]
        assert result["namespaces"], "expected at least one namespace"
        for ns in result["namespaces"]:
            assert set(ns) >= {"name", "path", "id", "type", "symbol_count"}, ns
            assert isinstance(ns["id"], int)
            assert isinstance(ns["symbol_count"], int) and ns["symbol_count"] >= 0
            assert ns["name"] and ns["path"]

    def test_list_namespaces_respects_limit(self, daemon, dex_binary):
        result = rpc(
            daemon["sock"], "list_namespaces",
            {"binary": dex_binary, "limit": 5},
        )["result"]
        assert result["count"] <= 5, result


class TestNamespacesNative:
    """list-namespaces on a native ELF: the getChildren() tree walk must still
    find nested user-created namespaces (guards the DEX fix against regressing
    native behavior)."""

    def test_created_namespace_is_listed(self, daemon):
        parent = "GrpcTestNsParent"
        child = "GrpcTestNsChild"

        rpc(daemon["sock"], "create_namespace",
            {"binary": daemon["short_name"], "name": parent})
        rpc(daemon["sock"], "create_namespace",
            {"binary": daemon["short_name"], "name": child, "parent": parent})

        result = rpc(daemon["sock"], "list_namespaces",
                     {"binary": daemon["short_name"], "limit": 100000})["result"]
        paths = {n["path"] for n in result["namespaces"]}
        assert parent in paths, f"top-level namespace missing: {paths}"
        # The nested child must be reached by the recursive tree walk.
        assert f"{parent}::{child}" in paths, (
            f"nested namespace not found via tree walk: {paths}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Handlers that rewrite or compare programs
#
# Most of the writes below have no inverse command (set-thunk, set-equate,
# set-calling-convention, set-signature, set-data-type, delete-function all
# leave state behind that can't be put back exactly), so they run against
# throwaway copies of testapp instead of the shared ``testapp`` the read-only
# tests depend on.  A copy loads and analyses in a few seconds.
#
# The copies' names must not substring-match each other or ``testapp``:
# ``get_program`` resolves by ``binary in key``.
#
# Within ``scratch`` each test touches its own function or address so the
# tests stay independent of run order.
# ══════════════════════════════════════════════════════════════════════════════

def rpc_error(sock: Path, cmd: str, args: dict | None = None,
              *, timeout: float = _RPC_TIMEOUT):
    """Send a request that must fail; return the ``DaemonError``."""
    from ghidra_rpc.client import DaemonError, send_request
    try:
        resp = send_request(sock, cmd, args or {}, socket_timeout=timeout)
    except DaemonError as exc:
        return exc
    pytest.fail(f"Expected '{cmd}' to fail, but it returned: {resp}")


def _load_copy(daemon, tmp_path_factory, name: str) -> dict:
    """Load a copy of testapp named *name*; return its short name + function map."""
    import shutil

    path = tmp_path_factory.mktemp(name) / name
    shutil.copy(_TEST_BINARY, path)
    short = rpc(daemon["sock"], "load", {"path": str(path), "analyze": True},
                timeout=_LOAD_TIMEOUT)["result"]["short_name"]
    funcs = rpc(daemon["sock"], "functions", {"binary": short})["result"]["functions"]
    return {"name": short, "funcs": {f["name"]: f["address"] for f in funcs}}


@pytest.fixture(scope="module")
def scratch(daemon, tmp_path_factory):
    """A disposable copy of testapp for destructive writes."""
    return _load_copy(daemon, tmp_path_factory, "gapscratch_bin")


@pytest.fixture(scope="module")
def diff_pair(daemon, tmp_path_factory):
    """Two byte-identical copies for diff/match tests, pristine except inside
    tests that patch one and restore it.  The shared ``testapp`` can't serve
    as the baseline: earlier tests retype its variables, which changes how
    its functions decompile."""
    return (_load_copy(daemon, tmp_path_factory, "gapdiff_a_bin"),
            _load_copy(daemon, tmp_path_factory, "gapdiff_b_bin"))


def _insns(daemon, binary: str, address: str, count: int) -> list[dict]:
    return rpc(daemon["sock"], "disassemble", {
        "binary": binary, "address": address, "count": count,
        "with_instructions": True,
    })["result"]["instructions"]


def _insn_text(insn: dict) -> str:
    """Assembler source for a disassembled instruction (round-trips through assemble)."""
    return f"{insn['mnemonic']} {insn['operands']}".strip()


def _read_hex(daemon, binary: str, address: str, length: int) -> str:
    return rpc(daemon["sock"], "read_bytes", {
        "binary": binary, "address": address, "length": length,
    })["result"]["hex"]


def _offset(address: str, delta: int) -> str:
    return f"0x{int(address, 16) + delta:08x}"


def _labels(daemon, binary: str, address: str, end: str | None = None) -> list[dict]:
    args = {"binary": binary, "address": address}
    if end:
        args["end"] = end
    return rpc(daemon["sock"], "list_labels", args)["result"]["labels"]


def _function_entry(daemon, binary: str, name: str, *, with_body: bool = False,
                    include_externals: bool = False) -> dict | None:
    funcs = rpc(daemon["sock"], "functions", {
        "binary": binary, "with_body": with_body,
        "include_externals": include_externals,
    })["result"]["functions"]
    return next((f for f in funcs if f["name"] == name), None)


def _unlabelled_addresses(daemon, binary: str, count: int) -> list[str]:
    """Return *count* addresses in .rodata that carry no symbol."""
    start = _find_block(daemon, ".rodata", binary)["start"]
    found = []
    for delta in range(1, 128):
        addr = _offset(start, delta)
        if not _labels(daemon, binary, addr):
            found.append(addr)
            if len(found) == count:
                return found
    pytest.fail(f"found only {len(found)} unlabelled addresses near {start}")


# ── exports ───────────────────────────────────────────────────────────────────

class TestExports:
    def test_exports_lists_global_functions_only(self, daemon):
        result = rpc(daemon["sock"], "exports", {"binary": daemon["short_name"]})["result"]
        assert result["count"] == len(result["exports"]) > 0
        for exp in result["exports"]:
            assert exp["name"] and exp["address"].startswith("0x"), exp
        names = {e["name"] for e in result["exports"]}
        assert {"stack_push", "factorial"} <= names, sorted(names)
        # node_alloc is `static` in testapp.c, so it must not be exported.
        assert "node_alloc" not in names


# ── write_bytes ───────────────────────────────────────────────────────────────

class TestWriteBytes:
    def test_round_trip_in_data_segment(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = _find_block(daemon, ".data", binary)["start"]
        original = _read_hex(daemon, binary, addr, 2)
        patched = "".join(f"{b ^ 0xFF:02x}" for b in bytes.fromhex(original))
        spaced = " ".join(patched[i:i + 2] for i in range(0, len(patched), 2))

        try:
            result = rpc(sock, "write_bytes",
                         {"binary": binary, "address": addr, "hex": spaced})["result"]
            assert result["verified"] is True
            assert result["length"] == 2
            assert result["hex"] == patched   # spaces stripped
            assert _read_hex(daemon, binary, addr, 2) == patched
        finally:
            rpc(sock, "write_bytes", {"binary": binary, "address": addr, "hex": original})
        assert _read_hex(daemon, binary, addr, 2) == original

    def test_overwriting_an_instruction_is_rejected(self, daemon, scratch):
        """Ghidra refuses setBytes over a defined instruction; the bytes must be untouched."""
        sock, binary = daemon["sock"], scratch["name"]
        addr = scratch["funcs"]["factorial"]
        original = _read_hex(daemon, binary, addr, 4)

        rpc_error(sock, "write_bytes", {"binary": binary, "address": addr, "hex": "90909090"})

        assert _read_hex(daemon, binary, addr, 4) == original

    def test_clear_then_write_patches_code(self, daemon, scratch):
        """The documented route for patching code: clear the instruction first."""
        sock, binary = daemon["sock"], scratch["name"]
        insn = _insns(daemon, binary, scratch["funcs"]["count_char"], 2)[1]
        addr, length = insn["address"], insn["length"]
        original = _read_hex(daemon, binary, addr, length)

        try:
            rpc(sock, "clear_data_range", {
                "binary": binary, "start": addr, "end": _offset(addr, length - 1),
            })
            result = rpc(sock, "write_bytes", {
                "binary": binary, "address": addr, "hex": "90" * length,
            })["result"]
            assert result["verified"] is True
            assert _read_hex(daemon, binary, addr, length) == "90" * length
        finally:
            rpc(sock, "assemble", {
                "binary": binary, "address": addr, "instructions": [_insn_text(insn)],
            })
        assert _read_hex(daemon, binary, addr, length) == original

    def test_unmapped_address_is_rejected(self, daemon, scratch):
        rpc_error(daemon["sock"], "write_bytes",
                  {"binary": scratch["name"], "address": "0x7fff0000", "hex": "00"})


# ── assemble ──────────────────────────────────────────────────────────────────

class TestAssemble:
    @staticmethod
    def _immediate_store(daemon, scratch) -> dict:
        """First `MOV <mem>,0x0` in sum_array (the `total = 0` store)."""
        insns = _insns(daemon, scratch["name"], scratch["funcs"]["sum_array"], 12)
        insn = next((i for i in insns
                     if i["mnemonic"] == "MOV" and i["operands"].endswith(",0x0")
                     and i["length"] >= 4), None)
        assert insn, f"no `MOV mem,0x0` in sum_array: {insns}"
        return insn

    def test_assemble_rewrites_instruction_and_listing(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        insn = self._immediate_store(daemon, scratch)
        addr = insn["address"]
        original = bytes.fromhex(insn["bytes"])
        patched_text = f"MOV {insn['operands'][:-3]}0x5"

        try:
            result = rpc(sock, "assemble", {
                "binary": binary, "address": addr, "instructions": [patched_text],
            })["result"]
            assert result["address"] == addr
            assert result["bytes_written"] == len(original)
            assert len(result["instructions"]) == 1
            assert result["instructions"][0]["operands"].endswith(",0x5")
            # imm32 immediate: only the low immediate byte differs from `...,0x0`.
            assert bytes.fromhex(result["hex"]) == original[:-4] + b"\x05\x00\x00\x00"
            assert _read_hex(daemon, binary, addr, len(original)) == result["hex"]

            listing = rpc(sock, "disassemble",
                          {"binary": binary, "address": addr, "count": 1})["result"]["listing"]
            assert ",0x5" in listing, listing
        finally:
            rpc(sock, "assemble", {
                "binary": binary, "address": addr, "instructions": [_insn_text(insn)],
            })
        assert _read_hex(daemon, binary, addr, len(original)) == original.hex()

    def test_syntax_error_is_reported_and_leaves_bytes_alone(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        insn = self._immediate_store(daemon, scratch)
        before = _read_hex(daemon, binary, insn["address"], insn["length"])

        exc = rpc_error(sock, "assemble", {
            "binary": binary, "address": insn["address"],
            "instructions": ["NOTANINSTRUCTION EAX"],
        })

        assert exc.error == "ValueError"
        assert "Assembly failed" in str(exc)
        assert _read_hex(daemon, binary, insn["address"], insn["length"]) == before


# ── function lifecycle and signature-level edits ──────────────────────────────

class TestFunctionLifecycle:
    def test_delete_then_create_restores_function_body(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        name, addr = "greet_casual", scratch["funcs"]["greet_casual"]
        before = _function_entry(daemon, binary, name, with_body=True)
        assert before is not None

        deleted = rpc(sock, "delete_function", {"binary": binary, "target": name})["result"]
        assert deleted == {"address": addr, "name": name, "deleted": True}
        assert _function_entry(daemon, binary, name) is None

        created = rpc(sock, "create_function",
                      {"binary": binary, "address": addr, "name": name})["result"]
        assert created["address"] == addr and created["name"] == name
        assert created["size"] == before["body_size"]

        after = _function_entry(daemon, binary, name, with_body=True)
        assert after is not None
        assert (after["body_min"], after["body_max"]) == (before["body_min"], before["body_max"])

    def test_create_function_rejects_existing_and_overlapping(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = scratch["funcs"]["factorial"]
        inside = _insns(daemon, binary, addr, 2)[1]["address"]

        assert "factorial" in str(rpc_error(sock, "create_function",
                                            {"binary": binary, "address": addr, "name": "dup"}))
        assert "factorial" in str(rpc_error(sock, "create_function",
                                            {"binary": binary, "address": inside, "name": "dup"}))
        assert _function_entry(daemon, binary, "dup") is None

    def test_set_thunk_hides_function_from_default_listing(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]

        result = rpc(sock, "set_thunk", {
            "binary": binary, "thunk": "stack_free", "target": "factorial",
        })["result"]

        assert result["verified"] is True
        assert result["thunk_name"] == "stack_free"
        assert result["target_name"] == "factorial"
        assert result["thunk_address"] == scratch["funcs"]["stack_free"]
        assert result["target_address"] == scratch["funcs"]["factorial"]
        assert _function_entry(daemon, binary, "stack_free") is None
        assert _function_entry(daemon, binary, "stack_free", include_externals=True) is not None

    def test_set_thunk_to_itself_is_rejected(self, daemon, scratch):
        rpc_error(daemon["sock"], "set_thunk", {
            "binary": scratch["name"], "thunk": "str_dup_upper", "target": "str_dup_upper",
        })

    def test_set_calling_convention_round_trip(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        listing = rpc(sock, "list_calling_conventions", {"binary": binary})["result"]
        default = listing["default"]
        other = next(c for c in listing["conventions"]
                     if c != default and c not in ("processEntry", "syscall"))

        changed = rpc(sock, "set_calling_convention", {
            "binary": binary, "target": "count_char", "convention": other,
        })["result"]
        assert changed["new_convention"] == other and changed["verified"] is True
        assert changed["address"] == scratch["funcs"]["count_char"]

        back = rpc(sock, "set_calling_convention", {
            "binary": binary, "target": "count_char", "convention": default,
        })["result"]
        assert back["old_convention"] == other
        assert back["new_convention"] == default and back["verified"] is True

    def test_set_calling_convention_rejects_unknown_name(self, daemon, scratch):
        exc = rpc_error(daemon["sock"], "set_calling_convention", {
            "binary": scratch["name"], "target": "count_char", "convention": "__nope",
        })
        listing = rpc(daemon["sock"], "list_calling_conventions",
                      {"binary": scratch["name"]})["result"]
        # The error names the valid choices so callers can self-correct.
        assert all(c in str(exc) for c in listing["conventions"])

    def test_set_function_signature_updates_listing(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]

        result = rpc(sock, "set_function_signature", {
            "binary": binary, "target": "str_dup_upper",
            "signature": "char * str_dup_upper(char * text);",
        })["result"]

        assert result["verified"] is True
        entry = _function_entry(daemon, binary, "str_dup_upper")
        assert "str_dup_upper(char * text)" in entry["signature"], entry

    def test_set_flow_override_round_trip(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        call = next(i for i in _insns(daemon, binary, scratch["funcs"]["main"], 30)
                    if i["mnemonic"] == "CALL")

        try:
            set_ = rpc(sock, "set_flow_override", {
                "binary": binary, "address": call["address"], "override": "CALL_RETURN",
            })["result"]
            assert (set_["old_override"], set_["override"], set_["verified"]) == (
                "NONE", "CALL_RETURN", True)
        finally:
            reset = rpc(sock, "set_flow_override", {
                "binary": binary, "address": call["address"], "override": "NONE",
            })["result"]
        assert (reset["old_override"], reset["override"], reset["verified"]) == (
            "CALL_RETURN", "NONE", True)

    def test_set_flow_override_rejects_unknown_value(self, daemon, scratch):
        call = next(i for i in _insns(daemon, scratch["name"], scratch["funcs"]["main"], 30)
                    if i["mnemonic"] == "CALL")
        rpc_error(daemon["sock"], "set_flow_override", {
            "binary": scratch["name"], "address": call["address"], "override": "BOGUS",
        })


# ── data definitions and labels ───────────────────────────────────────────────

class TestDataDefinitions:
    def test_set_data_type_is_visible_in_list_labels(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = _find_block(daemon, ".data", binary)["start"]

        result = rpc(sock, "set_data_type", {
            "binary": binary, "address": addr, "data_type": "int",
        })["result"]

        assert (result["address"], result["data_type"], result["length"]) == (addr, "int", 4)
        labels = _labels(daemon, binary, addr)
        assert labels, "expected the .data start label"
        assert all(l["data_type"] == "int" and l["data_length"] == 4 for l in labels), labels

    def test_apply_data_type_range_then_clear(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        bss = _find_block(daemon, ".bss", binary)
        if bss["size"] < 16:
            pytest.skip(f".bss too small for a 16-byte range: {bss}")
        start, end = bss["start"], _offset(bss["start"], 15)

        applied = rpc(sock, "apply_data_type_range", {
            "binary": binary, "start": start, "end": end,
            "data_type": "int", "clear": True,
        })["result"]
        assert (applied["type_size"], applied["applied_count"]) == (4, 4)
        labels = _labels(daemon, binary, start, end)
        assert labels and all(l["data_type"] == "int" for l in labels), labels

        cleared = rpc(sock, "clear_data_range",
                      {"binary": binary, "start": start, "end": end})["result"]
        assert cleared["cleared"] is True
        labels = _labels(daemon, binary, start, end)
        assert labels and all(l["data_type"] == "undefined" for l in labels), labels

    def test_list_labels_range_reports_function_symbols(self, daemon, scratch):
        addr = scratch["funcs"]["sum_array"]
        labels = _labels(daemon, scratch["name"], addr, _offset(addr, 0x10))
        entry = next((l for l in labels if l["name"] == "sum_array"), None)
        assert entry is not None, labels
        assert entry["address"] == addr and entry["type"] == "Function"


# ── equates ───────────────────────────────────────────────────────────────────

class TestEquates:
    """Equates attach to an instruction operand; main's ``i <= 6`` loop bound
    is `CMP [mem],0x6`.  No decompile is needed to find it.

    Matched on the instruction's bytes (imm8 is the last one): once an equate
    is applied the operand text reads as the equate's name, not ``0x6``."""

    @staticmethod
    def _loop_bound(daemon, scratch) -> str:
        insn = next((i for i in _insns(daemon, scratch["name"], scratch["funcs"]["main"], 40)
                     if i["mnemonic"] == "CMP" and i["bytes"].endswith("06")), None)
        assert insn, "no `CMP mem,0x6` in main"
        return insn["address"]

    def test_set_equate_shows_in_listing_and_list_equates(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = self._loop_bound(daemon, scratch)
        name = f"GRPC_LOOP_MAX_{uuid.uuid4().hex[:6]}"

        result = rpc(sock, "set_equate", {
            "binary": binary, "address": addr, "equate_name": name,
            "value": 6, "operand_index": 1,
        })["result"]

        assert result["verified"] is True and result["enum_linked"] is False
        at_addr = rpc(sock, "list_equates", {"binary": binary, "address": addr})["result"]
        assert [(e["name"], e["value"], e["operand_index"]) for e in at_addr["equates"]] == [
            (name, 6, 1)]
        everywhere = rpc(sock, "list_equates", {"binary": binary})["result"]["equates"]
        assert {"name": name, "value": 6} in everywhere
        listing = rpc(sock, "disassemble",
                      {"binary": binary, "address": addr, "count": 1})["result"]["listing"]
        assert name in listing, listing

    def test_set_equate_links_to_enum_entry(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = self._loop_bound(daemon, scratch)
        uid = uuid.uuid4().hex[:6]
        enum, entry = f"EqEnum_{uid}", f"EQ_SIX_{uid}"
        rpc(sock, "create_enum", {
            "binary": binary, "name": enum, "values": [{"name": entry, "value": 6}],
        })

        result = rpc(sock, "set_equate", {
            "binary": binary, "address": addr, "equate_name": entry,
            "enum_path": enum, "value": 6, "operand_index": 1,
        })["result"]

        assert result["enum_linked"] is True and result["verified"] is True
        at_addr = rpc(sock, "list_equates", {"binary": binary, "address": addr})["result"]
        assert [e["name"] for e in at_addr["equates"]] == [entry]

    def test_set_equate_rejects_name_missing_from_enum(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        uid = uuid.uuid4().hex[:6]
        enum = f"EqEnumStrict_{uid}"
        rpc(sock, "create_enum", {
            "binary": binary, "name": enum, "values": [{"name": f"ONLY_{uid}", "value": 6}],
        })
        exc = rpc_error(sock, "set_equate", {
            "binary": binary, "address": self._loop_bound(daemon, scratch),
            "equate_name": "NOT_IN_ENUM", "enum_path": enum, "value": 6,
        })
        assert "NOT_IN_ENUM" in str(exc)


# ── symbols and batch edits ───────────────────────────────────────────────────

class TestSymbolsAndBatchEdits:
    def test_rename_symbol_and_restore(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = _find_block(daemon, ".data", binary)["start"]
        new_name = f"grpc_renamed_{uuid.uuid4().hex[:6]}"

        result = rpc(sock, "rename_symbol", {
            "binary": binary, "address": addr, "new_name": new_name,
        })["result"]
        old_name = result["old_name"]
        try:
            assert result["new_name"] == new_name and result["verified"] is True
            assert result["created"] is False
            assert new_name in [l["name"] for l in _labels(daemon, binary, addr)]
        finally:
            rpc(sock, "rename_symbol", {"binary": binary, "address": addr, "new_name": old_name})
        assert old_name in [l["name"] for l in _labels(daemon, binary, addr)]

    def test_rename_symbol_create_adds_label_at_unlabelled_address(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        addr = _unlabelled_addresses(daemon, binary, 1)[0]
        name = f"grpc_created_{uuid.uuid4().hex[:6]}"

        result = rpc(sock, "rename_symbol", {
            "binary": binary, "address": addr, "new_name": name, "create": True,
        })["result"]

        assert result["created"] is True and result["verified"] is True
        assert name in [l["name"] for l in _labels(daemon, binary, addr)]

    def test_batch_rename_applies_good_items_and_reports_the_bad_one(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        uid = uuid.uuid4().hex[:6]
        renames = {"greet_formal": f"gf_{uid}", "stack_pop": f"sp_{uid}"}
        ops = [{"target": old, "new_name": new} for old, new in renames.items()]
        ops.insert(1, {"target": f"no_such_function_{uid}", "new_name": "x"})

        result = rpc(sock, "batch_rename", {"binary": binary, "operations": ops})["result"]

        assert (result["count"], result["ok_count"], result["error_count"]) == (3, 2, 1)
        assert [r["ok"] for r in result["results"]] == [True, False, True]
        assert [r["index"] for r in result["results"]] == [0, 1, 2]
        assert result["results"][0]["old_name"] == "greet_formal"
        assert "error" in result["results"][1]
        # The failure did not roll back its neighbours.
        for new in renames.values():
            assert _function_entry(daemon, binary, new) is not None, new

    def test_batch_rename_label_mode_creates_labels(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        uid = uuid.uuid4().hex[:6]
        addrs = _unlabelled_addresses(daemon, binary, 2)
        names = [f"grpc_batch_{uid}_{i}" for i in range(2)]

        result = rpc(sock, "batch_rename", {
            "binary": binary, "mode": "label",
            "operations": [{"address": a, "new_name": n, "create": True}
                           for a, n in zip(addrs, names)],
        })["result"]

        assert (result["ok_count"], result["error_count"]) == (2, 0)
        for addr, name in zip(addrs, names):
            assert name in [l["name"] for l in _labels(daemon, binary, addr)]

    def test_batch_set_comment_applies_good_items_and_reports_the_bad_one(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        insns = _insns(daemon, binary, scratch["funcs"]["count_char"], 4)
        first, second, third = insns[0]["address"], insns[1]["address"], insns[2]["address"]
        uid = uuid.uuid4().hex[:6]

        result = rpc(sock, "batch_set_comment", {"binary": binary, "operations": [
            {"address": first, "comment": f"first-{uid}"},
            {"address": second, "comment": "x", "comment_type": "bogus"},
            {"address": third, "comment": f"third-{uid}", "comment_type": "eol"},
        ]})["result"]

        try:
            assert (result["count"], result["ok_count"], result["error_count"]) == (3, 2, 1)
            assert [r["ok"] for r in result["results"]] == [True, False, True]
            assert result["results"][0]["comment_type"] == "eol"   # default
            listing = rpc(sock, "disassemble", {
                "binary": binary, "address": first, "count": 3,
            })["result"]["listing"]
            assert f"first-{uid}" in listing and f"third-{uid}" in listing, listing
        finally:
            rpc(sock, "batch_set_comment", {"binary": binary, "operations": [
                {"address": first, "comment": ""}, {"address": third, "comment": ""},
            ]})


# ── type edits ────────────────────────────────────────────────────────────────

class TestTypeEdits:
    def test_create_union_overlays_all_members_at_offset_zero(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        name = f"GrpcUnion_{uuid.uuid4().hex[:6]}"

        result = rpc(sock, "create_union", {"binary": binary, "name": name, "fields": [
            {"type": "int", "name": "as_int"},
            {"type": "char[8]", "name": "as_bytes"},
        ]})["result"]

        assert result["name"] == name and result["already_existed"] is False
        assert result["size"] == 8                       # the largest member
        assert [(f["name"], f["offset"], f["length"]) for f in result["fields"]] == [
            ("as_int", 0, 4), ("as_bytes", 0, 8)]
        listed = rpc(sock, "list_data_types", {
            "binary": binary, "category": "union", "query": name,
        })["result"]
        assert [d["name"] for d in listed["data_types"]] == [name]

    def test_modify_struct_edits_a_field_by_name_and_by_offset(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        name = f"GrpcStruct_{uuid.uuid4().hex[:6]}"
        rpc(sock, "create_struct", {"binary": binary, "name": name, "fields": [
            {"type": "int", "name": "a"}, {"type": "int", "name": "b"},
            {"type": "int", "name": "c"},
        ]})

        by_name = rpc(sock, "modify_struct", {
            "binary": binary, "struct_name": name, "field_name": "b",
            "new_name": "b_renamed", "new_type": "short", "new_comment": "narrowed",
        })["result"]
        modified = by_name["modified_field"]
        assert (modified["offset"], modified["old_name"], modified["new_name"]) == (
            4, "b", "b_renamed")
        fields = {f["offset"]: f for f in by_name["fields"]}
        assert (fields[4]["name"], fields[4]["data_type"], fields[4]["length"]) == (
            "b_renamed", "short", 2)
        assert fields[4]["comment"] == "narrowed"
        # Shrinking b must not shift the field after it.
        assert (fields[8]["name"], fields[8]["data_type"]) == ("c", "int")

        by_offset = rpc(sock, "modify_struct", {
            "binary": binary, "struct_name": name, "field_offset": 0, "new_name": "a_renamed",
        })["result"]
        assert by_offset["modified_field"]["offset"] == 0
        assert {f["offset"]: f["name"] for f in by_offset["fields"]}[0] == "a_renamed"

    def test_modify_struct_rejects_unknown_field(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        name = f"GrpcStructErr_{uuid.uuid4().hex[:6]}"
        rpc(sock, "create_struct", {"binary": binary, "name": name,
                                    "fields": [{"type": "int", "name": "only"}]})
        exc = rpc_error(sock, "modify_struct", {
            "binary": binary, "struct_name": name, "field_name": "missing", "new_name": "x",
        })
        assert "missing" in str(exc)

    def test_modify_enum_adds_and_removes_entries(self, daemon, scratch):
        sock, binary = daemon["sock"], scratch["name"]
        name = f"GrpcEnum_{uuid.uuid4().hex[:6]}"
        rpc(sock, "create_enum", {"binary": binary, "name": name, "values": [
            {"name": "A", "value": 1}, {"name": "B", "value": 2},
        ]})

        result = rpc(sock, "modify_enum", {
            "binary": binary, "name": name,
            "add": [{"name": "C", "value": 3}], "remove": ["A"],
        })["result"]

        assert {v["name"]: v["value"] for v in result["values"]} == {"B": 2, "C": 3}

    def test_modify_enum_rejects_unknown_enum(self, daemon, scratch):
        rpc_error(daemon["sock"], "modify_enum", {
            "binary": scratch["name"], "name": f"NoSuchEnum_{uuid.uuid4().hex[:6]}",
            "add": [{"name": "X", "value": 1}],
        })


# ── processor context ─────────────────────────────────────────────────────────

class TestProcessorContext:
    def test_get_reports_x86_64_long_mode(self, daemon):
        result = rpc(daemon["sock"], "get_processor_context", {
            "binary": daemon["short_name"], "address": daemon["main_addr"],
        })["result"]
        assert result["address"] == daemon["main_addr"]
        assert result["registers"]["longMode"] == 1
        assert result["registers"]["bit64"] == 1

    def test_get_with_register_filter_returns_only_that_register(self, daemon):
        result = rpc(daemon["sock"], "get_processor_context", {
            "binary": daemon["short_name"], "address": daemon["main_addr"],
            "register": "bit64",
        })["result"]
        assert result["registers"] == {"bit64": 1}

    def test_get_rejects_unknown_register(self, daemon):
        rpc_error(daemon["sock"], "get_processor_context", {
            "binary": daemon["short_name"], "address": daemon["main_addr"],
            "register": "NoSuchRegister",
        })

    def test_set_applies_over_the_inclusive_range_only(self, daemon, scratch):
        """DF (the x86 direction-flag context bit) set on [a, a+3] is visible at both
        ends of the range and absent just past it."""
        sock, binary = daemon["sock"], scratch["name"]
        start = scratch["funcs"]["count_char"]
        end = _offset(start, 3)

        def df_at(addr):
            return rpc(sock, "get_processor_context", {
                "binary": binary, "address": addr, "register": "DF",
            })["result"]["registers"]["DF"]

        try:
            result = rpc(sock, "set_processor_context", {
                "binary": binary, "address": start, "end": end,
                "register": "DF", "value": 1,
            })["result"]
            assert result["verified"] is True and result["value"] == 1
            assert (df_at(start), df_at(end), df_at(_offset(end, 1))) == (1, 1, 0)
        finally:
            rpc(sock, "set_processor_context", {
                "binary": binary, "address": start, "end": end,
                "register": "DF", "value": 0,
            })
        assert (df_at(start), df_at(end)) == (0, 0)

    def test_set_rejects_unknown_register(self, daemon, scratch):
        rpc_error(daemon["sock"], "set_processor_context", {
            "binary": scratch["name"], "address": scratch["funcs"]["count_char"],
            "register": "NoSuchRegister", "value": 1,
        })


# ── decompile_all ─────────────────────────────────────────────────────────────

class TestDecompileAll:
    def test_pages_through_functions(self, daemon):
        sock, binary = daemon["sock"], daemon["short_name"]
        listed = rpc(sock, "functions", {"binary": binary})["result"]["functions"]

        first = rpc(sock, "decompile_all", {"binary": binary, "limit": 3},
                    timeout=_LOAD_TIMEOUT)["result"]
        second = rpc(sock, "decompile_all", {"binary": binary, "limit": 3, "offset": 3},
                     timeout=_LOAD_TIMEOUT)["result"]

        # `functions` and `decompile_all` skip the same externals/thunks.
        assert first["total"] == second["total"] == len(listed)
        assert (first["count"], first["offset"]) == (3, 0)
        assert (second["count"], second["offset"]) == (3, 3)
        assert first["errors"] == second["errors"] == 0
        # Pages follow function order and don't overlap.
        assert [f["address"] for f in first["functions"] + second["functions"]] == [
            f["address"] for f in listed[:6]]
        for fn in first["functions"] + second["functions"]:
            assert fn["c_code"].strip(), fn

    def test_offset_past_the_end_returns_an_empty_page(self, daemon):
        result = rpc(daemon["sock"], "decompile_all", {
            "binary": daemon["short_name"], "offset": 10_000,
        })["result"]
        assert (result["count"], result["functions"], result["errors"]) == (0, [], 0)


# ── function_diff / match_function ────────────────────────────────────────────

class TestDiffAndMatch:
    """Two identical copies of testapp, one optionally patched with ``assemble``."""

    @staticmethod
    def _diff(daemon, pair, mode):
        a, b = pair
        return rpc(daemon["sock"], "function_diff", {
            "binary1": a["name"], "func1": "sum_array",
            "binary2": b["name"], "func2": "sum_array", "mode": mode,
        }, timeout=_LOAD_TIMEOUT)["result"]

    @staticmethod
    def _match(daemon, pair, **extra):
        a, b = pair
        return rpc(daemon["sock"], "match_function", {
            "source_binary": a["name"], "func": "sum_array",
            "target_binary": b["name"], **extra,
        }, timeout=_LOAD_TIMEOUT)["result"]

    @pytest.mark.parametrize("mode", ["decompile", "disassembly"])
    def test_identical_copies_diff_clean(self, daemon, diff_pair, mode):
        result = self._diff(daemon, diff_pair, mode)
        assert result["mode"] == mode
        assert result["is_identical"] is True, result["diff"]
        assert result["func1_address"] == result["func2_address"]

    def test_patched_constant_shows_up_in_both_modes_and_restoring_clears_it(
            self, daemon, diff_pair):
        sock, (_, b) = daemon["sock"], diff_pair
        insn = next(i for i in _insns(daemon, b["name"], b["funcs"]["sum_array"], 12)
                    if i["mnemonic"] == "MOV" and i["operands"].endswith(",0x0")
                    and i["length"] >= 4)

        try:
            rpc(sock, "assemble", {
                "binary": b["name"], "address": insn["address"],
                "instructions": [f"MOV {insn['operands'][:-3]}0x5"],
            })
            dis = self._diff(daemon, diff_pair, "disassembly")
            dec = self._diff(daemon, diff_pair, "decompile")
            assert dis["is_identical"] is False and dec["is_identical"] is False
            assert any(l.startswith("+") and "0x5" in l for l in dis["diff"].splitlines()), dis["diff"]
            assert any(l.startswith("+") and "5" in l for l in dec["diff"].splitlines()), dec["diff"]
        finally:
            rpc(sock, "assemble", {
                "binary": b["name"], "address": insn["address"],
                "instructions": [_insn_text(insn)],
            })
        # The decompiler cache must follow the restore, not just the patch.
        assert self._diff(daemon, diff_pair, "decompile")["is_identical"] is True
        assert self._diff(daemon, diff_pair, "disassembly")["is_identical"] is True

    def test_match_function_finds_the_same_function_in_the_other_copy(self, daemon, diff_pair):
        result = self._match(daemon, diff_pair)

        assert result["source"]["name"] == "sum_array"
        assert result["count"] == len(result["candidates"]) > 0
        best = result["candidates"][0]
        assert best["address"] == diff_pair[1]["funcs"]["sum_array"]
        assert best["similarity"] == pytest.approx(1.0)
        # Candidates are ranked best-first.
        sims = [c["similarity"] for c in result["candidates"]]
        assert sims == sorted(sims, reverse=True)

    def test_match_function_threshold_filters_candidates(self, daemon, diff_pair):
        result = self._match(daemon, diff_pair, threshold=0.99)
        assert result["candidates"]
        assert all(c["similarity"] >= 0.99 for c in result["candidates"])

    def test_both_binaries_still_work_after_match_function(self, daemon, diff_pair):
        """match_function closes and reopens both programs internally; afterwards
        reads and a write against each (an abort-wedged handle swallows writes)
        must still work."""
        sock = daemon["sock"]
        self._match(daemon, diff_pair)

        for copy in diff_pair:
            assert rpc(sock, "functions", {"binary": copy["name"]})["result"]["functions"]
            enum = f"PostMatchEnum_{uuid.uuid4().hex[:8]}"
            rpc(sock, "create_enum", {
                "binary": copy["name"], "name": enum, "values": [{"name": "X", "value": 1}],
            })
            found = rpc(sock, "list_data_types", {
                "binary": copy["name"], "category": "enum", "query": enum,
            })["result"]
            assert found["count"] == 1, f"write after match_function lost on {copy['name']}"


# ── goto (GUI-only) ───────────────────────────────────────────────────────────

class TestGotoHeadless:
    """The success path needs a GUI session; headless must say so clearly."""

    def test_goto_explains_it_needs_gui_mode(self, daemon):
        exc = rpc_error(daemon["sock"], "goto", {
            "binary": daemon["short_name"], "target": daemon["main_name"],
        })
        assert "GUI mode" in str(exc)
