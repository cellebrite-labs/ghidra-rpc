"""CLI entry point for ghidra-rpc.

All commands output valid JSON to stdout. Human-readable messages go to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from ghidra_rpc import __version__


class HexInt(click.ParamType):
    """Click parameter type that accepts both decimal and 0x-prefixed hex integers."""

    name = "integer"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        try:
            return int(value, 0)  # handles 0x prefix, 0o, 0b, and plain decimal
        except (ValueError, TypeError):
            self.fail(
                f"{value!r} is not a valid integer "
                f"(use decimal like 184 or hex like 0xb8)",
                param,
                ctx,
            )


HEX_INT = HexInt()
from ghidra_rpc import session as session_mod
from ghidra_rpc.client import DaemonError, DaemonNotRunning

# Directory scanned by _discover_instances() for orphaned sockets not in the
# registry. Sockets always live in /tmp (see session.socket_path_for_project),
# so this is a plain module attribute purely so tests can monkeypatch it to a
# tmp_path -- without that, a test-invoked `stop --all` would glob-match and
# stop *real* daemons running on the developer's machine.
_SOCKET_SCAN_DIR = Path("/tmp")


def _resolve_project(project: str | None) -> Path:
    """Resolve the project .gpr path from flag, env var, or error."""
    if project:
        return Path(project).resolve()
    env = os.environ.get("GHIDRA_RPC_PROJECT")
    if env:
        return Path(env).resolve()
    click.echo(
        "Error: No project specified. Use --project or set GHIDRA_RPC_PROJECT.",
        err=True,
    )
    sys.exit(1)


def _json_output(data: dict) -> None:
    """Print JSON to stdout and exit 0."""
    click.echo(json.dumps(data, indent=2))


def _json_error(error: str, message: str) -> None:
    """Print JSON error to stdout and exit 1."""
    click.echo(json.dumps({"ok": False, "error": error, "message": message}))
    sys.exit(1)


def _discover_instances(include_dead: bool = False) -> list[dict]:
    """Discover all ghidra-rpc daemon instances via registry + socket-dir glob.

    Merges entries from the global session registry with any
    ``ghidra-rpc-*.sock`` files under ``_SOCKET_SCAN_DIR`` not already in the
    registry (catches pre-registry installs and manually started daemons).
    Each candidate is probed with a short-timeout ping so liveness is always
    authoritative.

    When *include_dead* is False (default) only live instances are returned.
    Registry entries whose socket file has disappeared are pruned automatically.
    """
    from ghidra_rpc.client import send_request

    def _probe(socket_path: Path) -> dict | None:
        """Ping socket; return the result dict or None if not responsive."""
        try:
            resp = send_request(socket_path, "ping", {}, socket_timeout=5.0)
            if resp.get("ok"):
                return resp.get("result", {})
        except Exception:
            pass
        return None

    # Registry entries take precedence (they carry ghidra_install_dir etc.);
    # the socket-dir glob catches anything not registered.
    candidates: dict[str, dict] = {}  # str(socket_path) -> {socket, session}
    for sess in session_mod.load_all():
        key = str(sess.socket_path)
        candidates[key] = {"socket": sess.socket_path, "session": sess}
    for sock_path in sorted(_SOCKET_SCAN_DIR.glob("ghidra-rpc-*.sock")):
        key = str(sock_path)
        if key not in candidates:
            candidates[key] = {"socket": sock_path, "session": None}

    results: list[dict] = []
    stale: list[Path] = []

    for info in candidates.values():
        sock = info["socket"]
        sess = info["session"]
        ping_meta = _probe(sock)
        alive = ping_meta is not None

        if not alive:
            # Socket file gone entirely: stale registry entry, prune it.
            if not sock.exists() and sess:
                stale.append(sess.project_gpr)
            if not include_dead:
                continue

        entry: dict = {"running": alive, "socket": str(sock)}
        if alive and ping_meta:
            # Live daemon is the authoritative source.
            entry["project"] = ping_meta.get("project_gpr")
            entry["mode"]    = ping_meta.get("mode")
            entry["pid"]     = ping_meta.get("pid")
        elif sess:
            # Dead instance, but we have registry metadata.
            entry["project"] = str(sess.project_gpr)
            entry["mode"]    = sess.mode
            entry["pid"]     = None
        else:
            # Dead instance with no registry entry (glob-only).
            entry["project"] = None
            entry["mode"]    = None
            entry["pid"]     = None
        results.append(entry)

    for gpr in stale:
        session_mod.unregister(gpr)

    return results


@click.group()
@click.version_option(__version__, prog_name="ghidra-rpc")
def cli():
    """ghidra-rpc: CLI for the Ghidra RPC daemon."""
    pass


@cli.command()
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
@click.option("--headless", is_flag=True, help="Start in headless mode (no GUI)")
@click.option("--detach", is_flag=True, help="Start in background (non-blocking); prints JSON when ready.")
@click.option(
    "--timeout", "-t", type=float, default=None,
    help="With --detach: seconds to wait for daemon to become responsive "
         "(default: 60 s headless, 180 s GUI).",
)
@click.option(
    "--ghidra-install-dir", "ghidra_install_dir", type=str, default=None,
    help="Override GHIDRA_INSTALL_DIR (persisted in session so restarts work "
         "in environments that strip env vars).",
)
def start(project: str | None, headless: bool, detach: bool, timeout: float | None,
          ghidra_install_dir: str | None):
    """Start the ghidra-rpc daemon.

    By default starts in the foreground (blocking, shows logs). Use --detach
    to launch in the background and return once the socket is responsive.
    """
    from ghidra_rpc.daemon import start_background, start_blocking

    gpr = _resolve_project(project)
    mode = "headless" if headless else "gui"
    sock = session_mod.socket_path_for_project(gpr)

    # Resolve GHIDRA_INSTALL_DIR: CLI flag > env var
    ghidra_dir_path = None
    if ghidra_install_dir:
        ghidra_dir_path = Path(ghidra_install_dir)
    elif os.environ.get("GHIDRA_INSTALL_DIR"):
        ghidra_dir_path = Path(os.environ["GHIDRA_INSTALL_DIR"])

    session = session_mod.Session(
        mode=mode, project_gpr=gpr, socket_path=sock,
        ghidra_install_dir=ghidra_dir_path,
    )

    if detach:
        effective_timeout = timeout if timeout is not None else (180.0 if mode == "gui" else 60.0)
        try:
            start_background(session, timeout=effective_timeout)
            _json_output({"ok": True, "result": {"status": "started", "mode": mode, "socket": str(sock)}})
        except TimeoutError as e:
            if mode == "gui" and sock.exists():
                _json_output({
                    "ok": True,
                    "result": {
                        "status": "started",
                        "mode": mode,
                        "socket": str(sock),
                        "warning": (
                            f"Daemon started but did not become fully responsive within "
                            f"{effective_timeout:.0f} s (GUI startup is slow). "
                            "Retry commands in a few seconds."
                        ),
                    },
                })
            else:
                _json_error("StartTimeout", str(e))
    else:
        # Blocking foreground start — set GHIDRA_INSTALL_DIR in current process if given
        if ghidra_dir_path:
            os.environ["GHIDRA_INSTALL_DIR"] = str(ghidra_dir_path)
        click.echo(f"Starting ghidra-rpc daemon ({mode} mode)...", err=True)
        click.echo(f"  Project: {gpr}", err=True)
        click.echo(f"  Socket:  {sock}", err=True)
        start_blocking(session)


@cli.command()
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
@click.option("--headless", is_flag=True, default=None,
              help="Force headless mode for the restarted daemon.")
@click.option(
    "--timeout", "-t", type=float, default=None,
    help="Seconds to wait for daemon to become responsive "
         "(default: 60 s headless, 180 s GUI).",
)
@click.option(
    "--ghidra-install-dir", "ghidra_install_dir", type=str, default=None,
    help="Override GHIDRA_INSTALL_DIR (falls back to saved session value or env var).",
)
def restart(project: str | None, headless: bool | None, timeout: float | None,
            ghidra_install_dir: str | None):
    """Restart the daemon in the background."""
    from ghidra_rpc.daemon import start_background, stop_daemon

    gpr = _resolve_project(project)
    sock = session_mod.socket_path_for_project(gpr)

    # Stop existing daemon if running
    stop_daemon(sock)

    session = session_mod.load(gpr)
    if session is None:
        if headless:
            # No prior session — create one from scratch.
            session = session_mod.Session(
                mode="headless", project_gpr=gpr, socket_path=sock,
            )
        else:
            _json_error(
                "NoSession",
                f"No saved session for {gpr}. "
                "Use 'ghidra-rpc start --project <path>' first, or pass "
                "'--headless' to create a new headless session.",
            )

    # Allow --headless to override the saved mode.
    if headless:
        session = session_mod.Session(
            mode="headless", project_gpr=session.project_gpr,
            socket_path=session.socket_path,
            ghidra_install_dir=session.ghidra_install_dir,
        )

    # Resolve GHIDRA_INSTALL_DIR: CLI flag > saved session > current env
    if ghidra_install_dir:
        session.ghidra_install_dir = Path(ghidra_install_dir)
    elif not session.ghidra_install_dir and os.environ.get("GHIDRA_INSTALL_DIR"):
        session.ghidra_install_dir = Path(os.environ["GHIDRA_INSTALL_DIR"])

    # GUI mode (JVM + Ghidra + project open) takes significantly longer than headless.
    effective_timeout = timeout if timeout is not None else (180.0 if session.mode == "gui" else 60.0)

    try:
        start_background(session, timeout=effective_timeout)
        _json_output({"ok": True, "result": {"status": "restarted", "socket": str(sock)}})
    except TimeoutError as e:
        # For GUI mode the socket is created once the server starts listening, but
        # Ghidra's own startup (project load, analysis catch-up) can push responsiveness
        # beyond even a generous timeout.  If the socket file already exists the server
        # IS up; treat as a non-fatal warning so callers aren't misled.
        if session.mode == "gui" and sock.exists():
            _json_output({
                "ok": True,
                "result": {
                    "status": "started",
                    "socket": str(sock),
                    "warning": (
                        f"Daemon started but did not become fully responsive within "
                        f"{effective_timeout:.0f} s (GUI startup is slow). "
                        "Retry commands in a few seconds."
                    ),
                },
            })
        else:
            _json_error("RestartTimeout", str(e))


@cli.command()
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def status(project: str | None):
    """Check daemon status."""
    from ghidra_rpc.daemon import is_running

    gpr = _resolve_project(project)
    sock = session_mod.socket_path_for_project(gpr)
    running = is_running(sock)
    session = session_mod.load(gpr)

    # mode_source clarifies whether the reported mode reflects a currently running
    # daemon ('running') or just what was saved when 'start' was last invoked
    # ('session').  When the daemon is stopped, mode still shows the saved value so
    # 'restart' can use it — but mode_source tells callers not to infer liveness.
    if session:
        mode_source = "running" if running else "session"
    else:
        mode_source = None

    # When the daemon is live, fetch the list of loaded binaries in one extra
    # round-trip so callers get a full health snapshot without needing a second
    # list-binaries call.
    binaries = None
    if running:
        try:
            from ghidra_rpc.client import send_request
            resp = send_request(sock, "list_binaries", {})
            if resp.get("ok"):
                binaries = resp["result"].get("binaries", [])
        except Exception:
            pass  # Don't let a list_binaries failure break the status command

    _json_output({
        "ok": True,
        "result": {
            "running":     running,
            "socket":      str(sock),
            "mode":        session.mode if session else None,
            "mode_source": mode_source,
            "project":     str(gpr),
            "binaries":    binaries,  # list when running, null when stopped
        },
    })


@cli.command()
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
@click.option("--all", "stop_all", is_flag=True, default=False,
              help="Stop all running instances (mutually exclusive with --project).")
def stop(project: str | None, stop_all: bool):
    """Stop the daemon."""
    from ghidra_rpc.daemon import stop_daemon

    if stop_all and project:
        _json_error("InvalidArgs", "--all and --project are mutually exclusive.")

    if stop_all:
        instances = _discover_instances(include_dead=False)
        if not instances:
            _json_output({"ok": True, "result": {"stopped": [], "count": 0}})
            return
        stopped: list[str] = []
        failed: list[str] = []
        for inst in instances:
            label = inst.get("project") or inst["socket"]
            if stop_daemon(Path(inst["socket"])):
                stopped.append(label)
            else:
                failed.append(label)
        _json_output({"ok": True, "result": {
            "stopped": stopped, "failed": failed, "count": len(stopped),
        }})
        return

    gpr = _resolve_project(project)
    sock = session_mod.socket_path_for_project(gpr)

    if stop_daemon(sock):
        _json_output({"ok": True, "result": {"status": "stopped"}})
    else:
        _json_error("NotRunning", "Daemon is not running.")


@cli.command(name="list-instances")
@click.option("--all", "include_dead", is_flag=True, default=False,
              help="Also show registered instances that are not currently running.")
def list_instances(include_dead: bool):
    """List all known ghidra-rpc daemon instances.

    Discovers instances from the global session registry and from any
    /tmp/ghidra-rpc-*.sock files not already in the registry.  Each entry
    is probed for liveness; stale registry entries (socket file gone) are
    pruned automatically.

    Use the reported project path with --project (or GHIDRA_RPC_PROJECT) to
    attach to an existing session:

    \b
      export GHIDRA_RPC_PROJECT=/path/to/project.gpr
      ghidra-rpc list-binaries
    """
    instances = _discover_instances(include_dead=include_dead)
    _json_output({
        "ok": True,
        "result": {"instances": instances, "count": len(instances)},
    })


# ─── Generic command passthrough ───────────────────────────────────────────────
# All other commands are dispatched to the daemon via the RPC protocol.

@cli.command(name="load")
@click.argument("path")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
@click.option("--no-analyze", "no_analyze", is_flag=True, default=False,
              help="Skip auto-analysis after import. Useful for large binaries when "
                   "you only need the raw listing or plan to analyse later.")
@click.option("--analysis-timeout", "analysis_timeout", type=int, default=None,
              metavar="SECS",
              help="Abort auto-analysis after SECS seconds (best-effort). "
                   "The binary is still saved with partial analysis results.")
def load_binary(path: str, project: str | None, no_analyze: bool,
                analysis_timeout: int | None):
    """Load a binary into the Ghidra project."""
    args: dict = {"path": os.path.abspath(path)}
    if no_analyze:
        args["analyze"] = False
    if analysis_timeout is not None:
        args["analysis_timeout"] = analysis_timeout
    _rpc_command(_resolve_project(project), "load", args)


@cli.command(name="functions")
@click.argument("binary")
@click.option("--limit", "-l", type=int, default=None, help="Max results (default: all)")
@click.option("--offset", "-o", type=int, default=0, show_default=True, help="Offset for pagination")
@click.option("--address-min", "address_min", default="",
              help="Only return functions at or above this address (hex).")
@click.option("--address-max", "address_max", default="",
              help="Only return functions at or below this address (hex).")
@click.option("--with-body", "with_body", is_flag=True, default=False,
              help="Include body_min, body_max, body_size for each function.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_functions(binary: str, limit: int | None, offset: int,
                   address_min: str, address_max: str, with_body: bool,
                   project: str | None):
    """List functions in a binary.

    Use --address-min/--address-max for server-side range filtering (much
    faster than fetching all functions and filtering in Python for large
    binaries).  Use --with-body to include body address ranges.
    """
    args: dict = {"binary": binary, "offset": offset}
    if limit is not None:
        args["limit"] = limit
    if address_min:
        args["address_min"] = address_min
    if address_max:
        args["address_max"] = address_max
    if with_body:
        args["with_body"] = True
    _rpc_command(_resolve_project(project), "functions", args)


@cli.command(name="imports")
@click.argument("binary")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_imports(binary: str, project: str | None):
    """List imported symbols."""
    _rpc_command(_resolve_project(project), "imports", {"binary": binary})


@cli.command(name="exports")
@click.argument("binary")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_exports(binary: str, project: str | None):
    """List exported symbols."""
    _rpc_command(_resolve_project(project), "exports", {"binary": binary})


@cli.command(name="metadata")
@click.argument("binary")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def binary_metadata(binary: str, project: str | None):
    """Get binary metadata (arch, format, etc.)."""
    _rpc_command(_resolve_project(project), "metadata", {"binary": binary})


@cli.command(name="decompile")
@click.argument("binary")
@click.argument("func")
@click.option("--timeout", "-t", type=int, default=120, show_default=True,
              help="Decompiler timeout in seconds (120 s default; increase for large firmware functions).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def decompile(binary: str, func: str, timeout: int, project: str | None):
    """Decompile a function to pseudo-C.

    If decompile returns bad-instruction warnings, try `pcode --high` as a
    fallback: the P-code engine re-decodes bytes from the function object's
    context and often succeeds where the listing-level decompiler fails
    (e.g. for ARM Thumb regions that auto-analysis mis-classified).
    """
    _rpc_command(_resolve_project(project), "decompile", {
        "binary": binary, "func": func, "timeout": timeout,
    })


@cli.command(name="find-bytes")
@click.argument("binary")
@click.argument("pattern")
@click.option("--limit", "-l", type=int, default=100, help="Max results (default 100)")
@click.option("--address", "-a", type=str, default="",
              help="Start address for search (default: beginning of program)")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def find_bytes(binary: str, pattern: str, limit: int, address: str,
              project: str | None):
    """Search for a byte pattern in program memory.

    PATTERN is a space-separated hex string with optional wildcards:
      "55 8b ?? 83 ec"  — ?? for wildcard bytes
      "90 90 90 EB ."   — . also works as wildcard
      "558b??83ec"      — no-space form auto-splits into byte pairs

    Use for finding magic headers, crypto constants, instruction patterns,
    shellcode gadgets, or known signatures.
    """
    args: dict = {"binary": binary, "pattern": pattern, "limit": limit}
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "find_bytes", args)


@cli.command(name="strings")
@click.argument("binary")
@click.argument("query", default="")
@click.option("--limit", "-l", type=int, default=100, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def search_strings(binary: str, query: str, limit: int, project: str | None):
    """Search for strings in a binary (empty query lists all)."""
    _rpc_command(_resolve_project(project), "strings", {
        "binary": binary, "query": query, "limit": limit,
    })


@cli.command(name="symbols")
@click.argument("binary")
@click.argument("query")
@click.option("--limit", "-l", type=int, default=25, help="Max results")
@click.option("--offset", "-o", type=int, default=0, help="Offset for pagination")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def search_symbols(binary: str, query: str, limit: int, offset: int, project: str | None):
    """Search for symbols in a binary."""
    _rpc_command(_resolve_project(project), "symbols", {
        "binary": binary, "query": query, "limit": limit, "offset": offset,
    })


@cli.command(name="xrefs-to")
@click.argument("binary")
@click.argument("target")
@click.option("--limit", "-l", type=int, default=50, help="Max results")
@click.option("--all-binaries", "all_binaries", is_flag=True, default=False,
              help="Also search every other loaded binary for a same-named symbol "
                   "(e.g. a method defined here but called from a different dex) "
                   "and merge in real callers found there. Each result then "
                   "carries a 'binary' field.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def xrefs_to(binary: str, target: str, limit: int, all_binaries: bool, project: str | None):
    """Find cross-references TO a target."""
    _rpc_command(_resolve_project(project), "xrefs_to", {
        "binary": binary, "target": target, "limit": limit, "all_binaries": all_binaries,
    })


@cli.command(name="xrefs-from")
@click.argument("binary")
@click.argument("target")
@click.option("--limit", "-l", type=int, default=50, help="Max results")
@click.option("--no-stack", "no_stack", is_flag=True, default=False,
              help="Exclude stack-address references (e.g. Stack[-0x10]) from output.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def xrefs_from(binary: str, target: str, limit: int, no_stack: bool, project: str | None):
    """Find cross-references FROM a target."""
    _rpc_command(_resolve_project(project), "xrefs_from", {
        "binary": binary, "target": target, "limit": limit, "no_stack": no_stack,
    })


@cli.command(name="goto")
@click.argument("binary")
@click.argument("target")
@click.argument("target_type", type=click.Choice(["function", "address"]), default="function")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def goto(binary: str, target: str, target_type: str, project: str | None):
    """Navigate GUI to a function or address (GUI mode only)."""
    _rpc_command(_resolve_project(project), "goto", {
        "binary": binary, "target": target, "target_type": target_type,
    })


@cli.command(name="create-function")
@click.argument("binary")
@click.argument("address")
@click.option("--name", "-n", default="", help="Function name (default: auto-generated)")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def create_function(binary: str, address: str, name: str, project: str | None):
    """Create a function at an address where Ghidra hasn't auto-detected one.

    Auto-detects the function body by following flow from ADDRESS.
    Useful for hand-crafted assembly, obfuscated code, or unreachable
    code not found by analysis.
    """
    args: dict = {"binary": binary, "address": address}
    if name:
        args["name"] = name
    _rpc_command(_resolve_project(project), "create_function", args)


@cli.command(name="create-label")
@click.argument("binary")
@click.argument("address")
@click.argument("name")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def create_label(binary: str, address: str, name: str, project: str | None):
    """Create or rename a label at an address.

    If a symbol already exists at ADDRESS, its primary name is changed to NAME.
    If no symbol exists (e.g. inside an array or unanalysed region), a new
    USER_DEFINED label is created. This is the preferred way to annotate any
    listing address, regardless of whether auto-analysis placed a DAT_ symbol
    there or not.
    """
    _rpc_command(_resolve_project(project), "create_label", {
        "binary": binary, "address": address, "name": name,
    })


@cli.command(name="rename-function")
@click.argument("binary")
@click.argument("target")
@click.argument("new_name")
@click.option("--namespace", "-n", default="",
              help="Move the function into this namespace (must exist; use create-namespace first).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def rename_function(binary: str, target: str, new_name: str, namespace: str,
                    project: str | None):
    """Rename a function, optionally moving it into a namespace.

    Use --namespace to move the function into a namespace (creates clean
    C++ class-style decompiler output). The namespace must already exist
    (use create-namespace first).
    """
    args: dict = {
        "binary": binary, "target": target, "new_name": new_name,
    }
    if namespace:
        args["namespace"] = namespace
    _rpc_command(_resolve_project(project), "rename_function", args)


@cli.command(name="rename-symbol")
@click.argument("binary")
@click.argument("address")
@click.argument("new_name")
@click.option("--create", is_flag=True, default=False,
              help="Create a new label if no symbol exists at ADDRESS "
                   "(instead of erroring).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def rename_symbol(binary: str, address: str, new_name: str, create: bool,
                  project: str | None):
    """Rename a symbol at an address.

    Use --create to create the label if no symbol exists at ADDRESS yet.
    For a pure upsert (create-or-rename without knowing whether a symbol
    already exists), prefer the 'create-label' command instead.
    """
    _rpc_command(_resolve_project(project), "rename_symbol", {
        "binary": binary, "address": address, "new_name": new_name,
        "create": create,
    })


@cli.command(name="set-comment")
@click.argument("binary")
@click.argument("address")
@click.option("--comment", required=True, help="Comment text.")
@click.option("--type", "comment_type", type=click.Choice(["plate", "pre", "post", "eol", "repeatable"]), default="eol")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_comment(binary: str, address: str, comment: str, comment_type: str, project: str | None):
    """Set a comment at an address."""
    _rpc_command(_resolve_project(project), "set_comment", {
        "binary": binary, "address": address, "comment": comment, "comment_type": comment_type,
    })


@cli.command(name="set-signature")
@click.argument("binary")
@click.argument("target")
@click.argument("signature")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_signature(binary: str, target: str, signature: str, project: str | None):
    """Set a function's signature/prototype."""
    _rpc_command(_resolve_project(project), "set_function_signature", {
        "binary": binary, "target": target, "signature": signature,
    })


@cli.command(name="assemble")
@click.argument("binary")
@click.argument("address")
@click.argument("instructions", nargs=-1, required=True)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def assemble(binary: str, address: str, instructions: tuple,
             project: str | None):
    """Assemble instruction text at an address using Ghidra's SLEIGH assembler.

    Each INSTRUCTION argument is one assembly line:
      ghidra-rpc assemble binary 0x401234 "MOV EAX, 0" "NOP" "RET"

    The assembler patches the program bytes and creates instruction
    listings atomically.  Quote multi-word instructions to prevent
    shell word-splitting.
    """
    _rpc_command(_resolve_project(project), "assemble", {
        "binary": binary, "address": address,
        "instructions": list(instructions),
    })


@cli.command(name="disassemble")
@click.argument("binary")
@click.argument("address")
@click.option("--count", "-n", type=int, default=20, show_default=True,
              help="Number of instructions to list (max 1000)")
@click.option("--with-instructions", "with_instructions", is_flag=True, default=False,
              help="Also return the structured per-instruction array")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def disassemble(binary: str, address: str, count: int, with_instructions: bool,
                project: str | None):
    """Disassemble instructions starting at ADDRESS."""
    _rpc_command(_resolve_project(project), "disassemble", {
        "binary": binary, "address": address, "count": count,
        "with_instructions": with_instructions,
    })


@cli.command(name="set-data-type")
@click.argument("binary")
@click.argument("address")
@click.argument("data_type")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_data_type(binary: str, address: str, data_type: str, project: str | None):
    """Set the data type at an address in the listing (disassembler view).

    DATA_TYPE can be a built-in name (byte, char, int, string, unicode, …)
    or a C-style expression parsed by Ghidra (char *, int[10], MyStruct *).
    Use 'string' to define a null-terminated C string.
    """
    _rpc_command(_resolve_project(project), "set_data_type", {
        "binary": binary, "address": address, "data_type": data_type,
    })


@cli.command(name="retype-variable")
@click.argument("binary")
@click.argument("func")
@click.argument("variable")
@click.argument("data_type")
@click.option("--timeout", "-t", type=int, default=60, show_default=True,
              help="Decompiler timeout in seconds (retype triggers recompilation).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def retype_variable(binary: str, func: str, variable: str, data_type: str,
                    timeout: int, project: str | None):
    """Retype a local variable or parameter in the decompiler view.

    VARIABLE is the decompiler variable name (e.g. local_13, param_1).
    DATA_TYPE follows the same syntax as set-data-type.
    """
    _rpc_command(_resolve_project(project), "retype_variable", {
        "binary": binary, "func": func, "variable": variable,
        "data_type": data_type, "timeout": timeout,
    })


@cli.command(name="rename-variable")
@click.argument("binary")
@click.argument("func")
@click.argument("variable")
@click.argument("new_name")
@click.option("--timeout", "-t", type=int, default=60, show_default=True,
              help="Decompiler timeout in seconds (rename triggers recompilation).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def rename_variable(binary: str, func: str, variable: str, new_name: str,
                    timeout: int, project: str | None):
    """Rename a local variable or parameter in the decompiler view.

    VARIABLE is the decompiler variable name (e.g. local_13, param_1).
    NEW_NAME is the new variable name.
    """
    _rpc_command(_resolve_project(project), "rename_variable", {
        "binary": binary, "func": func, "variable": variable,
        "new_name": new_name, "timeout": timeout,
    })


@cli.command(name="batch-edit-variable")
@click.argument("binary")
@click.argument("func")
@click.option(
    "--json", "json_data", default="",
    help="JSON array of variable-edit operations (inline string).",
)
@click.option(
    "--json-file", "json_file", default=None,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Path to a JSON file containing the edit operations.",
)
@click.option("--timeout", "-t", type=int, default=60, show_default=True,
              help="Decompiler timeout in seconds.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def batch_edit_variable(
    binary: str, func: str,
    json_data: str, json_file: str,
    timeout: int, project: str | None,
):
    """Rename and/or retype many local variables in ONE decompiler snapshot.

    The function is decompiled once and every edit is applied in a single
    transaction, so auto-named locals do not renumber between edits (the
    failure mode of chaining single rename-variable / retype-variable calls).

    Each op identifies its variable by exactly one of "variable" (current name)
    or "storage" (e.g. "Stack[-0x18]:4", "EAX:4"), and supplies "new_name"
    and/or "data_type" (either may be omitted to change only the other).

    \b
    Example:
      [{"variable": "dVar1", "new_name": "pace", "data_type": "double"},
       {"variable": "dVar2", "new_name": "watts"},
       {"storage":  "Stack[-0x18]:8", "data_type": "Split *"}]

    Per-item results report old/new name+type and a `verified` read-back flag.
    """
    if json_file:
        with open(json_file) as f:
            operations = json.load(f)
    elif json_data:
        try:
            operations = json.loads(json_data)
        except json.JSONDecodeError as e:
            click.echo(f"Error: invalid JSON: {e}", err=True)
            sys.exit(1)
    else:
        click.echo("Error: provide --json or --json-file.", err=True)
        sys.exit(1)

    _rpc_command(_resolve_project(project), "batch_edit_variables", {
        "binary": binary, "func": func,
        "operations": operations, "timeout": timeout,
    })


@cli.command(name="write-bytes")
@click.argument("binary")
@click.argument("address")
@click.argument("hex_data")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def write_bytes(binary: str, address: str, hex_data: str, project: str | None):
    """Write raw bytes to a program address.

    HEX_DATA is a hex string of bytes to write (spaces optional):
      ghidra-rpc write-bytes binary 0x401234 "90 90 90"
      ghidra-rpc write-bytes binary 0x401234 909090

    Does NOT auto-redisassemble the affected region. Use 'disassemble'
    or 'assemble' afterwards to update the instruction listing.
    """
    _rpc_command(_resolve_project(project), "write_bytes", {
        "binary": binary, "address": address, "hex": hex_data,
    })


@cli.command(name="read-bytes")
@click.argument("binary")
@click.argument("address")
@click.argument("length", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def read_bytes(binary: str, address: str, length: int, project: str | None):
    """Read raw bytes from a binary address and print a hex dump.

    LENGTH accepts decimal (184) or hex (0xb8) notation.
    """
    _rpc_command(_resolve_project(project), "read_bytes", {
        "binary": binary, "address": address, "length": length,
    })


@cli.command(name="read-pointers")
@click.argument("binary")
@click.argument("address")
@click.argument("count", type=HEX_INT)
@click.option("--pointer-size", "-s", type=HEX_INT, default=None,
              help="Pointer width in bytes (1/2/4/8). Default: program's pointer size.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def read_pointers(binary: str, address: str, count: int,
                  pointer_size: int | None, project: str | None):
    """Read COUNT pointers at ADDRESS and resolve each to its symbol.

    COUNT accepts decimal (18) or hex (0x12). Handy for vtables, import
    tables, jump tables, and RTTI pointer arrays.
    """
    args = {"binary": binary, "address": address, "count": count}
    if pointer_size is not None:
        args["pointer_size"] = pointer_size
    _rpc_command(_resolve_project(project), "read_pointers", args)


@cli.command(name="list-vtable")
@click.argument("binary")
@click.argument("address")
@click.option("--count", "-c", type=HEX_INT, default=None,
              help="Fixed slot count (overrides auto-termination at the next "
                   "vftable symbol / first non-function pointer).")
@click.option("--pointer-size", "-s", type=HEX_INT, default=None,
              help="Pointer width in bytes. Default: program's pointer size.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_vtable(binary: str, address: str, count: int | None,
                pointer_size: int | None, project: str | None):
    """List the slots of a C++ vtable at ADDRESS (hex address or symbol name).

    Each slot is resolved to its target function. Without --count, the walk
    stops at the next vftable symbol, the first non-function pointer, or a
    hard cap — see `stopped_reason` in the output.
    """
    args = {"binary": binary, "address": address}
    if count is not None:
        args["count"] = count
    if pointer_size is not None:
        args["pointer_size"] = pointer_size
    _rpc_command(_resolve_project(project), "list_vtable", args)


@cli.command(name="relocations")
@click.argument("binary")
@click.option("--address", "-a", default="",
              help="Show only relocations at this address.")
@click.option("--limit", "-l", type=int, default=200, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def relocations(binary: str, address: str, limit: int, project: str | None):
    """List relocation table entries for a binary.

    Shows address, type, symbol name, original bytes, and status for
    each relocation.  Important for PIC/PIE analysis, IAT inspection,
    and understanding which addresses are patched by the dynamic linker.
    """
    args: dict = {"binary": binary, "limit": limit}
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "relocations", args)


@cli.command(name="memory-map")
@click.argument("binary")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def memory_map(binary: str, project: str | None):
    """List all memory segments (sections) of a binary.

    Shows name, address range, size, permissions (rwx), and type for
    each MemoryBlock.  Useful for understanding binary layout, finding
    code vs. data regions, and choosing address ranges for search.
    """
    _rpc_command(_resolve_project(project), "memory_map", {"binary": binary})


@cli.command(name="list-binaries")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_binaries(project: str | None):
    """List binaries currently loaded in the daemon."""
    _rpc_command(_resolve_project(project), "list_binaries", {})


@cli.command(name="list-project-programs")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_project_programs(project: str | None):
    """List all programs stored in the Ghidra project on disk.

    Unlike list-binaries, this shows every program in the project repository
    regardless of whether it is currently open in CodeBrowser or loaded into
    the daemon.
    """
    _rpc_command(_resolve_project(project), "list_project_programs", {})


@cli.command(name="save")
@click.argument("binary", required=False, default="")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def save_program(binary: str, project: str | None):
    """Save program changes to the Ghidra project database on disk.

    If BINARY is given, saves only that program. Otherwise saves all loaded
    programs. Write operations (rename, set-comment, etc.) auto-save, but
    this command is useful before stopping the daemon or as an explicit
    checkpoint.
    """
    args = {}
    if binary:
        args["binary"] = binary
    _rpc_command(_resolve_project(project), "save", args)


@cli.command(name="create-struct")
@click.argument("binary")
@click.argument("struct_name")
@click.argument("fields", nargs=-1, required=False)
@click.option(
    "--field", "explicit_fields", multiple=True, nargs=3,
    metavar="OFFSET TYPE NAME",
    help="Field at an explicit byte OFFSET (decimal or 0x hex), repeatable. "
         "Gaps between fields are auto-padded. Mutually exclusive with the "
         "positional TYPE NAME pairs.",
)
@click.option(
    "--if-not-exists", "if_not_exists", is_flag=True, default=False,
    help="If a struct with this name already exists, return it without error "
         "(idempotent mode, safe for scripts that may run multiple times).",
)
@click.option(
    "--or-replace", "or_replace", is_flag=True, default=False,
    help="If a struct with this name already exists, delete it and create "
         "a new one with the provided fields.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def create_struct(
    binary: str, struct_name: str, fields: tuple, explicit_fields: tuple,
    if_not_exists: bool, or_replace: bool, project: str | None
):
    """Create a named struct type in the program's data type manager.

    Two layouts:

    \b
    Sequential — FIELDS is a flat list of alternating TYPE NAME pairs:
      ghidra-rpc create-struct binary ErrorEntry int errorNumber "char *" ptrErrorMsg

    \b
    Explicit offsets — repeat --field OFFSET TYPE NAME; gaps auto-pad:
      ghidra-rpc create-struct binary Split \\
        --field 0x00 int time --field 0x10 "FixedIntervalData *" data

    Once created, the struct is available by name for set-data-type and
    apply-data-type-range (e.g. ErrorEntry, ErrorEntry[4], ErrorEntry *).
    Quote multi-word types like "char *" or "unsigned int" to prevent shell
    word-splitting.

    Use --if-not-exists to make the call idempotent (return the existing struct
    if the name is already taken).  Use --or-replace to delete the existing
    struct and recreate it with the new field layout.
    """
    if fields and explicit_fields:
        click.echo(
            "Error: use either positional TYPE NAME pairs or --field "
            "OFFSET TYPE NAME, not both.",
            err=True,
        )
        sys.exit(1)

    if explicit_fields:
        field_list = [
            {"offset": off, "type": ftype, "name": fname}
            for (off, ftype, fname) in explicit_fields
        ]
    elif fields:
        if len(fields) % 2 != 0:
            click.echo(
                "Error: FIELDS must be pairs of TYPE NAME "
                f"(got {len(fields)} token(s)).",
                err=True,
            )
            sys.exit(1)
        field_list = [
            {"type": fields[i], "name": fields[i + 1]}
            for i in range(0, len(fields), 2)
        ]
    elif if_not_exists:
        field_list = []  # allowed: idempotent lookup of an existing struct
    else:
        click.echo(
            "Error: provide fields as positional TYPE NAME pairs or "
            "--field OFFSET TYPE NAME.",
            err=True,
        )
        sys.exit(1)

    _rpc_command(_resolve_project(project), "create_struct", {
        "binary": binary, "name": struct_name, "fields": field_list,
        "if_not_exists": if_not_exists, "or_replace": or_replace,
    })


@cli.command(name="create-union")
@click.argument("binary")
@click.argument("union_name")
@click.argument("fields", nargs=-1, required=True)
@click.option(
    "--if-not-exists", "if_not_exists", is_flag=True, default=False,
    help="If a union with this name already exists, return it without error.",
)
@click.option(
    "--or-replace", "or_replace", is_flag=True, default=False,
    help="If a union with this name already exists, delete it and recreate.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def create_union(
    binary: str, union_name: str, fields: tuple,
    if_not_exists: bool, or_replace: bool, project: str | None
):
    """Create a named union type in the program's data type manager.

    FIELDS is a flat list of alternating TYPE NAME pairs:

      ghidra-rpc create-union <binary> <union_name> TYPE1 FIELD1 TYPE2 FIELD2 ...

    Example:
      ghidra-rpc create-union binary MyUnion uint as_uint "char[4]" as_bytes

    Unlike structs, all union fields share offset 0 and the union's size
    is the largest member. Semantics follow C union conventions.

    Same --if-not-exists / --or-replace flags as create-struct.
    """
    if len(fields) % 2 != 0:
        click.echo(
            "Error: FIELDS must be pairs of TYPE NAME "
            f"(got {len(fields)} token(s)).",
            err=True,
        )
        sys.exit(1)
    field_list = [
        {"type": fields[i], "name": fields[i + 1]}
        for i in range(0, len(fields), 2)
    ]
    _rpc_command(_resolve_project(project), "create_union", {
        "binary": binary, "name": union_name, "fields": field_list,
        "if_not_exists": if_not_exists, "or_replace": or_replace,
    })


@cli.command(name="modify-struct")
@click.argument("binary")
@click.argument("struct_name")
@click.option(
    "--field-offset", "field_offset", type=int, default=None,
    help="Byte offset of the field to modify.",
)
@click.option(
    "--field-name", "field_name", default="",
    help="Name of the field to modify (alternative to --field-offset).",
)
@click.option("--new-type", "new_type", default="",
              help="New data type for the field.")
@click.option("--new-name", "new_name", default="",
              help="New name for the field.")
@click.option("--new-comment", "new_comment", default="",
              help="New comment for the field.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def modify_struct(
    binary: str, struct_name: str,
    field_offset: int | None, field_name: str,
    new_type: str, new_name: str, new_comment: str,
    project: str | None
):
    """Retype, rename, or re-comment a field in an existing struct.

    Identify the field by --field-offset (byte offset) or --field-name.
    Then specify the changes: --new-type, --new-name, and/or --new-comment.

    Example:
      ghidra-rpc modify-struct binary Node --field-offset 8 \
        --new-type "Node *" --new-name next
    """
    if field_offset is None and not field_name:
        click.echo(
            "Error: At least one of --field-offset or --field-name is required.",
            err=True,
        )
        sys.exit(1)
    if not new_type and not new_name and not new_comment:
        click.echo(
            "Error: At least one of --new-type, --new-name, or --new-comment is required.",
            err=True,
        )
        sys.exit(1)

    args: dict = {"binary": binary, "struct_name": struct_name}
    if field_offset is not None:
        args["field_offset"] = field_offset
    if field_name:
        args["field_name"] = field_name
    if new_type:
        args["new_type"] = new_type
    if new_name:
        args["new_name"] = new_name
    if new_comment:
        args["new_comment"] = new_comment
    _rpc_command(_resolve_project(project), "modify_struct", args)


@cli.command(name="create-enum")
@click.argument("binary")
@click.argument("enum_name")
@click.argument("values", nargs=-1, required=False)
@click.option(
    "--size", "size", type=click.Choice(["1", "2", "4", "8"]), default="4", show_default=True,
    help="Byte size of the enum (1, 2, 4, or 8).",
)
@click.option(
    "--if-not-exists", "if_not_exists", is_flag=True, default=False,
    help="If an enum with this name already exists, return it without error.",
)
@click.option(
    "--or-replace", "or_replace", is_flag=True, default=False,
    help="If an enum with this name already exists, delete it and recreate it.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def create_enum(
    binary: str, enum_name: str, values: tuple,
    size: str, if_not_exists: bool, or_replace: bool, project: str | None
):
    """Create a named enum type in the program's data type manager.

    VALUES is a flat list of alternating NAME VALUE pairs:

      ghidra-rpc create-enum <binary> <enum_name> NAME1 VALUE1 NAME2 VALUE2 ...

    Example:
      ghidra-rpc create-enum binary MyEnum Enum0 0 Enum1 1 Enum2 2 Enum3 3
      ghidra-rpc create-enum binary ExceptionNumbers _FPE_INVALID 0x81 _FPE_DENORMAL 0x82 --size 4

    Once created, the enum is available by name for retype-variable and
    set-data-type. Use --if-not-exists for idempotent scripts, --or-replace
    to rebuild it from scratch.
    """
    if len(values) % 2 != 0:
        click.echo(
            "Error: VALUES must be pairs of NAME VALUE "
            f"(got {len(values)} token(s)).",
            err=True,
        )
        sys.exit(1)
    value_list = [
        {"name": values[i], "value": int(values[i + 1], 0)}
        for i in range(0, len(values), 2)
    ]
    _rpc_command(_resolve_project(project), "create_enum", {
        "binary": binary, "name": enum_name, "values": value_list,
        "size": int(size), "if_not_exists": if_not_exists, "or_replace": or_replace,
    })


@cli.command(name="set-equate")
@click.argument("binary")
@click.argument("address")
@click.argument("equate_name")
@click.argument("value")
@click.option(
    "--operand-index", "operand_index", type=int, default=1, show_default=True,
    help="Zero-based index of the scalar operand in the instruction.",
)
@click.option(
    "--enum-path", "enum_path", default="",
    help="DTM path of an enum type to link this equate to (e.g. MyEnum or "
         "/MyDir/MyEnum). When provided, the equate is formally linked to "
         "the enum so Ghidra shows its name in the listing view.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_equate(
    binary: str, address: str, equate_name: str, value: str,
    operand_index: int, enum_path: str, project: str | None
):
    """Apply a named equate to a scalar operand at ADDRESS.

    Creates the equate in the program's EquateTable if it does not exist,
    then attaches it to the instruction operand at OPERAND_INDEX (default 1).
    VALUE is the scalar integer the operand must equal (hex like 0x81 is OK).

    When --enum-path is given (or auto-detected), the equate is formally
    linked to the enum type so Ghidra renders the name in the listing and
    decompiler views instead of the raw hex constant.

    Example - tag the immediate in "CMP AX, 0x81" with ExceptionNumbers entry:
      ghidra-rpc set-equate binary 0x004010b4 _FPE_INVALID 0x81 --enum-path ExceptionNumbers
    """
    _rpc_command(_resolve_project(project), "set_equate", {
        "binary": binary, "address": address,
        "equate_name": equate_name, "value": int(value, 0),
        "operand_index": operand_index, "enum_path": enum_path,
    })


@cli.command(name="list-equates")
@click.argument("binary")
@click.argument("address", default="")
@click.option("--limit", "-l", type=int, default=200, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_equates(
    binary: str, address: str, limit: int, project: str | None
):
    """List equates in a program or at a specific address.

    Without ADDRESS: lists all equates defined in the program's EquateTable.
    With ADDRESS: lists only equates applied at that instruction (across all
    operand indices), each entry includes operand_index.

    Output: {equates:[{name, value[, operand_index, address]}], count, total}
    """
    args: dict = {"binary": binary, "limit": limit}
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "list_equates", args)


@cli.command(name="set-bookmark")
@click.argument("binary")
@click.argument("address")
@click.option("--type", "bm_type", type=click.Choice(
    ["Note", "Warning", "Error", "Info", "Analysis"],
    case_sensitive=False), default="Note", show_default=True,
    help="Bookmark type.")
@click.option("--category", "-c", default="", help="Free-form category string.")
@click.option("--comment", "-m", default="", help="Bookmark comment text.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_bookmark(binary: str, address: str, bm_type: str, category: str,
                comment: str, project: str | None):
    """Create or update a bookmark at an address.

    Bookmarks are first-class Ghidra annotations visible in the GUI's
    Bookmarks window.  Use them to mark interesting locations, track
    analysis progress, or flag findings for human review.

    Example:
      ghidra-rpc set-bookmark binary 0x401234 --type Note \\
        --category vuln-research --comment "User-controlled memcpy size"
    """
    _rpc_command(_resolve_project(project), "set_bookmark", {
        "binary": binary, "address": address,
        "type": bm_type, "category": category, "comment": comment,
    })


@cli.command(name="list-bookmarks")
@click.argument("binary")
@click.option("--type", "bm_type", default="",
              help="Filter by bookmark type (Note, Warning, Error, Info, Analysis).")
@click.option("--category", "category", default="",
              help="Filter by bookmark category (substring match, case-insensitive).")
@click.option("--address", "-a", default="",
              help="List only bookmarks at this address.")
@click.option("--limit", "-l", type=int, default=200, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_bookmarks(binary: str, bm_type: str, category: str, address: str, limit: int,
                  project: str | None):
    """List bookmarks in a program.

    Without filters, lists all bookmarks.  Use --type to filter by bookmark
    type, --category to filter by category (e.g. to exclude/isolate
    analysis-generated bookmarks from user-created ones), or --address to
    list bookmarks at a specific address.
    """
    args: dict = {"binary": binary, "limit": limit}
    if bm_type:
        args["type"] = bm_type
    if category:
        args["category"] = category
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "list_bookmarks", args)


@cli.command(name="remove-bookmark")
@click.argument("binary")
@click.argument("address")
@click.option("--type", "bm_type", type=click.Choice(
    ["Note", "Warning", "Error", "Info", "Analysis"],
    case_sensitive=False), default="Note", show_default=True,
    help="Bookmark type to remove.")
@click.option("--category", "-c", default="", help="Category of bookmark to remove.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def remove_bookmark(binary: str, address: str, bm_type: str, category: str,
                   project: str | None):
    """Remove a bookmark at an address."""
    _rpc_command(_resolve_project(project), "remove_bookmark", {
        "binary": binary, "address": address,
        "type": bm_type, "category": category,
    })


@cli.command(name="list-data-types")
@click.argument("binary")
@click.option(
    "--category", default="all",
    type=click.Choice(["all", "struct", "enum", "union",
                       "typedef", "pointer", "array", "other"]),
    show_default=True,
    help="Filter by data-type category.",
)
@click.option("--query", default="", help="Substring filter on type name.")
@click.option("--limit", "-l", type=int, default=200, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_data_types(
    binary: str, category: str, query: str, limit: int, project: str | None
):
    """Enumerate data types in the program's DataTypeManager.

    Use --category to filter (struct, enum, union, typedef, pointer, array).
    Use --query to filter by name substring.
    Useful for discovering existing enums and structs before applying them.

    Output: {data_types:[{name, path, category, size}], count, total}
    """
    _rpc_command(_resolve_project(project), "list_data_types", {
        "binary": binary, "category": category,
        "query": query, "limit": limit,
    })


@cli.command(name="modify-enum")
@click.argument("binary")
@click.argument("enum_name")
@click.option(
    "--add", "add_entries", multiple=True, metavar="NAME:VALUE",
    help="Add an entry. Repeat for multiple: --add Err0:0 --add Err1:1. "
         "VALUE accepts 0x-prefixed hex.",
)
@click.option(
    "--remove", "remove_entries", multiple=True, metavar="NAME",
    help="Remove an entry by name. Repeat for multiple: --remove Err0 --remove Err1.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def modify_enum(
    binary: str, enum_name: str,
    add_entries: tuple, remove_entries: tuple,
    project: str | None
):
    """Add or remove individual entries from an existing enum.

    Removals are applied before additions, so rename = --remove OLD --add NEW:VALUE
    is safe in a single call.

    Example:
      ghidra-rpc modify-enum binary ExceptionNumbers \\
          --remove _FPE_OLD_NAME \\
          --add _FPE_NEW_NAME:0x85

    Output: {name, path, size, values:[{name, value}]}
    """
    add = []
    for entry in add_entries:
        if ":" not in entry:
            raise click.BadParameter(
                f"--add entries must be NAME:VALUE, got: {entry!r}"
            )
        name, _, raw_val = entry.partition(":")
        add.append({"name": name, "value": int(raw_val, 0)})

    _rpc_command(_resolve_project(project), "modify_enum", {
        "binary": binary, "name": enum_name,
        "add": add, "remove": list(remove_entries),
    })


@cli.command(name="clear-data-range")
@click.argument("binary")
@click.argument("start")
@click.argument("end")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def clear_data_range(binary: str, start: str, end: str, project: str | None):
    """Clear all data/code definitions in an inclusive address range [START, END].

    Resets the bytes to 'undefined' so that set-data-type or
    apply-data-type-range can stamp fresh type definitions over the region.

    Both START and END are inclusive: every byte from START to END is cleared.
    """
    _rpc_command(_resolve_project(project), "clear_data_range", {
        "binary": binary, "start": start, "end": end,
    })


@cli.command(name="apply-data-type-range")
@click.argument("binary")
@click.argument("start")
@click.argument("end")
@click.argument("data_type")
@click.option(
    "--clear", "do_clear", is_flag=True, default=False,
    help="Clear all existing data definitions in the range before applying "
         "the type. Without this flag, addresses with conflicting existing "
         "data are skipped (their errors are reported per-address). Use "
         "--clear when you need a clean-slate stamp across the region.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def apply_data_type_range(
    binary: str, start: str, end: str, data_type: str,
    do_clear: bool, project: str | None
):
    """Stamp a fixed-size type repeatedly across an inclusive address range.

    Equivalent to: (optionally clear the range, then) apply DATA_TYPE at
    START, START+size, START+2*size, … for as many complete instances as fit.
    Both START and END are inclusive.

    Without --clear: conflicting data units are skipped (errors reported per
    address). Use this when the region is already undefined or when you want
    to preserve adjacent definitions outside the struct grid.

    With --clear: atomically clears the entire range first, then stamps. Use
    this when the region has existing conflicting definitions. Combines
    clear-data-range + apply-data-type-range into a single round-trip.

    Example — label 23 consecutive ErrorEntry structs (8 bytes each):
      apply-data-type-range binary 0x0040e4a8 0x0040e55f ErrorEntry --clear
    """
    _rpc_command(_resolve_project(project), "apply_data_type_range", {
        "binary": binary, "start": start, "end": end,
        "data_type": data_type, "clear": do_clear,
    })


@cli.command(name="list-labels")
@click.argument("binary")
@click.argument("address")
@click.option("--end", "end_addr", default="", help="End of range (inclusive). "
              "If omitted, lists only symbols at ADDRESS.")
@click.option("--limit", "-l", type=int, default=100, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_labels(
    binary: str, address: str, end_addr: str, limit: int, project: str | None
):
    """List symbols/labels at an address or within an address range.

    Without --end: shows all symbols (including secondary) at ADDRESS.
    With --end: shows the primary symbol at each labeled address in
    [ADDRESS, END] (inclusive), up to --limit results.

    Includes USER_DEFINED, ANALYSIS (auto-generated DAT_/FUN_), and IMPORTED
    symbols. Useful for checking what labels exist before calling rename-symbol
    or create-label.
    """
    args: dict = {"binary": binary, "address": address, "limit": limit}
    if end_addr:
        args["end"] = end_addr
    _rpc_command(_resolve_project(project), "list_labels", args)


@cli.command(name="list-calling-conventions")
@click.argument("binary")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_calling_conventions(binary: str, project: str | None):
    """List all calling conventions available for the binary's architecture.

    Shows convention names like __cdecl, __stdcall, __fastcall, __thiscall,
    AAPCS, etc.  Use these names with set-calling-convention.
    """
    _rpc_command(_resolve_project(project), "list_calling_conventions", {
        "binary": binary,
    })


@cli.command(name="set-calling-convention")
@click.argument("binary")
@click.argument("target")
@click.argument("convention")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_calling_convention(binary: str, target: str, convention: str,
                           project: str | None):
    """Change a function's calling convention.

    TARGET is a function name or hex address.
    CONVENTION must be a valid name from list-calling-conventions
    (e.g. __fastcall, __stdcall, __thiscall).

    Correcting the calling convention fixes parameter passing in the
    decompiler output when Ghidra's auto-detection is wrong.
    """
    _rpc_command(_resolve_project(project), "set_calling_convention", {
        "binary": binary, "target": target, "convention": convention,
    })


@cli.command(name="basic-blocks")
@click.argument("binary")
@click.argument("func")
@click.option("--limit", "-l", type=int, default=500, help="Max blocks (default 500)")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def basic_blocks(binary: str, func: str, limit: int, project: str | None):
    """Get the basic blocks (control-flow graph) of a function.

    Returns each basic block with its address range, instruction count,
    successor edges, and predecessor addresses. Essential for CFG analysis,
    cyclomatic complexity, loop detection, and unreachable code identification.

    FUNC can be a function name or hex address.
    """
    _rpc_command(_resolve_project(project), "basic_blocks", {
        "binary": binary, "func": func, "limit": limit,
    })


@cli.command(name="pcode")
@click.argument("binary")
@click.argument("func")
@click.option("--high", is_flag=True, default=False,
              help="Return high (SSA) P-code from the decompiler instead of raw listing P-code.")
@click.option("--timeout", "-t", type=int, default=60,
              help="Decompiler timeout for --high mode (default 60 s).")
@click.option("--limit", "-l", type=int, default=1000, help="Max P-code ops (default 1000)")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def pcode(binary: str, func: str, high: bool, timeout: int, limit: int,
          project: str | None):
    """Get P-code (Ghidra's intermediate representation) for a function.

    Raw P-code (default): listing-level ops for each machine instruction.
    High P-code (--high): SSA-form ops from the decompiler with resolved
    variable names. Use for precise data-flow tracing, taint analysis,
    and identifying all CALL/CALLIND/BRANCHIND operations.

    FUNC can be a function name or hex address.
    """
    _rpc_command(_resolve_project(project), "pcode", {
        "binary": binary, "func": func, "high": high,
        "timeout": timeout, "limit": limit,
    })


@cli.command(name="tag-function")
@click.argument("binary")
@click.argument("target")
@click.option("--tag", "-t", required=True, help="Tag string to apply.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def tag_function(binary: str, target: str, tag: str, project: str | None):
    """Add a tag to a function for classification.

    Tags are string labels (e.g. 'crypto', 'vuln-sink', 'analyzed') visible
    in Ghidra's Function Tags window. Useful for tracking analysis progress
    and classifying functions.

    TARGET is a function name or hex address.
    """
    _rpc_command(_resolve_project(project), "tag_function", {
        "binary": binary, "target": target, "tag": tag,
    })


@cli.command(name="untag-function")
@click.argument("binary")
@click.argument("target")
@click.option("--tag", "-t", required=True, help="Tag string to remove.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def untag_function(binary: str, target: str, tag: str, project: str | None):
    """Remove a tag from a function.

    TARGET is a function name or hex address.
    """
    _rpc_command(_resolve_project(project), "untag_function", {
        "binary": binary, "target": target, "tag": tag,
    })


@cli.command(name="list-tags")
@click.argument("binary")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_tags(binary: str, project: str | None):
    """List all function tags defined in the program with use counts."""
    _rpc_command(_resolve_project(project), "list_tags", {
        "binary": binary,
    })


@cli.command(name="functions-by-tag")
@click.argument("binary")
@click.option("--tag", "-t", required=True, help="Tag to search for.")
@click.option("--limit", "-l", type=int, default=200, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def functions_by_tag(binary: str, tag: str, limit: int, project: str | None):
    """List all functions with a specific tag."""
    _rpc_command(_resolve_project(project), "functions_by_tag", {
        "binary": binary, "tag": tag, "limit": limit,
    })


@cli.command(name="set-thunk")
@click.argument("binary")
@click.argument("thunk")
@click.argument("target")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_thunk(binary: str, thunk: str, target: str, project: str | None):
    """Mark a function as a thunk (forwarding wrapper) to another function.

    THUNK is the forwarding function (e.g. a PLT stub).
    TARGET is the real function it forwards to.

    Marking a thunk propagates the target's name/signature to all call
    sites, cleans up xrefs, and improves decompilation output. Essential
    for PLT/IAT analysis and C++ virtual dispatch stubs.
    """
    _rpc_command(_resolve_project(project), "set_thunk", {
        "binary": binary, "thunk": thunk, "target": target,
    })


@cli.command(name="set-flow-override")
@click.argument("binary")
@click.argument("address")
@click.argument("override", type=click.Choice(
    ["NONE", "BRANCH", "CALL", "CALL_RETURN", "RETURN"],
    case_sensitive=False))
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_flow_override(binary: str, address: str, override: str,
                      project: str | None):
    """Override the flow type of an instruction.

    Useful when Ghidra misclassifies a jump as a branch vs. a tail call,
    or doesn't recognize that a CALL never returns.

    OVERRIDE values: NONE, BRANCH, CALL, CALL_RETURN, RETURN.
    """
    _rpc_command(_resolve_project(project), "set_flow_override", {
        "binary": binary, "address": address, "override": override,
    })


@cli.command(name="create-namespace")
@click.argument("binary")
@click.argument("name")
@click.option("--parent", default="",
              help="Parent namespace (default: GlobalNamespace).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def create_namespace(binary: str, name: str, parent: str, project: str | None):
    """Create a namespace (or return the existing one).

    Namespaces group symbols. For C++ binaries they mirror the class/namespace
    hierarchy. Create a namespace first, then use rename-function --namespace
    to move functions into it.

    Example:
      ghidra-rpc create-namespace binary MyClass
      ghidra-rpc rename-function binary sub_401234 destructor --namespace MyClass
    """
    args: dict = {"binary": binary, "name": name}
    if parent:
        args["parent"] = parent
    _rpc_command(_resolve_project(project), "create_namespace", args)


@cli.command(name="list-namespaces")
@click.argument("binary")
@click.option("--limit", "-l", type=int, default=500, help="Max results")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def list_namespaces(binary: str, limit: int, project: str | None):
    """List all namespaces defined in the program."""
    _rpc_command(_resolve_project(project), "list_namespaces", {
        "binary": binary, "limit": limit,
    })


# ─── Version Tracking / Binary Diff commands ─────────────────────────────────

@cli.command(name="version-track")
@click.argument("source")
@click.argument("destination")
@click.option("--limit", "-l", type=int, default=500, help="Max matched results")
@click.option("--include-data", "include_data", is_flag=True, default=False,
              help="Include data matches (not just functions).")
@click.option("--min-similarity", "min_similarity", type=float, default=0.0,
              help="Minimum similarity score (0.0-1.0) to include in results.")
@click.option("--changed-only", "changed_only", is_flag=True, default=False,
              help="Only return matched pairs where similarity < 1.0 (i.e. functions that changed).")
@click.option("--ref-min-score", "ref_min_score", type=float, default=0.95,
              help="Min score for reference correlators (default 0.95).")
@click.option("--ref-min-conf", "ref_min_conf", type=float, default=10.0,
              help="Min confidence for reference correlators (default 10.0).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def version_track(source: str, destination: str, limit: int, include_data: bool,
                  min_similarity: float, changed_only: bool,
                  ref_min_score: float, ref_min_conf: float,
                  project: str | None):
    """Run Auto Version Tracking between two loaded binaries.

    Uses Ghidra's Version Tracking framework with multiple correlators
    (exact bytes, exact instructions, symbol name, reference, BSim) to
    match functions between SOURCE and DESTINATION binaries.

    Both binaries must be loaded first with 'ghidra-rpc load'.

    Returns matched function pairs with similarity scores, plus lists
    of unmatched functions in each binary.  Use --changed-only to show
    only functions that differ (similarity < 1.0).
    """
    _rpc_command(_resolve_project(project), "version_track", {
        "source": source, "destination": destination,
        "limit": limit, "include_data": include_data,
        "min_similarity": min_similarity, "changed_only": changed_only,
        "ref_min_score": ref_min_score, "ref_min_conf": ref_min_conf,
    })


@cli.command(name="match-function")
@click.argument("source_binary")
@click.argument("func")
@click.argument("target_binary")
@click.option("--threshold", "-t", type=float, default=0.0,
              help="Minimum similarity score (0.0-1.0) for candidates.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def match_function(source_binary: str, func: str, target_binary: str,
                   threshold: float, project: str | None):
    """Find matching function(s) in another binary.

    Given a function in SOURCE_BINARY, finds the most likely corresponding
    function(s) in TARGET_BINARY using BSim and other correlators.

    FUNC can be a function name or hex address.

    Returns candidates sorted by similarity score.
    """
    _rpc_command(_resolve_project(project), "match_function", {
        "source_binary": source_binary, "func": func,
        "target_binary": target_binary, "threshold": threshold,
    })


@cli.command(name="decompile-all")
@click.argument("binary")
@click.option("--timeout", "-t", type=int, default=60, show_default=True,
              help="Per-function decompiler timeout in seconds.")
@click.option("--limit", "-l", type=int, default=None,
              help="Max functions to decompile (default: all).")
@click.option("--offset", "-o", type=int, default=0, show_default=True,
              help="Offset for pagination.")
@click.option("--socket-timeout", type=float, default=1800.0, show_default=True,
              help="Max seconds to wait for the whole sweep to finish. Raise "
                   "this for binaries with many thousands of functions.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def decompile_all(binary: str, timeout: int, limit: int | None, offset: int,
                  socket_timeout: float, project: str | None):
    """Bulk decompile all functions in a binary.

    Returns decompiled pseudo-C for every function (skipping externals
    and thunks).  Use --limit/--offset for pagination on large binaries.

    For diff workflows, decompile both binaries and compare the output
    externally, or use function-diff for per-function comparison.
    """
    args: dict = {"binary": binary, "timeout": timeout, "offset": offset}
    if limit is not None:
        args["limit"] = limit
    _rpc_command(_resolve_project(project), "decompile_all", args, socket_timeout=socket_timeout)


@cli.command(name="search-decompiled")
@click.argument("binary")
@click.argument("pattern")
@click.option("--class", "class_filter", default="",
              help="Only search functions whose fully qualified name "
                   "(namespace path) contains this substring, e.g. a DEX "
                   "class name.")
@click.option("--case-sensitive", is_flag=True, default=False,
              help="Match PATTERN case-sensitively (default: case-insensitive).")
@click.option("--limit", "-l", type=int, default=50, show_default=True,
              help="Max matching functions to return.")
@click.option("--max-scan", type=int, default=5000, show_default=True,
              help="Safety cap on how many functions are actually decompiled "
                   "and searched, in case --class isn't given on a huge binary.")
@click.option("--timeout", "-t", type=int, default=60, show_default=True,
              help="Per-function decompiler timeout in seconds.")
@click.option("--socket-timeout", type=float, default=1800.0, show_default=True,
              help="Max seconds to wait for the whole sweep to finish. Raise "
                   "this for binaries with many thousands of functions.")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def search_decompiled(binary: str, pattern: str, class_filter: str, case_sensitive: bool,
                       limit: int, max_scan: int, timeout: int, socket_timeout: float,
                       project: str | None):
    """Regex-search decompiled C across many functions in one call.

    PATTERN is a regex applied per source line of each function's
    decompiled output.  Use --class to scope the sweep to a namespace (e.g.
    a DEX/APK class) instead of hand-rolling a symbols+decompile+grep loop
    per function.

    Note: PATTERN and --class are matched against Ghidra's own decompiled
    output and qualified names, so results are only as good as Ghidra's
    analysis (e.g. DEX method/class naming after R8/ProGuard obfuscation).
    """
    args: dict = {
        "binary": binary, "pattern": pattern,
        "ignore_case": not case_sensitive,
        "limit": limit, "max_functions": max_scan, "timeout": timeout,
    }
    if class_filter:
        args["class_filter"] = class_filter
    _rpc_command(_resolve_project(project), "search_decompiled", args, socket_timeout=socket_timeout)


@cli.command(name="function-diff")
@click.argument("binary1")
@click.argument("func1")
@click.argument("binary2")
@click.argument("func2")
@click.option("--mode", "-m",
              type=click.Choice(["decompile", "disassembly"]),
              default="decompile", show_default=True,
              help="Diff mode: 'decompile' for pseudo-C (semantic), "
                   "'disassembly' for instruction-level (byte-exact).")
@click.option("--timeout", "-t", type=int, default=60, show_default=True,
              help="Per-function decompiler timeout in seconds (decompile mode only).")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def function_diff(binary1: str, func1: str, binary2: str, func2: str,
                  mode: str, timeout: int, project: str | None):
    """Diff two functions from two binaries.

    In decompile mode (default), decompiles both functions, normalises
    auto-generated variable names to suppress noise, and returns a
    unified diff.  Best for understanding semantic changes.

    In disassembly mode, extracts instruction mnemonics and operands,
    normalises absolute addresses, and diffs.  Best for byte-level
    analysis, obfuscated code, or when the decompiler hides changes.
    """
    _rpc_command(_resolve_project(project), "function_diff", {
        "binary1": binary1, "func1": func1,
        "binary2": binary2, "func2": func2,
        "mode": mode, "timeout": timeout,
    })


@cli.command(name="delete-function")
@click.argument("binary")
@click.argument("target")
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def delete_function(binary: str, target: str, project: str | None):
    """Delete (remove) a function definition from the program.

    Only removes the function record \u2014 the underlying bytes are unchanged
    and the address becomes undefined code.  Useful after creating bad stubs
    (e.g. wrong Thumb parity) so the function can be re-created at the
    correct address.

    TARGET is a function name or hex address.
    """
    _rpc_command(_resolve_project(project), "delete_function", {
        "binary": binary, "target": target,
    })


@cli.command(name="batch-rename")
@click.argument("binary")
@click.option(
    "--json", "json_data", default="",
    help="JSON array of rename operations (inline string).",
)
@click.option(
    "--json-file", "json_file", default=None,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Path to a JSON file containing the rename operations.",
)
@click.option(
    "--mode",
    type=click.Choice(["function", "label"]),
    default="function", show_default=True,
    help="'function' to rename functions, 'label' to rename/create labels at addresses.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def batch_rename(
    binary: str,
    json_data: str, json_file: str,
    mode: str,
    project: str | None,
):
    """Rename many functions or labels in one round-trip (one transaction).

    Accepts a JSON array of rename operations via --json or --json-file.

    \b
    Function mode (--mode function, default):
      [{"target": "sub_401234", "new_name": "init_uart"},
       {"target": "0x03288102", "new_name": "thumb_handler", "namespace": "radio"}]

    \b
    Label mode (--mode label):
      [{"address": "0x0333afcc", "new_name": "g_debugStr"},
       {"address": "0x0333b000", "new_name": "g_logLevel", "create": true}]

    All successful renames are committed in a single Ghidra transaction.
    Failed items are reported per-item; they do not roll back successes.
    """
    if json_file:
        with open(json_file) as f:
            operations = json.load(f)
    elif json_data:
        try:
            operations = json.loads(json_data)
        except json.JSONDecodeError as e:
            click.echo(f"Error: invalid JSON: {e}", err=True)
            sys.exit(1)
    else:
        click.echo("Error: provide --json or --json-file.", err=True)
        sys.exit(1)

    _rpc_command(_resolve_project(project), "batch_rename", {
        "binary": binary, "operations": operations, "mode": mode,
    })


@cli.command(name="batch-set-comment")
@click.argument("binary")
@click.option(
    "--json", "json_data", default="",
    help="JSON array of comment operations (inline string).",
)
@click.option(
    "--json-file", "json_file", default=None,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Path to a JSON file containing the comment operations.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def batch_set_comment(
    binary: str,
    json_data: str, json_file: str,
    project: str | None,
):
    """Set comments at many addresses in one round-trip (one transaction).

    Accepts a JSON array via --json or --json-file.
    Each item: {"address": "0x...", "comment": "...", "comment_type": "eol"}.
    comment_type defaults to "eol"; valid: plate, pre, post, eol, repeatable.
    address can be a hex address or a function name.

    \b
    Example:
      [{"address": "0x03288102", "comment": "Thumb handler entry"},
       {"address": "init_uart",  "comment": "Called from main", "comment_type": "plate"}]
    """
    if json_file:
        with open(json_file) as f:
            operations = json.load(f)
    elif json_data:
        try:
            operations = json.loads(json_data)
        except json.JSONDecodeError as e:
            click.echo(f"Error: invalid JSON: {e}", err=True)
            sys.exit(1)
    else:
        click.echo("Error: provide --json or --json-file.", err=True)
        sys.exit(1)

    _rpc_command(_resolve_project(project), "batch_set_comment", {
        "binary": binary, "operations": operations,
    })


@cli.command(name="get-processor-context")
@click.argument("binary")
@click.argument("address")
@click.option(
    "--register", "-r", default="",
    help="Show only this register (e.g. TMode). Default: all context registers.",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def get_processor_context(
    binary: str, address: str, register: str, project: str | None
):
    """Inspect ISA context register values at an address.

    Useful for diagnosing why bytes aren't decoded as the expected ISA
    (e.g. TMode=0 on ARM Thumb code that should be TMode=1).

    Example (ARM firmware):
      ghidra-rpc get-processor-context binary 0x03288100 --register TMode
    """
    args: dict = {"binary": binary, "address": address}
    if register:
        args["register"] = register
    _rpc_command(_resolve_project(project), "get_processor_context", args)


@cli.command(name="set-processor-context")
@click.argument("binary")
@click.argument("address")
@click.argument("register")
@click.argument("value", type=int)
@click.option(
    "--end", "end_addr", default="",
    help="End address (inclusive). Defaults to ADDRESS (single address).",
)
@click.option("--project", "-p", type=str, help="Path to .gpr project file")
def set_processor_context(
    binary: str, address: str, register: str, value: int,
    end_addr: str, project: str | None,
):
    """Set an ISA context register at an address or range.

    CRITICAL for ARM firmware RE: after clearing a mis-classified data
    range, set TMode=1 before re-disassembling so the SLEIGH disassembler
    decodes the bytes as Thumb-2 instead of ARM.

    \b
    ARM Thumb recovery workflow:
      1. clear-data-range         binary 0x03288100 0x032883ff
      2. set-processor-context    binary 0x03288100 TMode 1 --end 0x032883ff
      3. disassemble              binary 0x03288100 --count 40
      4. create-function          binary 0x03288100
    """
    args: dict = {
        "binary": binary, "address": address,
        "register": register, "value": value,
    }
    if end_addr:
        args["end"] = end_addr
    _rpc_command(_resolve_project(project), "set_processor_context", args)


# \u2500\u2500\u2500 RPC dispatch helper \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

def _rpc_command(gpr: Path, cmd: str, args: dict, socket_timeout: float | None = None) -> None:
    """Send a command to the daemon, with auto-restart on failure.

    ``socket_timeout``, when given, overrides the client's automatic
    per-command timeout derivation (see ``client._derive_socket_timeout``).
    Needed for bulk sweep commands (e.g. decompile-all, search-decompiled)
    where the wall-clock cost scales with the number of functions in the
    binary, not with the per-function ``timeout`` argument alone.
    """
    from ghidra_rpc.client import send_request_with_auto_restart

    try:
        response = send_request_with_auto_restart(gpr, cmd, args, socket_timeout=socket_timeout)
        # Warn on stderr if a write operation returned verified: false so
        # scripted workflows don't silently ignore failed mutations.
        result = response.get("result", {})
        if isinstance(result, dict) and result.get("verified") is False:
            click.echo(
                f"Warning: {cmd} returned verified=false — the change may "
                f"not have taken effect. Check the result.",
                err=True,
            )
        _json_output(response)
    except DaemonNotRunning as e:
        _json_error("DaemonNotRunning", str(e))
    except DaemonError as e:
        click.echo(json.dumps(e.full_response, indent=2))
        sys.exit(1)
    except Exception as e:
        _json_error(type(e).__name__, str(e))


def main():
    """Entry point. Converts Click usage errors (bad options/args, unknown
    subcommands, etc.) to the same JSON error envelope as RPC failures, so
    scripted callers never have to handle a plain-text usage message.
    """
    try:
        rv = cli(standalone_mode=False)
    except click.ClickException as e:
        click.echo(json.dumps({
            "ok": False,
            "error": type(e).__name__,
            "message": e.format_message(),
        }))
        sys.exit(e.exit_code)
    except click.exceptions.Abort:
        click.echo("Aborted!", err=True)
        sys.exit(1)
    else:
        sys.exit(rv if isinstance(rv, int) else 0)


if __name__ == "__main__":
    main()
