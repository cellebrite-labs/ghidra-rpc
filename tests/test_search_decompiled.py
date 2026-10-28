"""Unit tests for search_decompiled's pure logic (regex matching, class_filter,
limit/max_functions truncation, coverage reporting) using a fully mocked Ghidra
program -- no real Ghidra/JVM needed. Server-side handling of *actual*
decompiler output is only exercised by tests/test_integration.py against a
real headless daemon.
"""

from __future__ import annotations

import sys
import types
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def fake_ghidra_util_task(monkeypatch):
    """search_decompiled does `from ghidra.util.task import TaskMonitor`
    inside the handler (per the "never import ghidra.* at module level"
    rule) -- stub the module chain so that import succeeds under test."""
    fake_task_monitor = types.SimpleNamespace(DUMMY=object())
    fake_ghidra = types.ModuleType("ghidra")
    fake_util = types.ModuleType("ghidra.util")
    fake_task = types.ModuleType("ghidra.util.task")
    fake_task.TaskMonitor = fake_task_monitor
    monkeypatch.setitem(sys.modules, "ghidra", fake_ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.util", fake_util)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", fake_task)


def _make_function(name, qualified_name, address, c_code,
                    external=False, thunk=False):
    func = MagicMock()
    func.isExternal.return_value = external
    func.isThunk.return_value = thunk
    func.getSymbol.return_value.getName.return_value = qualified_name
    func.getEntryPoint.return_value = address
    func._c_code = c_code
    func._name = name
    return func


def _make_pi(functions):
    """Build a fake ProgramInfo whose decompiler_pool echoes back each
    function's pre-baked C code (or raises, to simulate a decompile failure)."""
    pi = MagicMock()
    fm = MagicMock()
    fm.getFunctions.return_value = functions
    pi.program.getFunctionManager.return_value = fm

    @contextmanager
    def acquire():
        decompiler = MagicMock()

        def decompile_function(func, timeout, monitor):
            result = MagicMock()
            if func._c_code is None:
                result.getDecompiledFunction.return_value = None
            else:
                decompiled = MagicMock()
                decompiled.getC.return_value = func._c_code
                result.getDecompiledFunction.return_value = decompiled
            return result

        decompiler.decompileFunction.side_effect = decompile_function
        yield decompiler

    pi.decompiler_pool.acquire.side_effect = acquire
    return pi


def _make_ctx(pi):
    ctx = MagicMock()
    ctx.get_program.return_value = pi
    return ctx


class TestSearchDecompiled:
    def _handler(self):
        from ghidra_rpc.server.tools.decompiler import _handle_search_decompiled
        return _handle_search_decompiled

    def test_requires_binary_and_pattern(self):
        handler = self._handler()
        with pytest.raises(ValueError):
            handler(_make_ctx(_make_pi([])), {"pattern": "foo"})
        with pytest.raises(ValueError):
            handler(_make_ctx(_make_pi([])), {"binary": "bin"})

    def test_invalid_regex_raises_value_error(self):
        handler = self._handler()
        with pytest.raises(ValueError):
            handler(_make_ctx(_make_pi([])), {"binary": "bin", "pattern": "("})

    def test_matches_across_functions_case_insensitive_by_default(self):
        functions = [
            _make_function("f1", "f1", "0x1000", "void f1(void) { do_thing(); }"),
            _make_function("f2", "f2", "0x2000", "void f2(void) { OTHER(); }"),
            _make_function("f3", "f3", "0x3000", "void f3(void) { nothing_here(); }"),
        ]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "do_thing|other",
        })
        names = {m["function"] for m in result["matches"]}
        assert names == {"f1", "f2"}
        assert result["count"] == 2
        assert result["functions_searched"] == 3
        assert result["functions_total"] == 3
        assert result["truncated"] is False

    def test_matching_lines_include_line_numbers(self):
        c_code = "void f(void)\n{\n  target_call();\n}\n"
        functions = [_make_function("f", "f", "0x1000", c_code)]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target_call",
        })
        assert result["matches"][0]["matching_lines"] == [
            {"line": 3, "text": "target_call();"}
        ]

    def test_case_sensitive_when_ignore_case_false(self):
        functions = [_make_function("f", "f", "0x1000", "void f(void) { NEEDLE(); }")]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "needle", "ignore_case": False,
        })
        assert result["count"] == 0

    def test_class_filter_scopes_to_qualified_name_substring(self):
        functions = [
            _make_function("bar", "com::foo::Bar::bar", "0x1000", "void bar(void) { target(); }"),
            _make_function("baz", "com::other::Baz::baz", "0x2000", "void baz(void) { target(); }"),
        ]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target", "class_filter": "com::foo",
        })
        assert result["functions_total"] == 1
        assert result["matches"][0]["function"] == "com::foo::Bar::bar"

    def test_external_and_thunk_functions_are_skipped(self):
        functions = [
            _make_function("ext", "ext", "0x1000", "void ext(void) { target(); }", external=True),
            _make_function("thunk", "thunk", "0x2000", "void thunk(void) { target(); }", thunk=True),
            _make_function("real", "real", "0x3000", "void real(void) { target(); }"),
        ]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target",
        })
        assert result["functions_total"] == 1
        assert result["matches"][0]["function"] == "real"

    def test_decompile_failure_is_skipped_not_fatal(self):
        functions = [
            _make_function("bad", "bad", "0x1000", None),  # simulates decompile failure
            _make_function("good", "good", "0x2000", "void good(void) { target(); }"),
        ]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target",
        })
        assert result["count"] == 1
        assert result["matches"][0]["function"] == "good"
        assert result["functions_searched"] == 2

    def test_limit_truncates_and_sets_truncated_flag(self):
        functions = [
            _make_function(f"f{i}", f"f{i}", hex(i), "void f(void) { target(); }")
            for i in range(5)
        ]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target", "limit": 2,
        })
        assert result["count"] == 2
        assert result["truncated"] is True
        assert result["functions_total"] == 5

    def test_max_functions_caps_sweep_and_sets_truncated_flag(self):
        functions = [
            _make_function(f"f{i}", f"f{i}", hex(i), "void f(void) { no_match_here(); }")
            for i in range(10)
        ]
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target", "max_functions": 3,
        })
        assert result["functions_searched"] == 3
        assert result["truncated"] is True
        assert result["count"] == 0

    def test_zero_limit_or_max_functions_rejected(self):
        # Searching nothing would echo address_min back as
        # next_unscanned_address, so a resume loop would never end.
        handler = self._handler()
        for key in ("limit", "max_functions"):
            with pytest.raises(ValueError):
                handler(_make_ctx(_make_pi([])),
                        {"binary": "bin", "pattern": "x", key: 0})


class _FakeAddress:
    """Minimal stand-in for ghidra.program.model.address.Address."""

    def __init__(self, offset):
        self.offset = offset

    def compareTo(self, other):
        return (self.offset > other.offset) - (self.offset < other.offset)

    def __str__(self):
        return f"{self.offset:08x}"


class TestSearchDecompiledCoverage:
    """scanned_range / next_unscanned_address and address_min/max filtering."""

    @pytest.fixture(autouse=True)
    def fake_parse_address(self, monkeypatch):
        import ghidra_rpc.server.context as context
        monkeypatch.setattr(context, "_parse_address",
                            lambda program, s: _FakeAddress(int(s, 16)))

    def _handler(self):
        from ghidra_rpc.server.tools.decompiler import _handle_search_decompiled
        return _handle_search_decompiled

    def _functions(self, n, c_code="void f(void) { no_match_here(); }"):
        return [
            _make_function(f"f{i}", f"f{i}", _FakeAddress(0x1000 + 0x10 * i), c_code)
            for i in range(n)
        ]

    def test_complete_coverage(self):
        result = self._handler()(_make_ctx(_make_pi(self._functions(3))), {
            "binary": "bin", "pattern": "target",
        })
        assert result["scanned_range"] == {"min": "00001000", "max": "00001020"}
        assert result["next_unscanned_address"] is None

    def test_nothing_searched(self):
        result = self._handler()(_make_ctx(_make_pi([])), {
            "binary": "bin", "pattern": "target",
        })
        assert result["scanned_range"] is None
        assert result["next_unscanned_address"] is None

    def test_max_functions_truncation_reports_resume_point(self):
        result = self._handler()(_make_ctx(_make_pi(self._functions(10))), {
            "binary": "bin", "pattern": "target", "max_functions": 3,
        })
        assert result["scanned_range"] == {"min": "00001000", "max": "00001020"}
        assert result["next_unscanned_address"] == "00001030"

    def test_limit_truncation_reports_resume_point(self):
        functions = self._functions(5, "void f(void) { target(); }")
        result = self._handler()(_make_ctx(_make_pi(functions)), {
            "binary": "bin", "pattern": "target", "limit": 2,
        })
        assert result["scanned_range"] == {"min": "00001000", "max": "00001010"}
        assert result["next_unscanned_address"] == "00001020"

    def test_address_range_filters_candidates(self):
        result = self._handler()(_make_ctx(_make_pi(self._functions(10))), {
            "binary": "bin", "pattern": "target",
            "address_min": "0x1020", "address_max": "0x1040",
        })
        assert result["functions_total"] == 3
        assert result["scanned_range"] == {"min": "00001020", "max": "00001040"}
        assert result["next_unscanned_address"] is None

    def test_inverted_address_range_rejected(self):
        with pytest.raises(ValueError):
            self._handler()(_make_ctx(_make_pi(self._functions(3))), {
                "binary": "bin", "pattern": "target",
                "address_min": "0x2000", "address_max": "0x1000",
            })
