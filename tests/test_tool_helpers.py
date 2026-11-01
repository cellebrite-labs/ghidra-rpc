"""Unit tests for tool-handler helpers and argument validation (no Ghidra needed).

Two kinds of logic live here, both reachable without a JVM:

* Pure helpers (``_normalise_decompiled``, ``_normalise_disassembly``,
  ``_sanitize_signature``, ``_format_hexdump``).
* Argument validation that handlers perform *before* they resolve a program
  (``write_bytes``, ``assemble``, ``function_diff``, ``decompile_all``,
  ``goto``) -- each test also asserts the program was never looked up, so a
  bad request can't have touched Ghidra state.

Behavior against a real program is covered by tests/test_integration.py.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from ghidra_rpc.server.tools.disassembly import _handle_assemble
from ghidra_rpc.server.tools.memory import _format_hexdump, _handle_write_bytes
from ghidra_rpc.server.tools.modifications import _sanitize_signature
from ghidra_rpc.server.tools.navigation import _handle_goto
from ghidra_rpc.server.tools.version_tracking import (
    _handle_decompile_all,
    _handle_function_diff,
    _normalise_decompiled,
    _normalise_disassembly,
)


# ── _normalise_decompiled ─────────────────────────────────────────────────────

class TestNormaliseDecompiled:
    def test_auto_generated_names_are_replaced(self):
        code = (
            "int FUN_00101298(long param_1)\n"
            "{\n"
            "  int local_c;\n"
            "  long lVar1;\n"
            "  local_c = DAT_00104028;\n"
            "  goto LAB_0010129f;\n"
            "}\n"
        )
        out = _normalise_decompiled(code)
        assert "FUN_ADDR" in out and "FUN_00101298" not in out
        assert "param_X" in out and "param_1" not in out
        assert "local_X" in out and "local_c" not in out
        assert "xVarN" in out and "lVar1" not in out
        assert "DAT_ADDR" in out and "DAT_00104028" not in out
        assert "LAB_ADDR" in out and "LAB_0010129f" not in out

    def test_user_assigned_names_are_preserved(self):
        code = "int my_func(int count)\n{\n  return count_char(buf, 0x1f);\n}\n"
        assert _normalise_decompiled(code) == code

    def test_long_hex_literals_become_addr_but_small_constants_stay(self):
        out = _normalise_decompiled("p = 0x00101298; n = 0x1f; m = 0xffff;")
        assert out == "p = 0xADDR; n = 0x1f; m = 0xffff;"

    def test_idempotent(self):
        once = _normalise_decompiled("FUN_00101298(param_1, local_8, 0x00101298)")
        assert _normalise_decompiled(once) == once

    def test_relocated_copies_normalise_to_the_same_text(self):
        """The point of the helper: two builds that differ only in layout diff clean."""
        a = "void FUN_00101298(int param_1)\n{\n  local_10 = DAT_00104028;\n}\n"
        b = "void FUN_00401500(int param_2)\n{\n  local_18 = DAT_00605040;\n}\n"
        assert _normalise_decompiled(a) == _normalise_decompiled(b)


# ── _normalise_disassembly ────────────────────────────────────────────────────

class TestNormaliseDisassembly:
    def test_addresses_are_replaced(self):
        out = _normalise_disassembly("CALL 0x00101298\nLEA RAX,[0x102092]\nJMP 001014c2")
        assert out == "CALL 0xADDR\nLEA RAX,[0xADDR]\nJMP ADDR"

    def test_small_immediates_are_kept(self):
        code = "MOV EAX,0x5\nCMP dword ptr [RBP + -0x4],0x6\nAND EAX,0xff"
        assert _normalise_disassembly(code) == code

    def test_relocated_copies_normalise_to_the_same_text(self):
        a = "CALL 0x00101298\nMOV EAX,0x5"
        b = "CALL 0x00401500\nMOV EAX,0x5"
        assert _normalise_disassembly(a) == _normalise_disassembly(b)

    def test_changed_constant_survives_normalisation(self):
        """A real patch (different immediate) must still show up as a diff."""
        a = _normalise_disassembly("MOV dword ptr [RBP + -0x4],0x0")
        b = _normalise_disassembly("MOV dword ptr [RBP + -0x4],0x5")
        assert a != b


# ── _sanitize_signature ───────────────────────────────────────────────────────

class TestSanitizeSignature:
    def test_plain_signature_is_unchanged(self):
        assert _sanitize_signature("int add(int a, int b)") == ("int add(int a, int b)", None)

    def test_strips_whitespace_and_trailing_semicolon(self):
        assert _sanitize_signature("  int add(int a, int b) ;  ") == (
            "int add(int a, int b)", None
        )

    def test_extracts_inline_calling_convention(self):
        sig, cc = _sanitize_signature("void __thiscall Foo::bar(int x);")
        assert (sig, cc) == ("void Foo::bar(int x)", "__thiscall")

    def test_extracts_convention_at_start_of_string(self):
        sig, cc = _sanitize_signature("__fastcall int f(int a)")
        assert (sig, cc) == ("int f(int a)", "__fastcall")

    @pytest.mark.parametrize("cc", [
        "__thiscall", "__fastcall", "__stdcall", "__cdecl", "__vectorcall", "__pascal",
    ])
    def test_every_known_convention_is_recognised(self, cc):
        sig, found = _sanitize_signature(f"int {cc} f(int a)")
        assert (sig, found) == ("int f(int a)", cc)

    def test_identifier_containing_a_convention_is_not_mangled(self):
        sig, cc = _sanitize_signature("int my__thiscall_helper(int a)")
        assert (sig, cc) == ("int my__thiscall_helper(int a)", None)


# ── _format_hexdump ───────────────────────────────────────────────────────────

class _FakeStart:
    def __init__(self, offset):
        self._offset = offset

    def getUnsignedOffset(self):
        return self._offset


class TestFormatHexdump:
    def test_full_line_matches_documented_format(self):
        data = b"%10s\x00C3ll3br1te\x00"
        assert len(data) == 16
        assert _format_hexdump(_FakeStart(0x102039), data) == (
            "0x00102039  25 31 30 73 00 43 33 6c  6c 33 62 72 31 74 65 00  "
            "|%10s.C3ll3br1te.|"
        )

    def test_partial_last_line_is_padded_so_columns_align(self):
        lines = _format_hexdump(_FakeStart(0x1000), bytes(range(0x41, 0x41 + 20))).split("\n")
        assert len(lines) == 2
        # Both lines put the ASCII gutter at the same column.
        assert lines[0].index("|") == lines[1].index("|")
        assert lines[1].endswith("|QRST|")

    def test_line_addresses_advance_by_width(self):
        lines = _format_hexdump(_FakeStart(0x2000), b"\x00" * 40).split("\n")
        assert [l[:10] for l in lines] == ["0x00002000", "0x00002010", "0x00002020"]

    def test_non_printable_bytes_render_as_dots(self):
        out = _format_hexdump(_FakeStart(0), b"\x00\x1f\x7f\x80A~")
        assert out.endswith("|....A~|")

    def test_second_group_is_empty_for_short_input(self):
        out = _format_hexdump(_FakeStart(0), b"ABC")
        assert out.startswith("0x00000000  41 42 43")
        assert out.endswith("|ABC|")


# ── write_bytes validation ────────────────────────────────────────────────────

def _ctx():
    return MagicMock()


class TestWriteBytesValidation:
    @pytest.mark.parametrize("args, fragment", [
        ({"hex": "90"}, "address"),
        ({"address": "0x1000"}, "hex"),
        ({"address": "0x1000", "hex": "9"}, "even number"),
        ({"address": "0x1000", "hex": "9 0 9"}, "even number"),
        ({"address": "0x1000", "hex": "zz"}, "Invalid hex"),
        ({"address": "0x1000", "hex": "  "}, "At least 1 byte"),
        ({"address": "0x1000", "hex": "00" * 4097}, "4096"),
    ])
    def test_bad_request_is_rejected_before_touching_the_program(self, args, fragment):
        ctx = _ctx()
        with pytest.raises(ValueError, match=fragment):
            _handle_write_bytes(ctx, {"binary": "bin", **args})
        ctx.get_program.assert_not_called()
        ctx.save_program.assert_not_called()

    def test_size_limit_is_inclusive_at_4096(self):
        """4096 bytes passes validation (it then fails on the mock program, not on size)."""
        ctx = _ctx()
        ctx.get_program.side_effect = RuntimeError("reached program lookup")
        with pytest.raises(RuntimeError, match="reached program lookup"):
            _handle_write_bytes(ctx, {"binary": "b", "address": "0x1000", "hex": "00" * 4096})


# ── assemble validation ───────────────────────────────────────────────────────

class TestAssembleValidation:
    @pytest.mark.parametrize("args, fragment", [
        ({"instructions": ["NOP"]}, "address"),
        ({"address": "0x1000"}, "instructions"),
        ({"address": "0x1000", "instructions": []}, "instructions"),
        ({"address": "0x1000", "instructions": "NOP"}, "must be a list"),
    ])
    def test_bad_request_is_rejected_before_touching_the_program(self, args, fragment):
        ctx = _ctx()
        with pytest.raises(ValueError, match=fragment):
            _handle_assemble(ctx, {"binary": "bin", **args})
        ctx.get_program.assert_not_called()
        ctx.save_program.assert_not_called()


# ── function_diff / decompile_all validation ──────────────────────────────────

class TestFunctionDiffValidation:
    _good = {"binary1": "a", "func1": "f", "binary2": "b", "func2": "f"}

    def test_invalid_mode_is_rejected(self):
        ctx = _ctx()
        with pytest.raises(ValueError, match="Invalid mode 'bogus'"):
            _handle_function_diff(ctx, {**self._good, "mode": "bogus"})
        ctx.get_program.assert_not_called()

    @pytest.mark.parametrize("missing", ["binary1", "func1", "binary2", "func2"])
    def test_each_required_argument_is_enforced(self, missing):
        ctx = _ctx()
        args = {k: v for k, v in self._good.items() if k != missing}
        with pytest.raises(ValueError, match="Missing required arguments"):
            _handle_function_diff(ctx, args)
        ctx.get_program.assert_not_called()


@pytest.fixture
def fake_ghidra_util_task(monkeypatch):
    """decompile_all imports ``ghidra.util.task`` inside the handler (the
    "no ghidra.* at module level" rule), so stub the chain for the call."""
    ghidra = types.ModuleType("ghidra")
    util = types.ModuleType("ghidra.util")
    task = types.ModuleType("ghidra.util.task")
    task.TaskMonitor = types.SimpleNamespace(DUMMY=object())
    monkeypatch.setitem(sys.modules, "ghidra", ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.util", util)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task)


class TestDecompileAllValidation:
    def test_missing_binary_is_rejected(self, fake_ghidra_util_task):
        ctx = _ctx()
        with pytest.raises(ValueError, match="binary"):
            _handle_decompile_all(ctx, {})
        ctx.get_program.assert_not_called()


# ── goto (GUI-only) ───────────────────────────────────────────────────────────

class TestGotoHeadless:
    def test_headless_context_gets_a_clear_gui_only_error(self):
        headless = types.SimpleNamespace()   # HeadlessContext has no `goto`
        with pytest.raises(RuntimeError, match="only available in GUI mode"):
            _handle_goto(headless, {"binary": "bin", "target": "main"})

    def test_missing_target_is_rejected_first(self):
        gui = MagicMock()
        with pytest.raises(ValueError, match="target"):
            _handle_goto(gui, {"binary": "bin"})
        gui.goto.assert_not_called()

    def test_gui_context_receives_the_request(self):
        gui = MagicMock()
        gui.goto.return_value = {"navigated": True}
        assert _handle_goto(gui, {"binary": "bin", "target": "main"}) == {"navigated": True}
        gui.goto.assert_called_once_with("bin", "main", "function")

    def test_target_type_is_forwarded(self):
        gui = MagicMock()
        _handle_goto(gui, {"binary": "bin", "target": "0x1000", "target_type": "address"})
        gui.goto.assert_called_once_with("bin", "0x1000", "address")
