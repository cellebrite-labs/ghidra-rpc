"""Unit tests for the shared address formatter/parser and _find_function's
address handling, using fake Ghidra objects -- no real Ghidra/JVM needed.
Round-tripping against real AddressFactory spaces is covered by
tests/test_integration.py.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from ghidra_rpc.server.context import _fmt_address, _looks_like_address


class _FakeSpace:
    def __init__(self, stack=False):
        self._stack = stack

    def isStackSpace(self):
        return self._stack


class _FakeAddress:
    """Stand-in for a Ghidra Address: str() is the space-qualified form,
    toString(False) the bare offset, mirroring GenericAddress."""

    def __init__(self, full, offset, stack=False):
        self._full, self._offset, self._space = full, offset, _FakeSpace(stack)

    def getAddressSpace(self):
        return self._space

    def toString(self, show_space):
        return self._offset

    def __str__(self):
        return self._full


class TestFmtAddress:
    def test_default_space(self):
        assert _fmt_address(_FakeAddress("00101139", "00101139")) == "0x00101139"

    def test_non_default_space(self):
        addr = _FakeAddress("register:00000020", "00000020")
        assert _fmt_address(addr) == "register:0x00000020"

    def test_overlay_space(self):
        addr = _FakeAddress("ov1::00001000", "00001000")
        assert _fmt_address(addr) == "ov1::0x00001000"

    def test_stack_unchanged(self):
        addr = _FakeAddress("Stack[-0x10]", "Stack[-0x10]", stack=True)
        assert _fmt_address(addr) == "Stack[-0x10]"

    def test_none(self):
        assert _fmt_address(None) is None


class TestLooksLikeAddress:
    @pytest.mark.parametrize("s", [
        "0x00101139", "0X401000", "register:0x20", "ov1::0x00001000",
        "EXTERNAL:0x00000001", " 0x10 ",
    ])
    def test_addresses(self, s):
        assert _looks_like_address(s)

    @pytest.mark.parametrize("s", [
        "00101139", "main", "FUN_00101139", "Foo::bar", "deadbeef",
        "0x", "0xZZ", "ov1::00001000", "Stack[-0x10]",
    ])
    def test_non_addresses(self, s):
        assert not _looks_like_address(s)


# ---------------------------------------------------------------------------
# _find_function
# ---------------------------------------------------------------------------

_DEFAULT, _USER = "DEFAULT", "USER_DEFINED"


@pytest.fixture(autouse=True)
def fake_source_type(monkeypatch):
    """_find_function imports SourceType inside the function (per the "never
    import ghidra.* at module level" rule) -- stub the module chain."""
    names = ["ghidra", "ghidra.program", "ghidra.program.model",
             "ghidra.program.model.symbol"]
    for name in names:
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["ghidra.program.model.symbol"].SourceType = types.SimpleNamespace(
        DEFAULT=_DEFAULT, USER_DEFINED=_USER)


def _func(name, source=_USER):
    f = MagicMock()
    f.getName.return_value = name
    f.getSymbol.return_value.getSource.return_value = source
    f.getEntryPoint.return_value = _FakeAddress("00001000", "00001000")
    return f


def _pi(functions, at=None):
    pi = MagicMock()
    fm = pi.program.getFunctionManager.return_value
    fm.getFunctions.return_value = functions
    fm.getFunctionAt.return_value = at
    fm.getFunctionContaining.return_value = None
    return pi


def _find(pi, target):
    from ghidra_rpc.server.tools.decompiler import _find_function
    return _find_function(pi, target)


class TestFindFunction:
    def test_0x_address_resolves_via_address_factory(self):
        target = _func("FUN_00101139", _DEFAULT)
        pi = _pi([], at=target)
        assert _find(pi, "0x00101139") is target
        pi.program.getAddressFactory.return_value.getAddress.assert_called_with("0x00101139")

    def test_space_qualified_address_is_an_address(self):
        target = _func("FUN_00001000", _DEFAULT)
        pi = _pi([], at=target)
        assert _find(pi, "ov1::0x00001000") is target
        pi.program.getAddressFactory.return_value.getAddress.assert_called_with("ov1::0x00001000")

    def test_address_with_no_function_raises_instead_of_name_matching(self):
        pi = _pi([_func("0x401000_lookalike")], at=None)
        with pytest.raises(ValueError, match="No function at or containing"):
            _find(pi, "0x401000")

    def test_bare_hex_does_not_partial_match_default_names(self):
        pi = _pi([_func("FUN_00101139", _DEFAULT), _func("FUN_00101200", _DEFAULT)])
        with pytest.raises(ValueError, match="0x prefix"):
            _find(pi, "00101139")

    def test_bare_hex_still_partial_matches_user_names(self):
        user = _func("add_numbers")
        pi = _pi([_func("FUN_00add000", _DEFAULT), user])
        assert _find(pi, "add") is user

    def test_ambiguity_error_lists_0x_addresses(self):
        pi = _pi([_func("helper_a"), _func("helper_b")])
        with pytest.raises(ValueError, match=r"@ 0x00001000"):
            _find(pi, "helper")
