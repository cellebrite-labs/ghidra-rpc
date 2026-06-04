"""Tests for CLI argument handling."""

from __future__ import annotations

import pytest

from ghidra_rpc.cli import _resolve_project


def test_resolve_project_rejects_hidden_parent(tmp_path, capsys):
    gpr = tmp_path / ".analysis" / "bad.gpr"

    with pytest.raises(SystemExit) as exc:
        _resolve_project(str(gpr))

    assert exc.value.code == 1
    assert "hidden path elements" in capsys.readouterr().err


def test_resolve_project_rejects_hidden_project_name(tmp_path, capsys):
    gpr = tmp_path / ".bad.gpr"

    with pytest.raises(SystemExit) as exc:
        _resolve_project(str(gpr))

    assert exc.value.code == 1
    assert "hidden path elements" in capsys.readouterr().err


def test_resolve_project_accepts_normal_path(tmp_path):
    gpr = tmp_path / "analysis-ghidra-rpc" / "good.gpr"

    assert _resolve_project(str(gpr)) == gpr.resolve()


def test_resolve_project_validates_env_var(tmp_path, monkeypatch, capsys):
    gpr = tmp_path / ".analysis" / "bad.gpr"
    monkeypatch.setenv("GHIDRA_RPC_PROJECT", str(gpr))

    with pytest.raises(SystemExit) as exc:
        _resolve_project(None)

    assert exc.value.code == 1
    assert "hidden path elements" in capsys.readouterr().err
