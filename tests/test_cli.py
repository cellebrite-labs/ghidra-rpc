"""CLI-level tests that don't need Ghidra or a running daemon.

Covers the ``main()`` entry point's error-handling contract (all output is
JSON, including Click usage errors) and a couple of argument-parsing
ergonomics fixes.
"""

from __future__ import annotations

import json
import sys

import pytest
from click.testing import CliRunner

from ghidra_rpc.cli import cli, main


def _run_main(monkeypatch, argv):
    """Invoke ghidra_rpc.cli.main() with argv patched, capturing SystemExit."""
    monkeypatch.setattr(sys, "argv", ["ghidra-rpc"] + argv)
    with pytest.raises(SystemExit) as exc_info:
        main()
    return exc_info.value.code


class TestUsageErrorsAsJson:
    """Click usage errors (bad options, unknown flags, bad choices) must come
    out as the same {"ok": false, ...} JSON envelope as RPC errors, not a
    plain-text usage string -- see ghidra-rpc-issues-20260705-122346.md #2."""

    def test_invalid_choice_reported_as_json(self, monkeypatch, capsys, tmp_path):
        gpr = tmp_path / "test.gpr"
        code = _run_main(monkeypatch, [
            "set-comment", "bin", "0x1000", "--comment", "hi",
            "--type", "not-a-real-type",
            "--project", str(gpr),
        ])
        assert code == 2
        out = capsys.readouterr().out
        data = json.loads(out)  # must not raise -- this is the whole point
        assert data["ok"] is False
        assert "error" in data and "message" in data

    def test_unknown_option_reported_as_json(self, monkeypatch, capsys, tmp_path):
        gpr = tmp_path / "test.gpr"
        code = _run_main(monkeypatch, [
            "set-comment", "bin", "0x1000", "--comment", "hi",
            "--this-flag-does-not-exist",
            "--project", str(gpr),
        ])
        assert code == 2
        data = json.loads(capsys.readouterr().out)
        assert data["ok"] is False

    def test_help_still_exits_zero_and_prints_text(self, monkeypatch, capsys):
        code = _run_main(monkeypatch, ["--help"])
        assert code == 0
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_version_still_exits_zero(self, monkeypatch, capsys):
        code = _run_main(monkeypatch, ["--version"])
        assert code == 0


class TestSetCommentUsesCommentOption:
    """COMMENT is passed via --comment (matching set-bookmark's --comment
    option), not positionally -- see ghidra-rpc-issues-20260705-122346.md #1."""

    def test_dash_dash_comment_parses(self, tmp_path):
        gpr = tmp_path / "nonexistent.gpr"
        result = CliRunner().invoke(
            cli, ["set-comment", "bin", "0x1000", "--comment", "hello", "--project", str(gpr)]
        )
        # No daemon is running for this project, so we expect a clean
        # DaemonNotRunning JSON error -- proof the args parsed successfully
        # and reached RPC dispatch, not a Click usage error.
        data = json.loads(result.output)
        assert data["ok"] is False
        assert data["error"] == "DaemonNotRunning"

    def test_missing_comment_is_a_usage_error(self, tmp_path):
        gpr = tmp_path / "nonexistent.gpr"
        result = CliRunner().invoke(
            cli, ["set-comment", "bin", "0x1000", "--project", str(gpr)]
        )
        assert result.exit_code != 0

    def test_positional_comment_no_longer_accepted(self, tmp_path):
        gpr = tmp_path / "nonexistent.gpr"
        result = CliRunner().invoke(
            cli, ["set-comment", "bin", "0x1000", "positional-text", "--project", str(gpr)]
        )
        assert result.exit_code != 0


class TestListBookmarksCategoryFilter:
    """--category must be accepted and forwarded -- see report item #3."""

    def test_category_flag_forwarded_to_rpc_args(self, tmp_path, monkeypatch):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)

        result = CliRunner().invoke(
            cli, ["list-bookmarks", "bin", "--category", "BLE-Protocol",
                  "--project", str(tmp_path / "test.gpr")]
        )
        assert result.exit_code == 0
        assert captured["args"]["category"] == "BLE-Protocol"


class TestDisassembleVerboseList:
    """--verbose-list flag parsing and forwarding test."""

    def test_verbose_list_default_is_false(self, tmp_path, monkeypatch):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)

        result = CliRunner().invoke(
            cli, ["disassemble", "bin", "0x1000", "--project", str(tmp_path / "test.gpr")]
        )
        assert result.exit_code == 0
        assert captured["args"]["verbose_list"] is False

    def test_verbose_list_flag_passed_as_true(self, tmp_path, monkeypatch):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)

        result = CliRunner().invoke(
            cli, ["disassemble", "bin", "0x1000", "--verbose-list", "--project", str(tmp_path / "test.gpr")]
        )
        assert result.exit_code == 0
        assert captured["args"]["verbose_list"] is True

