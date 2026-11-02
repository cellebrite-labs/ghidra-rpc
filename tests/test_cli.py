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



class TestArgumentErrorsAsJson:
    """Argument errors the command bodies detect (bad JSON, non-integer values,
    unpaired tokens, no project) use the same JSON envelope as Click's own
    usage errors, never a traceback or a plain-text stderr message."""

    @pytest.fixture
    def no_rpc(self, monkeypatch):
        import ghidra_rpc.cli as cli_mod

        def fail(*args, **kwargs):
            raise AssertionError("argument error must be caught before any RPC")
        monkeypatch.setattr(cli_mod, "_rpc_command", fail)

    def _usage_error(self, monkeypatch, capsys, argv, tmp_path, *, project=True):
        if project:
            argv = argv + ["--project", str(tmp_path / "test.gpr")]
        code = _run_main(monkeypatch, argv)
        data = json.loads(capsys.readouterr().out)
        assert code == 2
        assert data["ok"] is False
        return data["message"]

    def test_malformed_json_file(self, monkeypatch, capsys, tmp_path, no_rpc):
        bad = tmp_path / "ops.json"
        bad.write_text("{bad")
        for cmd in (["batch-rename", "b"], ["batch-set-comment", "b"],
                    ["batch-edit-variable", "b", "f"]):
            msg = self._usage_error(monkeypatch, capsys,
                                    cmd + ["--json-file", str(bad)], tmp_path)
            assert "--json-file" in msg

    def test_malformed_inline_json(self, monkeypatch, capsys, tmp_path, no_rpc):
        msg = self._usage_error(monkeypatch, capsys,
                                ["batch-rename", "b", "--json", "{bad"], tmp_path)
        assert "invalid JSON" in msg

    def test_missing_json(self, monkeypatch, capsys, tmp_path, no_rpc):
        msg = self._usage_error(monkeypatch, capsys, ["batch-set-comment", "b"], tmp_path)
        assert "--json-file" in msg

    def test_non_integer_enum_value(self, monkeypatch, capsys, tmp_path, no_rpc):
        msg = self._usage_error(monkeypatch, capsys,
                                ["create-enum", "b", "E", "A", "zz"], tmp_path)
        assert "'zz' is not a valid integer" in msg

    def test_non_integer_modify_enum_value(self, monkeypatch, capsys, tmp_path, no_rpc):
        msg = self._usage_error(monkeypatch, capsys,
                                ["modify-enum", "b", "E", "--add", "A:zz"], tmp_path)
        assert "'zz' is not a valid integer" in msg

    def test_non_integer_equate_value(self, monkeypatch, capsys, tmp_path, no_rpc):
        msg = self._usage_error(monkeypatch, capsys,
                                ["set-equate", "b", "0x1", "N", "zz"], tmp_path)
        assert "'zz' is not a valid integer" in msg

    def test_unpaired_fields(self, monkeypatch, capsys, tmp_path, no_rpc):
        msg = self._usage_error(monkeypatch, capsys,
                                ["create-union", "b", "U", "int"], tmp_path)
        assert "pairs of TYPE NAME" in msg

    def test_no_project(self, monkeypatch, capsys, tmp_path, no_rpc):
        monkeypatch.delenv("GHIDRA_RPC_PROJECT", raising=False)
        msg = self._usage_error(monkeypatch, capsys, ["imports", "b"], tmp_path,
                                project=False)
        assert "No project specified" in msg

    def test_hex_values_still_parse(self, monkeypatch, tmp_path):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured[cmd] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)
        gpr = ["--project", str(tmp_path / "test.gpr")]
        runner = CliRunner()
        assert runner.invoke(cli, ["create-enum", "b", "E", "A", "0x81"] + gpr).exit_code == 0
        assert runner.invoke(cli, ["set-equate", "b", "0x1", "N", "0x81"] + gpr).exit_code == 0
        assert runner.invoke(cli, ["modify-enum", "b", "E", "--add", "A:0"] + gpr).exit_code == 0
        assert captured["create_enum"]["values"] == [{"name": "A", "value": 0x81}]
        assert captured["set_equate"]["value"] == 0x81
        assert captured["modify_enum"]["add"] == [{"name": "A", "value": 0}]

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


class TestSearchDecompiledOptions:
    """--address-min/--address-max are forwarded to the RPC args."""

    def _invoke(self, tmp_path, monkeypatch, *extra):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)

        result = CliRunner().invoke(
            cli, ["search-decompiled", "bin", "target", *extra,
                  "--project", str(tmp_path / "test.gpr")]
        )
        assert result.exit_code == 0
        return captured

    def test_address_range_forwarded(self, tmp_path, monkeypatch):
        captured = self._invoke(tmp_path, monkeypatch,
                                "--address-min", "0x1000", "--address-max", "0x2000")
        assert captured["args"]["address_min"] == "0x1000"
        assert captured["args"]["address_max"] == "0x2000"

    def test_address_range_omitted_by_default(self, tmp_path, monkeypatch):
        captured = self._invoke(tmp_path, monkeypatch)
        assert "address_min" not in captured["args"]
        assert "address_max" not in captured["args"]


class TestDisassembleWithInstructions:
    """--with-instructions flag parsing and forwarding test."""

    def test_with_instructions_default_is_false(self, tmp_path, monkeypatch):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)

        result = CliRunner().invoke(
            cli, ["disassemble", "bin", "0x1000", "--project", str(tmp_path / "test.gpr")]
        )
        assert result.exit_code == 0
        assert captured["args"]["with_instructions"] is False

    def test_with_instructions_flag_passed_as_true(self, tmp_path, monkeypatch):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)

        result = CliRunner().invoke(
            cli, ["disassemble", "bin", "0x1000", "--with-instructions",
                  "--project", str(tmp_path / "test.gpr")]
        )
        assert result.exit_code == 0
        assert captured["args"]["with_instructions"] is True


class TestNegativeValues:
    """set-equate VALUE and create-enum NAME VALUE pairs accept negative numbers
    (error codes like -1), which Click would otherwise parse as options, while
    a mistyped option still fails instead of becoming a name."""

    def _invoke(self, monkeypatch, capsys, argv):
        captured = {}

        def fake_rpc_command(gpr, cmd, args, socket_timeout=None):
            captured["args"] = args

        import ghidra_rpc.cli as cli_mod
        monkeypatch.setattr(cli_mod, "_rpc_command", fake_rpc_command)
        monkeypatch.setattr(cli_mod, "_resolve_project", lambda p: "P")
        monkeypatch.setattr(sys, "argv", ["ghidra-rpc"] + argv)
        try:
            main()
        except SystemExit as e:
            return e.code, captured, capsys.readouterr().out
        return 0, captured, capsys.readouterr().out

    def test_set_equate_negative_value(self, monkeypatch, capsys):
        code, captured, _ = self._invoke(monkeypatch, capsys, [
            "set-equate", "bin", "0x10", "ERR_FAIL", "-1", "--operand-index", "2"])
        assert code == 0
        assert captured["args"]["value"] == -1
        assert captured["args"]["operand_index"] == 2

    def test_create_enum_negative_values(self, monkeypatch, capsys):
        code, captured, _ = self._invoke(monkeypatch, capsys, [
            "create-enum", "bin", "Status", "FAIL", "-1", "BAD", "-0x10", "OK", "0",
            "--size", "4"])
        assert code == 0
        assert captured["args"]["values"] == [
            {"name": "FAIL", "value": -1}, {"name": "BAD", "value": -16},
            {"name": "OK", "value": 0}]
        assert captured["args"]["size"] == 4

    @pytest.mark.parametrize("argv", [
        ["set-equate", "bin", "0x10", "--typo", "5"],
        ["create-enum", "bin", "Status", "FAIL", "-1", "--siz", "4"],
        ["create-enum", "bin", "Status", "FAIL", "1", "--if-not-exist"],
    ])
    def test_mistyped_option_is_still_a_json_usage_error(self, monkeypatch, capsys, argv):
        code, captured, out = self._invoke(monkeypatch, capsys, argv)
        assert code == 2
        assert captured == {}
        data = json.loads(out)
        assert data["ok"] is False and "No such option" in data["message"]
