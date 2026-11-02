"""Unit tests for GUI-mode calls not blocking on Ghidra's modal dialogs.

Both bugs were found verifying Ghidra 12.2 and reproduce on 12.0.4/12.1 too;
each left the daemon stuck until someone clicked a dialog on the desktop.

* ``GuiContext.load_binary`` opens the imported program in CodeBrowser, which
  shows a modal "Analyze now?" dialog on the Swing thread for an unanalyzed
  program.  The fix flags the program with
  ``GhidraProgramUtilities.markProgramNotToAskToAnalyze`` before it is saved
  and opened; the tests check the flag is set, *before* the tool opens it.
* Every ``load`` launches its own CodeBrowser; closing the project with more
  than one changed instance makes Ghidra ask "Save Tool Changes?".  ``close``
  marks such duplicate instances unchanged before requesting the shutdown.

Ghidra classes are faked (no Ghidra needed).
"""

import sys
import threading
import types

import pytest

from ghidra_rpc.server.context import (
    GuiContext,
    _clear_duplicate_tool_changes,
    _suppress_analyze_prompt,
)


def _install_fake_modules(monkeypatch, mods: dict[str, dict]):
    """Register fake module chains, e.g. {"ghidra.util.task": {"TaskMonitor": ...}}."""
    for dotted, attrs in mods.items():
        parts = dotted.split(".")
        for i in range(1, len(parts) + 1):
            name = ".".join(parts[:i])
            if name not in sys.modules or name in mods:
                monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        for attr, value in attrs.items():
            setattr(sys.modules[dotted], attr, value)


class TestSuppressAnalyzePrompt:
    def test_marks_program_not_to_ask(self, monkeypatch):
        marked = []
        utils = types.SimpleNamespace(markProgramNotToAskToAnalyze=marked.append)
        _install_fake_modules(
            monkeypatch, {"ghidra.program.util": {"GhidraProgramUtilities": utils}}
        )
        program = object()

        _suppress_analyze_prompt(program)

        assert marked == [program]

    def test_noop_when_ghidra_lacks_the_method(self, monkeypatch):
        _install_fake_modules(
            monkeypatch,
            {"ghidra.program.util": {"GhidraProgramUtilities": types.SimpleNamespace()}},
        )

        _suppress_analyze_prompt(object())  # must not raise


class TestLoadBinaryOrdering:
    def test_prompt_suppressed_before_save_and_tool_launch(self, monkeypatch, tmp_path):
        events = []
        program = object()

        class _Loaded:
            def getDomainObject(self):
                return program

            def save(self, monitor):
                events.append("save")
                return "domain-file"

        class _Results:
            def getPrimary(self):
                return _Loaded()

            def close(self):
                events.append("close")

        class _Builder:
            def __getattr__(self, name):
                if name == "load":
                    return lambda: _Results()
                return lambda *a, **kw: self

        utils = types.SimpleNamespace(
            markProgramNotToAskToAnalyze=lambda p: events.append(("mark", p))
        )
        _install_fake_modules(
            monkeypatch,
            {
                "ghidra.program.util": {"GhidraProgramUtilities": utils},
                "ghidra.app.util.importer": {
                    "ProgramLoader": types.SimpleNamespace(builder=_Builder)
                },
                "ghidra.util.task": {"TaskMonitor": types.SimpleNamespace(DUMMY=object())},
                "java.io": {"File": lambda p: p},
                "java.util": {"List": types.SimpleNamespace(of=lambda *a: list(a))},
            },
        )

        binary = tmp_path / "prog.bin"
        binary.write_bytes(b"\x7fELF-not-really")

        ctx = GuiContext.__new__(GuiContext)
        ctx.programs = {}
        ctx._programs_lock = threading.RLock()
        tool_services = types.SimpleNamespace(
            launchDefaultTool=lambda files: events.append("launch")
        )
        ctx.project = types.SimpleNamespace(getToolServices=lambda: tool_services)

        def fake_refresh():
            # Pretend CodeBrowser opened the program so load_binary stops waiting.
            ctx.programs[expected_key] = types.SimpleNamespace(analysis_complete=False)

        ctx.refresh_programs = fake_refresh
        from ghidra_rpc.server.context import _gen_unique_bin_name

        expected_key = f"/{_gen_unique_bin_name(binary)}"

        key = ctx.load_binary(str(binary), analyze=False)

        assert key == expected_key
        assert events == [("mark", program), "save", "close", "launch"]


class _FakeTool:
    def __init__(self, template: str):
        self.template = template
        self.changed = True

    def getToolName(self):
        return self.template

    def setConfigChanged(self, changed):
        self.changed = changed


class TestClearDuplicateToolChanges:
    def test_clears_every_instance_when_a_template_runs_twice(self):
        a, b = _FakeTool("CodeBrowser"), _FakeTool("CodeBrowser")

        _clear_duplicate_tool_changes([a, b])

        assert (a.changed, b.changed) == (False, False)

    def test_single_instance_left_for_ghidra_to_save_silently(self):
        only = _FakeTool("CodeBrowser")

        _clear_duplicate_tool_changes([only])

        assert only.changed is True

    def test_only_duplicated_templates_are_cleared(self):
        cb1, cb2 = _FakeTool("CodeBrowser"), _FakeTool("CodeBrowser")
        other = _FakeTool("VersionTracking")

        _clear_duplicate_tool_changes([cb1, other, cb2])

        assert (cb1.changed, cb2.changed, other.changed) == (False, False, True)

    def test_no_tools(self):
        _clear_duplicate_tool_changes([])  # must not raise


class TestCloseClearsToolPrompts:
    def test_tool_flags_cleared_before_shutdown_requested(self, monkeypatch):
        events = []
        tools = [_FakeTool("CodeBrowser"), _FakeTool("CodeBrowser")]
        for t in tools:
            t.setConfigChanged = lambda changed, t=t: events.append(("clear", t))

        project = types.SimpleNamespace(
            getToolServices=lambda: types.SimpleNamespace(getRunningTools=lambda: tools)
        )
        app_info = types.SimpleNamespace(getActiveProject=lambda: project)
        _install_fake_modules(
            monkeypatch, {"ghidra.framework.main": {"AppInfo": app_info}}
        )

        ctx = GuiContext.__new__(GuiContext)
        ctx.programs = {}
        ctx._own_programs = {}
        ctx._programs_lock = threading.RLock()
        ctx.project = project
        ctx.run_on_swing = lambda fn: fn()
        ctx.launcher = types.SimpleNamespace(
            request_shutdown=lambda: events.append("shutdown")
        )

        ctx.close()

        assert events == [("clear", tools[0]), ("clear", tools[1]), "shutdown"]

    def test_failure_clearing_flags_does_not_block_shutdown(self, monkeypatch):
        events = []
        _install_fake_modules(
            monkeypatch,
            {"ghidra.framework.main": {"AppInfo": types.SimpleNamespace()}},
        )
        ctx = GuiContext.__new__(GuiContext)
        ctx.programs = {}
        ctx._own_programs = {}
        ctx._programs_lock = threading.RLock()
        ctx.project = None
        ctx.run_on_swing = lambda fn: fn()  # AppInfo has no getActiveProject -> raises
        ctx.launcher = types.SimpleNamespace(
            request_shutdown=lambda: events.append("shutdown")
        )

        ctx.close()

        assert events == ["shutdown"]
