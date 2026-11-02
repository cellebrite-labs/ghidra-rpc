"""Unit tests for GuiContext's project-matching logic (no Ghidra needed).

Regression coverage for a real bug found while verifying GUI mode on Windows:
ProjectLocator.getLocation() returns a URL-derived path with a leading slash
before a Windows drive letter (e.g. "/C:/test/"), which pathlib misparses as
drive-relative rather than absolute, so the comparison in _project_matches
was unconditionally False on Windows -- _wait_for_project timed out on every
GUI-mode start, regardless of whether Ghidra opened the correct project.
"""

from pathlib import Path
from types import SimpleNamespace

from ghidra_rpc.server.context import GuiContext


def _make_locator(location: str, name: str):
    return SimpleNamespace(getLocation=lambda: location, getName=lambda: name)


def _make_project(location: str, name: str):
    return SimpleNamespace(getProjectLocator=lambda: _make_locator(location, name))


class TestNormalizeProjectLocation:
    def test_strips_leading_slash_before_windows_drive_letter(self):
        assert GuiContext._normalize_project_location("/C:/test/") == "C:/test/"

    def test_lowercase_drive_letter(self):
        assert GuiContext._normalize_project_location("/c:/test/") == "c:/test/"

    def test_backslash_variant(self):
        assert GuiContext._normalize_project_location("\\C:\\test\\") == "C:\\test\\"

    def test_posix_path_untouched(self):
        loc = "/tmp/ghidra-multi-test/projA/"
        assert GuiContext._normalize_project_location(loc) == loc

    def test_already_bare_drive_path_untouched(self):
        assert GuiContext._normalize_project_location("C:/test/") == "C:/test/"


class TestProjectMatches:
    def test_matches_windows_style_location(self, monkeypatch):
        monkeypatch.setattr(Path, "resolve", lambda self: self, raising=False)
        session = SimpleNamespace(project_gpr=Path("C:/test/gui2.gpr"))
        project = _make_project("/C:/test/", "gui2")
        assert GuiContext._project_matches(project, session) is True

    def test_rejects_different_project_name(self, monkeypatch):
        monkeypatch.setattr(Path, "resolve", lambda self: self, raising=False)
        session = SimpleNamespace(project_gpr=Path("C:/test/gui2.gpr"))
        project = _make_project("/C:/test/", "other")
        assert GuiContext._project_matches(project, session) is False

    def test_swallows_locator_exceptions(self):
        session = SimpleNamespace(project_gpr=Path("C:/test/gui2.gpr"))
        broken_project = SimpleNamespace(
            getProjectLocator=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        assert GuiContext._project_matches(broken_project, session) is False


# ── refresh_programs ──────────────────────────────────────────────────────────
# Regression coverage for a bug found in a live GUI check: closing the
# CodeBrowser that had a program open left the daemon serving that closed
# Program ("ClosedException: File is closed") until restart, and every
# refresh stacked another "ghidra-rpc" consumer on project-folder programs
# (Ghidra's addConsumer does not de-duplicate).

import sys  # noqa: E402
import threading  # noqa: E402
import types  # noqa: E402

import pytest  # noqa: E402


class _FakeProgram:
    def __init__(self, path):
        self.path = path
        self.closed = False
        self.releases = []

    def getDomainFile(self):
        return SimpleNamespace(getPathname=lambda: self.path)

    def isClosed(self):
        return self.closed

    def release(self, consumer):
        self.releases.append(consumer)

    def getFunctionManager(self):   # duck-typed "is a Program" check
        return None


class _FakeDomainFile:
    def __init__(self, path, program):
        self.path = path
        self.program = program
        self.opens = 0

    def getPathname(self):
        return self.path

    def getDomainObject(self, consumer, *_):
        self.opens += 1
        return self.program


class _FakePool:
    def __init__(self):
        self.disposed = False

    def dispose(self):
        self.disposed = True


class _World:
    """A fake active project: running tools' open programs + root-folder files."""

    def __init__(self):
        self.tool_programs = {}   # key -> program open in a tool
        self.files = {}           # key -> _FakeDomainFile in the root folder

    def project(self):
        world = self

        class _PM:
            def getAllOpenPrograms(self):
                return list(world.tool_programs.values())

        tool = types.SimpleNamespace(getService=lambda _svc: _PM())
        return types.SimpleNamespace(
            getToolServices=lambda: types.SimpleNamespace(getRunningTools=lambda: [tool]),
            getProjectData=lambda: types.SimpleNamespace(
                getRootFolder=lambda: types.SimpleNamespace(
                    getFiles=lambda: list(world.files.values())
                )
            ),
        )


@pytest.fixture
def gui(monkeypatch):
    world = _World()
    for name, attrs in {
        "ghidra": {},
        "ghidra.app": {},
        "ghidra.app.services": {"ProgramManager": object()},
        "ghidra.framework": {},
        "ghidra.framework.main": {
            "AppInfo": types.SimpleNamespace(getActiveProject=world.project)
        },
        "ghidra.util": {},
        "ghidra.util.task": {"TaskMonitor": types.SimpleNamespace(DUMMY=object())},
    }.items():
        mod = types.ModuleType(name)
        for attr, value in attrs.items():
            setattr(mod, attr, value)
        monkeypatch.setitem(sys.modules, name, mod)

    ctx = GuiContext.__new__(GuiContext)
    ctx.programs = {}
    ctx._own_programs = {}
    ctx._programs_lock = threading.RLock()
    ctx.project = None

    ctx._init_program_info = lambda program: SimpleNamespace(
        program=program, decompiler_pool=_FakePool())
    return ctx, world


class TestRefreshPrograms:
    def test_closed_tool_copy_is_replaced_by_the_project_copy(self, gui):
        ctx, world = gui
        tool_copy = _FakeProgram("/app")
        world.tool_programs["/app"] = tool_copy
        world.files["/app"] = _FakeDomainFile("/app", _FakeProgram("/app"))
        ctx.refresh_programs()
        old = ctx.programs["/app"]
        assert old.program is tool_copy
        ctx.refresh_programs()
        assert ctx.programs["/app"] is old   # unchanged program: entry kept
        assert world.files["/app"].opens == 0

        # User closes the CodeBrowser: Ghidra closes its copy of the program.
        tool_copy.closed = True
        del world.tool_programs["/app"]
        ctx.refresh_programs()

        assert ctx.programs["/app"].program is world.files["/app"].program
        assert old.decompiler_pool.disposed

    def test_project_file_is_opened_once_across_refreshes(self, gui):
        ctx, world = gui
        df = world.files["/app"] = _FakeDomainFile("/app", _FakeProgram("/app"))

        for _ in range(3):
            ctx.refresh_programs()

        assert df.opens == 1
        assert ctx.programs["/app"].program is df.program

    def test_own_consumer_released_when_the_file_goes_away(self, gui):
        ctx, world = gui
        program = _FakeProgram("/app")
        world.files["/app"] = _FakeDomainFile("/app", program)
        ctx.refresh_programs()

        del world.files["/app"]
        ctx.refresh_programs()

        assert "/app" not in ctx.programs
        assert program.releases == ["ghidra-rpc"]
        assert ctx._own_programs == {}

    def test_closed_own_copy_is_reopened(self, gui):
        ctx, world = gui
        first = _FakeProgram("/app")
        df = world.files["/app"] = _FakeDomainFile("/app", first)
        ctx.refresh_programs()

        first.closed = True
        df.program = _FakeProgram("/app")
        ctx.refresh_programs()

        assert df.opens == 2
        assert ctx.programs["/app"].program is df.program
