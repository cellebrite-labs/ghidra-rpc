"""Tests for the global session registry and instance discovery.

These tests cover:
  - _registry_path() resolution (env vars, platform defaults)
  - register() / unregister() / load_all() round-trips
  - _discover_instances() discovery logic
  - list-instances and stop --all CLI commands
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ghidra_rpc.session import (
    Session,
    _registry_path,
    load_all,
    register,
    unregister,
)


# ─── Shared helpers ────────────────────────────────────────────────────────────

def _make_session(tmp_path: Path, name: str = "test") -> Session:
    """Return a minimal Session whose paths are inside tmp_path."""
    gpr = tmp_path / f"{name}.gpr"
    gpr.touch()
    return Session(
        mode="headless",
        project_gpr=gpr,
        socket_path=tmp_path / f"ghidra-rpc-{name}.sock",
    )


def _start_mock_server(session: Session) -> threading.Thread:
    """Spin up a real RPC server for *session* in a daemon thread.

    Clears the handler registry first (we only need the built-in ``ping``),
    then waits until the socket file appears before returning.
    """
    from ghidra_rpc.server import main as server_main

    server_main._HANDLERS.clear()
    ctx = MagicMock()
    t = threading.Thread(
        target=server_main.run_server,
        args=(session, ctx),
        daemon=True,
    )
    t.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        if session.socket_path.exists():
            break
        time.sleep(0.05)
    assert session.socket_path.exists(), "Mock server socket did not appear in time"
    return t


# ─── _registry_path resolution ────────────────────────────────────────────────

class TestRegistryPath:
    """_registry_path() should respect env vars and platform conventions."""

    def test_state_dir_override_wins(self, tmp_path, monkeypatch):
        custom = tmp_path / "custom"
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(custom))
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        assert _registry_path() == custom / "sessions.json"

    def test_state_dir_override_beats_xdg(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(tmp_path / "state"))
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
        assert _registry_path() == tmp_path / "state" / "sessions.json"

    def test_xdg_state_home_used_on_linux(self, tmp_path, monkeypatch):
        if sys.platform != "linux":
            pytest.skip("Linux-specific state directory")
        monkeypatch.delenv("GHIDRA_RPC_STATE_DIR", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        assert _registry_path() == tmp_path / "ghidra-rpc" / "sessions.json"

    def test_linux_default_is_local_state(self, monkeypatch):
        if sys.platform != "linux":
            pytest.skip("Linux-specific default")
        monkeypatch.delenv("GHIDRA_RPC_STATE_DIR", raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        path = _registry_path()
        assert path == Path.home() / ".local" / "state" / "ghidra-rpc" / "sessions.json"

    def test_windows_default_uses_local_app_data(self, monkeypatch):
        if sys.platform != "win32":
            pytest.skip("Windows-specific default")
        monkeypatch.delenv("GHIDRA_RPC_STATE_DIR", raising=False)
        monkeypatch.setenv("LOCALAPPDATA", str(Path.home() / "custom-local-app-data"))
        path = _registry_path()
        assert path == Path.home() / "custom-local-app-data" / "ghidra-rpc" / "sessions.json"

    def test_macos_default_uses_library_application_support(self, monkeypatch):
        if sys.platform != "darwin":
            pytest.skip("macOS-specific default")
        monkeypatch.delenv("GHIDRA_RPC_STATE_DIR", raising=False)
        path = _registry_path()
        assert path == Path.home() / "Library" / "Application Support" / "ghidra-rpc" / "sessions.json"

    def test_result_always_named_sessions_json(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(tmp_path))
        assert _registry_path().name == "sessions.json"


# ─── register / unregister / load_all ────────────────────────────────────────

class TestRegistry:
    """File-based registry round-trips."""

    @pytest.fixture(autouse=True)
    def isolate_registry(self, tmp_path, monkeypatch):
        """Redirect the registry to a temp dir so tests never touch ~/.local/state."""
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(tmp_path))

    # ── load_all ──────────────────────────────────────────────────────────────

    def test_load_all_when_no_file_exists(self):
        assert load_all() == []

    def test_load_all_when_file_is_empty_string(self, tmp_path):
        reg = _registry_path()
        reg.parent.mkdir(parents=True, exist_ok=True)
        reg.write_text("")
        assert load_all() == []

    def test_corrupted_registry_returns_empty_list(self, tmp_path):
        reg = _registry_path()
        reg.parent.mkdir(parents=True, exist_ok=True)
        reg.write_text("{{{{ not valid json")
        assert load_all() == []

    # ── register ──────────────────────────────────────────────────────────────

    def test_register_and_load_all(self, tmp_path):
        sess = _make_session(tmp_path)
        register(sess)

        sessions = load_all()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.mode == "headless"
        assert s.project_gpr == sess.project_gpr.resolve()
        assert s.socket_path == sess.socket_path
        assert s.ghidra_install_dir is None

    def test_register_multiple_sessions(self, tmp_path):
        register(_make_session(tmp_path, "alpha"))
        register(_make_session(tmp_path, "beta"))
        assert len(load_all()) == 2

    def test_register_is_idempotent(self, tmp_path):
        sess = _make_session(tmp_path)
        register(sess)
        register(sess)
        assert len(load_all()) == 1

    def test_register_persists_ghidra_install_dir(self, tmp_path):
        gpr = tmp_path / "proj.gpr"
        gpr.touch()
        sess = Session(
            mode="headless",
            project_gpr=gpr,
            socket_path=tmp_path / "proj.sock",
            ghidra_install_dir=Path("/opt/ghidra"),
        )
        register(sess)
        loaded = load_all()
        assert len(loaded) == 1
        assert loaded[0].ghidra_install_dir == Path("/opt/ghidra")

    def test_register_creates_parent_dirs(self, tmp_path, monkeypatch):
        deep = tmp_path / "a" / "b" / "c"
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(deep))
        register(_make_session(tmp_path))
        assert (deep / "sessions.json").exists()

    def test_concurrent_registers_do_not_lose_entries(self, tmp_path):
        sessions = [_make_session(tmp_path, f"concurrent-{index}") for index in range(8)]
        threads = [threading.Thread(target=register, args=(session,)) for session in sessions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            assert not thread.is_alive()
        assert len(load_all()) == len(sessions)

    # ── unregister ────────────────────────────────────────────────────────────

    def test_unregister_removes_entry(self, tmp_path):
        sess = _make_session(tmp_path)
        register(sess)
        unregister(sess.project_gpr)
        assert load_all() == []

    def test_unregister_leaves_other_entries(self, tmp_path):
        sess_a = _make_session(tmp_path, "a")
        sess_b = _make_session(tmp_path, "b")
        register(sess_a)
        register(sess_b)
        unregister(sess_a.project_gpr)
        remaining = load_all()
        assert len(remaining) == 1
        assert remaining[0].project_gpr == sess_b.project_gpr.resolve()

    def test_unregister_nonexistent_entry_is_noop(self, tmp_path):
        """Unregistering a project that was never registered must not raise."""
        register(_make_session(tmp_path))   # registry file now exists
        unregister(tmp_path / "ghost.gpr")  # should silently do nothing
        assert len(load_all()) == 1

    def test_unregister_when_no_registry_file_is_noop(self, tmp_path):
        """Calling unregister before the registry file has ever been written is safe."""
        unregister(tmp_path / "nobody.gpr")


# ─── _discover_instances ──────────────────────────────────────────────────────

class TestDiscoverInstances:
    """Integration tests for the discovery helper (uses a real mock server)."""

    @pytest.fixture(autouse=True)
    def isolate_registry(self, short_tmp_path, monkeypatch):
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(short_tmp_path))
        # _discover_instances() also globs a socket dir for orphaned sockets
        # not in the registry; redirect it so this never touches /tmp and
        # can't see (or stop!) real daemons running on the host.
        monkeypatch.setattr("ghidra_rpc.cli._SOCKET_SCAN_DIR", short_tmp_path)

    def test_empty_when_nothing_registered_or_running(self):
        from ghidra_rpc.cli import _discover_instances
        assert _discover_instances() == []

    def test_finds_running_instance(self, short_tmp_path):
        sess = _make_session(short_tmp_path)
        register(sess)
        _start_mock_server(sess)

        from ghidra_rpc.cli import _discover_instances
        instances = _discover_instances()

        assert len(instances) == 1
        inst = instances[0]
        assert inst["running"] is True
        assert inst["mode"] == "headless"
        assert inst["project"] == str(sess.project_gpr.resolve())
        assert isinstance(inst["pid"], int) and inst["pid"] > 0
        assert inst["socket"] == str(sess.socket_path)

    def test_excludes_dead_instance_by_default(self, short_tmp_path):
        """Registered session with no running daemon is hidden by default."""
        sess = _make_session(short_tmp_path)
        register(sess)
        # socket file does not exist → not running

        from ghidra_rpc.cli import _discover_instances
        assert _discover_instances(include_dead=False) == []

    def test_includes_dead_instance_with_flag(self, short_tmp_path):
        """include_dead=True surfaces entries whose socket exists but is unresponsive."""
        sess = _make_session(short_tmp_path)
        register(sess)
        sess.socket_path.touch()   # file present, but no server behind it

        from ghidra_rpc.cli import _discover_instances
        instances = _discover_instances(include_dead=True)

        assert len(instances) == 1
        inst = instances[0]
        assert inst["running"] is False
        assert inst["project"] == str(sess.project_gpr.resolve())
        assert inst["pid"] is None

    def test_stale_entry_pruned_when_socket_file_gone(self, short_tmp_path):
        """If the socket file has disappeared, the registry entry is auto-pruned."""
        sess = _make_session(short_tmp_path)
        register(sess)
        assert len(load_all()) == 1
        # socket file never created → it's gone

        from ghidra_rpc.cli import _discover_instances
        _discover_instances(include_dead=False)

        assert load_all() == [], "Stale registry entry should have been pruned"

    def test_stale_entry_still_emitted_then_pruned_with_all_flag(self, short_tmp_path):
        """With include_dead=True, stale entries appear in output but are still pruned."""
        sess = _make_session(short_tmp_path)
        register(sess)
        # socket file absent → stale

        from ghidra_rpc.cli import _discover_instances
        instances = _discover_instances(include_dead=True)

        # Entry is returned (running=False)
        assert len(instances) == 1
        assert instances[0]["running"] is False
        # And the registry is cleaned up
        assert load_all() == []

    def test_unregistered_socket_discovered_via_glob(self, short_tmp_path, monkeypatch):
        """Sockets in the scan dir not in the registry are still discovered via glob."""
        # Create a socket file with the canonical naming pattern in the
        # (isolated) scan dir -- not real /tmp, per isolate_registry above.
        import hashlib
        gpr = short_tmp_path / "unregistered.gpr"
        gpr.touch()
        digest = hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]
        sock_path = short_tmp_path / f"ghidra-rpc-{digest}.sock"

        sess = Session(mode="headless", project_gpr=gpr, socket_path=sock_path)
        # Deliberately do NOT register — only start the server
        _start_mock_server(sess)

        try:
            from ghidra_rpc.cli import _discover_instances
            instances = _discover_instances()
            sockets = [i["socket"] for i in instances]
            assert str(sock_path) in sockets
        finally:
            # Clean up the /tmp socket left by the daemon thread
            if sock_path.exists():
                sock_path.unlink()


# ─── list-instances and stop --all CLI commands ───────────────────────────────

class TestListInstancesCLI:

    @pytest.fixture(autouse=True)
    def isolate_registry(self, short_tmp_path, monkeypatch):
        monkeypatch.setenv("GHIDRA_RPC_STATE_DIR", str(short_tmp_path))
        # `stop --all` walks the same discovery path as _discover_instances;
        # without this a real daemon on the host could get stopped for real.
        monkeypatch.setattr("ghidra_rpc.cli._SOCKET_SCAN_DIR", short_tmp_path)

    def test_empty_result(self):
        from click.testing import CliRunner
        from ghidra_rpc.cli import cli

        result = CliRunner().invoke(cli, ["list-instances"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["result"]["count"] == 0
        assert data["result"]["instances"] == []

    def test_reports_running_instance(self, short_tmp_path):
        sess = _make_session(short_tmp_path)
        register(sess)
        _start_mock_server(sess)

        from click.testing import CliRunner
        from ghidra_rpc.cli import cli

        result = CliRunner().invoke(cli, ["list-instances"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["result"]["count"] == 1
        inst = data["result"]["instances"][0]
        assert inst["running"] is True
        assert inst["mode"] == "headless"
        assert inst["pid"] is not None

    def test_all_flag_includes_dead_entries(self, short_tmp_path):
        sess = _make_session(short_tmp_path)
        register(sess)
        sess.socket_path.touch()   # file present, no server

        from click.testing import CliRunner
        from ghidra_rpc.cli import cli

        result = CliRunner().invoke(cli, ["list-instances", "--all"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["result"]["count"] == 1
        assert data["result"]["instances"][0]["running"] is False

    def test_stop_all_when_no_instances(self):
        from click.testing import CliRunner
        from ghidra_rpc.cli import cli

        result = CliRunner().invoke(cli, ["stop", "--all"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["result"]["stopped"] == []

    def test_stop_all_conflicts_with_project(self):
        from click.testing import CliRunner
        from ghidra_rpc.cli import cli

        result = CliRunner().invoke(cli, ["stop", "--all", "--project", "/tmp/x.gpr"])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["ok"] is False
        assert data["error"] == "InvalidArgs"

    def test_stop_all_stops_running_instance(self, short_tmp_path):
        sess = _make_session(short_tmp_path)
        register(sess)
        _start_mock_server(sess)

        from click.testing import CliRunner
        from ghidra_rpc.cli import cli

        result = CliRunner().invoke(cli, ["stop", "--all"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True
        assert len(data["result"]["stopped"]) == 1
        assert data["result"]["failed"] == []
