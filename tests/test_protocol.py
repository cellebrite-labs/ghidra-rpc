"""Tests for the local transport protocol and server dispatch."""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ghidra_rpc import transport


# We need to test the server without Ghidra, so mock the tool registration
def _make_mock_context():
    """Create a mock context with a programs dict."""
    ctx = MagicMock()
    ctx._programs_lock = threading.RLock()
    ctx.programs = {}
    return ctx


def _send_request(sock_path: Path, cmd: str, args: dict | None = None) -> dict:
    """Send a raw JSON request and return parsed response."""
    request = {
        "id": str(uuid.uuid4()),
        "cmd": cmd,
        "args": args or {},
    }
    s, auth_token = transport.connect(sock_path, 5)
    if auth_token is not None:
        request["auth"] = auth_token
    try:
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    return json.loads(buf.decode().strip())


class TestProtocol:
    """Test the wire protocol without needing Ghidra."""

    @pytest.fixture(autouse=True)
    def setup_server(self, short_tmp_path):
        """Start a server with a mock context in a background thread.

        Readiness is confirmed by a real ``ping`` round-trip, not by the socket
        file merely appearing: the file exists after ``bind()`` but before
        ``listen()``, so an early ``connect()`` races and gets
        ``ConnectionRefusedError``.  On teardown the server is stopped and its
        thread joined, so daemon threads (and their hold on the module-global
        ``_HANDLERS`` dict) don't leak across tests — leaked servers under
        random test ordering were the source of the intermittent
        ``ConnectionRefusedError`` failures.
        """
        from ghidra_rpc.server import main as server_main
        server_main._HANDLERS.clear()

        # Register a test handler
        def echo_handler(ctx, args):
            return {"echo": args}

        server_main.register_handler("echo", echo_handler)

        self.sock_path = short_tmp_path / "test.sock"
        from ghidra_rpc.session import Session
        session = Session(mode="headless", project_gpr=short_tmp_path / "test.gpr", socket_path=self.sock_path)

        self.ctx = _make_mock_context()
        self.server_thread = threading.Thread(
            target=server_main.run_server,
            args=(session, self.ctx),
            daemon=True,
        )
        self.server_thread.start()

        # Wait until the server actually accepts connections and answers a ping.
        deadline = time.time() + 5
        ready = False
        while time.time() < deadline:
            try:
                if _send_request(self.sock_path, "ping").get("ok"):
                    ready = True
                    break
            except OSError:
                pass  # bind() done but not yet listen(), or socket not up yet
            time.sleep(0.02)
        assert ready, "Server did not become reachable"

        yield

        # Teardown: tell the server to stop (unless a test already did) so
        # daemon threads don't accumulate across the suite.  Once "stop" is
        # acked the server has set its shutdown flag and no longer accepts
        # connections, so it's safe for the next test to clear _HANDLERS and
        # bind a fresh socket; we don't block joining the winding-down thread.
        try:
            if self.sock_path.exists():
                _send_request(self.sock_path, "stop")
        except OSError:
            pass

    def test_ping(self):
        resp = _send_request(self.sock_path, "ping")
        assert resp["ok"] is True
        assert resp["result"]["status"] == "alive"

    def test_ping_returns_session_metadata(self):
        """Ping response must include project_gpr, mode, and pid."""
        resp = _send_request(self.sock_path, "ping")
        result = resp["result"]
        assert "project_gpr" in result
        assert result["mode"] == "headless"
        assert isinstance(result["pid"], int) and result["pid"] > 0

    def test_echo_handler(self):
        resp = _send_request(self.sock_path, "echo", {"hello": "world"})
        assert resp["ok"] is True
        assert resp["result"]["echo"] == {"hello": "world"}

    def test_unknown_command(self):
        resp = _send_request(self.sock_path, "nonexistent_cmd")
        assert resp["ok"] is False
        assert resp["error"] == "UnknownCommand"

    def test_windows_transport_rejects_missing_authentication(self):
        s, auth_token = transport.connect(self.sock_path, 5)
        if auth_token is None:
            s.close()
            pytest.skip("Authentication is only used by the Windows TCP transport")
        request = {"id": "unauthorized", "cmd": "ping", "args": {}}
        s.sendall((json.dumps(request) + "\n").encode())
        response = json.loads(s.recv(65536).decode().strip())
        s.close()
        assert response["ok"] is False
        assert response["error"] == "Unauthorized"

    def test_stop(self):
        resp = _send_request(self.sock_path, "stop")
        assert resp["ok"] is True
        # Server should shut down — give it time to clean up
        deadline = time.time() + 5
        while time.time() < deadline:
            if not self.sock_path.exists():
                break
            time.sleep(0.1)
        assert not self.sock_path.exists()

    def test_invalid_json(self):
        s, _ = transport.connect(self.sock_path, 5)
        s.sendall(b"not valid json\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode().strip())
        assert resp["ok"] is False
        assert resp["error"] == "InvalidJSON"

    def test_request_id_echoed(self):
        req_id = "test-id-12345"
        request = {"id": req_id, "cmd": "ping", "args": {}}
        s, auth_token = transport.connect(self.sock_path, 5)
        if auth_token is not None:
            request["auth"] = auth_token
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode().strip())
        assert resp["id"] == req_id
