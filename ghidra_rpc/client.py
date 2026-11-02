"""Client for communicating with the ghidra-rpc daemon over a local transport."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from ghidra_rpc import session as session_mod
from ghidra_rpc import transport
from ghidra_rpc.timeouts import DEFAULT_DECOMPILE_TIMEOUT, DOUBLE_DECOMPILE_COMMANDS


class DaemonNotRunning(Exception):
    """Raised when the daemon socket doesn't exist or can't be connected to."""
    pass


class DaemonError(Exception):
    """Raised when the daemon returns an error response (ok: false)."""

    def __init__(self, error: str, message: str, full_response: dict):
        super().__init__(message)
        self.error = error
        self.full_response = full_response


# Default socket timeout when the request has no ``timeout`` arg.
_DEFAULT_SOCKET_TIMEOUT: float = 120.0

# Extra seconds added on top of the operation timeout to give the server time
# to serialise and send its response after the operation itself completes.
_SOCKET_TIMEOUT_BUFFER: float = 30.0


def _derive_socket_timeout(cmd: str, args: dict | None) -> float | None:
    """Return the appropriate socket timeout for a request.

    The result always exceeds the server's own budget for ``cmd``, so the
    client never gives up while the daemon is still working (and holding the
    handler lock):

    * ``load`` -> ``None`` (no limit): importing and saving a binary have no
      server-side bound, and analysis runs to completion unless
      ``analysis_timeout`` caps it, so no fixed wait is safe.
    * Commands that decompile twice (``timeouts.DOUBLE_DECOMPILE_COMMANDS``)
      -> ``2 * timeout + buffer``.
    * Otherwise, if ``args`` has a ``timeout``, ``timeout +
      _SOCKET_TIMEOUT_BUFFER``; else ``_DEFAULT_SOCKET_TIMEOUT`` (120 s).
    """
    args = args or {}
    if cmd == "load":
        return None
    if cmd in DOUBLE_DECOMPILE_COMMANDS:
        timeout = float(args.get("timeout", DEFAULT_DECOMPILE_TIMEOUT))
        return 2 * timeout + _SOCKET_TIMEOUT_BUFFER
    if args.get("timeout") is not None:
        return float(args["timeout"]) + _SOCKET_TIMEOUT_BUFFER
    return _DEFAULT_SOCKET_TIMEOUT


def send_request(
    socket_path: Path,
    cmd: str,
    args: dict | None = None,
    *,
    socket_timeout: float | None = None,
) -> dict:
    """Send a JSON-RPC-style request to the daemon and return the parsed response.

    Connects to the local daemon endpoint, sends a newline-delimited JSON request,
    reads the response, and returns the parsed dict.

    ``socket_timeout`` controls how long the client waits for the server to
    respond.  If not given it is derived from ``cmd`` and ``args`` so the
    network layer never fires before the server operation has had its full
    allotment (see ``_derive_socket_timeout``).

    Raises ``DaemonNotRunning`` if the socket is missing or the connection is
    refused, and ``DaemonError`` if the daemon returns ``ok: false``.
    """
    if not socket_path.exists():
        raise DaemonNotRunning(f"Socket not found: {socket_path}")

    effective_timeout = (
        socket_timeout if socket_timeout is not None
        else _derive_socket_timeout(cmd, args)
    )

    try:
        sock, auth_token = transport.connect(socket_path, effective_timeout)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        raise DaemonNotRunning(f"Cannot connect to daemon at {socket_path}: {e}")

    request = {
        "id": str(uuid.uuid4()),
        "cmd": cmd,
        "args": args or {},
    }
    if auth_token is not None:
        request["auth"] = auth_token
    request_bytes = (json.dumps(request) + "\n").encode("utf-8")

    try:
        sock.sendall(request_bytes)

        # Read response: accumulate until we get a newline
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        sock.close()

    if not buf.strip():
        raise DaemonError("EmptyResponse", "Daemon returned empty response", {})

    response = json.loads(buf.decode("utf-8").strip())

    if not response.get("ok", False):
        raise DaemonError(
            response.get("error", "UnknownError"),
            response.get("message", "Unknown error from daemon"),
            response,
        )

    return response


def send_request_with_auto_restart(
    project_gpr: Path,
    cmd: str,
    args: dict | None = None,
    *,
    socket_timeout: float | None = None,
) -> dict:
    """Send a request, auto-restarting the daemon if it's not running.

    First tries to send directly. If that fails (socket missing or connection
    refused), loads the session file and attempts a background restart. If no
    session file exists, raises DaemonNotRunning with a helpful message.

    ``socket_timeout`` is forwarded to ``send_request``; when not given it is
    derived automatically from ``cmd`` and ``args`` (see ``send_request``).
    """
    from ghidra_rpc import daemon as daemon_mod

    sock_path = session_mod.socket_path_for_project(project_gpr)

    # First attempt
    try:
        return send_request(sock_path, cmd, args, socket_timeout=socket_timeout)
    except DaemonNotRunning:
        pass

    # Try to restart from saved session
    session = session_mod.load(project_gpr)
    if session is None:
        raise DaemonNotRunning(
            f"Daemon not running. Start it with: ghidra-rpc start --project {project_gpr}"
        )

    try:
        daemon_mod.start_background(session)  # waits per the session's mode
    except Exception as e:
        raise DaemonNotRunning(
            f"Failed to restart daemon: {e}\n"
            f"Check `ghidra-rpc status --project {project_gpr}` before starting "
            "it again: a slow (GUI) start may still be in progress."
        )

    # Retry once after restart
    return send_request(
        session.socket_path, cmd, args, socket_timeout=socket_timeout
    )
