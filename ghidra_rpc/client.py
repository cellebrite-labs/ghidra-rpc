"""Client for communicating with the ghidra-rpc daemon over Unix socket."""

from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path

from ghidra_rpc import session as session_mod
from ghidra_rpc import transport


class DaemonNotRunning(Exception):
    """Raised when the daemon socket doesn't exist or can't be connected to."""
    pass


class DaemonError(Exception):
    """Raised when the daemon returns an error response (ok: false)."""

    def __init__(self, error: str, message: str, full_response: dict):
        super().__init__(message)
        self.error = error
        self.full_response = full_response


# Keys in the request args dict that carry a user-visible operation timeout.
# The socket timeout is set to max(these values) + _SOCKET_TIMEOUT_BUFFER so
# the network layer never fires before the server has finished the operation.
_TIMEOUT_ARG_KEYS = ("timeout", "analysis_timeout")

# Default socket timeout when no operation-level timeout is present.
_DEFAULT_SOCKET_TIMEOUT: float = 120.0

# Extra seconds added on top of the operation timeout to give the server time
# to serialise and send its response after the operation itself completes.
_SOCKET_TIMEOUT_BUFFER: float = 30.0


def _derive_socket_timeout(args: dict | None) -> float:
    """Return the appropriate socket timeout for a request.

    If ``args`` contains any of the recognised timeout keys, the socket
    timeout is set to ``max(those values) + _SOCKET_TIMEOUT_BUFFER``.
    This ensures that a ``decompile --timeout 180`` or
    ``load --analysis-timeout 300`` request always gets a socket timeout that
    exceeds the operation's own budget.

    Falls back to ``_DEFAULT_SOCKET_TIMEOUT`` (120 s) when no timeout arg is
    present.
    """
    if not args:
        return _DEFAULT_SOCKET_TIMEOUT
    timeouts = [
        float(args[k])
        for k in _TIMEOUT_ARG_KEYS
        if args.get(k) is not None
    ]
    if timeouts:
        return max(timeouts) + _SOCKET_TIMEOUT_BUFFER
    return _DEFAULT_SOCKET_TIMEOUT


def send_request(
    socket_path,
    cmd: str,
    args: dict | None = None,
    *,
    socket_timeout: float | None = None,
) -> dict:
    """Send a JSON-RPC-style request to the daemon and return the parsed response.

    Connects to the Unix domain socket, sends a newline-delimited JSON request,
    reads the response, and returns the parsed dict.

    ``socket_timeout`` controls how long the client waits for the server to
    respond.  If not given it is derived automatically:

    * If ``args`` contains a ``"timeout"`` or ``"analysis_timeout"`` key the
      socket timeout is ``max(those values) + 30 s`` so the network layer
      never fires before the server operation has had its full allotment.
    * Otherwise the default is 120 s.

    Raises ``DaemonNotRunning`` if the socket is missing or the connection is
    refused, and ``DaemonError`` if the daemon returns ``ok: false``.
    """
    if not transport.endpoint_exists(socket_path):
        raise DaemonNotRunning(f"Socket not found: {socket_path}")

    effective_timeout = (
        socket_timeout if socket_timeout is not None
        else _derive_socket_timeout(args)
    )

    request = {
        "id": str(uuid.uuid4()),
        "cmd": cmd,
        "args": args or {},
    }
    request_bytes = (json.dumps(request) + "\n").encode("utf-8")

    try:
        sock = transport.create_client_socket(str(socket_path), effective_timeout)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        raise DaemonNotRunning(f"Cannot connect to daemon at {socket_path}: {e}")

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
    derived automatically from ``args`` (see ``send_request``).
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
        daemon_mod.start_background(session)
    except Exception:
        raise DaemonNotRunning(
            f"Failed to restart daemon. Please run: ghidra-rpc start --project {project_gpr}"
        )

    # Retry once after restart
    return send_request(
        session.socket_path, cmd, args, socket_timeout=socket_timeout
    )
