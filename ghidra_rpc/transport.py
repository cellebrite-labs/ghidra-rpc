"""Cross-platform IPC transport for ghidra-rpc.

On POSIX, ghidra-rpc talks to its daemon over a Unix domain socket at a
deterministic path under ``/tmp``.  On Windows, where CPython does not
reliably expose ``AF_UNIX`` / ``AF_PIPE``, it uses a TCP loopback listener on
``127.0.0.1`` with a deterministic port derived from the project path hash.
Every project therefore gets its own stable endpoint, so client and daemon
agree across restarts without a shared config file.

The endpoint is a canonical *string*:

* POSIX:   ``/tmp/ghidra-rpc-<hash>.sock``
* Windows: ``tcp:127.0.0.1:<port>``

This lets the rest of the code treat the endpoint as an opaque string while
``session.save``/``load`` keep it stable across daemon restarts.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

# Deterministic TCP port range, kept in the user/registered range below the
# Windows default dynamic port allocation (49152+) to avoid clashing with
# ephemeral ports handed out by the OS.
_TCP_PORT_BASE = 40000
_TCP_PORT_RANGE = 20000


def _hash_of(gpr: Path) -> str:
    return hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]


def socket_path_for_project(gpr: Path) -> str:
    """Return the canonical transport-endpoint string for a project."""
    digest = _hash_of(gpr)
    if IS_WINDOWS:
        port = _TCP_PORT_BASE + (int(digest[:4], 16) % _TCP_PORT_RANGE)
        return f"tcp:127.0.0.1:{port}"
    return f"/tmp/ghidra-rpc-{digest}.sock"


def log_path_for_project(gpr: Path) -> Path:
    """Return the daemon log path for a project."""
    digest = _hash_of(gpr)
    if IS_WINDOWS:
        import tempfile

        return Path(tempfile.gettempdir()) / f"ghidra-rpc-{digest}.log"
    return Path(f"/tmp/ghidra-rpc-{digest}.log")


def _tcp_parts(endpoint: str) -> tuple[str, int]:
    _, host, port = endpoint.split(":")
    return host, int(port)


def create_client_socket(endpoint: str, timeout: float):
    """Create a connected stream socket for the given endpoint."""
    import socket as _sock

    if IS_WINDOWS:
        host, port = _tcp_parts(endpoint)
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(endpoint)
    return s


def create_server_socket(endpoint: str):
    """Create a listening stream socket for the given endpoint."""
    import socket as _sock

    if IS_WINDOWS:
        host, port = _tcp_parts(endpoint)
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        return s
    p = Path(endpoint)
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass
    s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    s.bind(endpoint)
    s.listen(5)
    return s


def endpoint_exists(endpoint: str) -> bool:
    """Return True if a daemon appears to be listening at the endpoint.

    On POSIX this checks for the socket file; on Windows it attempts a short
    TCP connect to the loopback endpoint (a TCP port has no path to stat).
    """
    if not IS_WINDOWS:
        return Path(endpoint).exists()
    import socket as _sock

    try:
        with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect(_tcp_parts(endpoint))
        return True
    except OSError:
        return False


def remove_endpoint(endpoint: str) -> None:
    """Clean up the endpoint after shutdown (Unix: unlink the socket file)."""
    if IS_WINDOWS:
        return
    p = Path(endpoint)
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass
