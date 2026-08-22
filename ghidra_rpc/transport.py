"""Cross-platform local transport for ghidra-rpc."""

from __future__ import annotations

import json
import os
import secrets
import socket
import tempfile
from pathlib import Path


_IS_WINDOWS = os.name == "nt"
_WINDOWS_HOST = "127.0.0.1"


def endpoint_directory() -> Path:
    """Return the directory used for daemon endpoint files."""
    if _IS_WINDOWS:
        return Path(tempfile.gettempdir())
    return Path("/tmp")


def listen(endpoint_path: Path, backlog: int = 5) -> tuple[socket.socket, str | None]:
    """Create a listening local transport and publish its endpoint.

    Unix uses an ``AF_UNIX`` socket. Windows uses an authenticated loopback TCP
    socket because ``AF_UNIX`` is not available in every Windows Python build.
    The TCP port and a random authentication token are stored in *endpoint_path*.
    """
    endpoint_path.parent.mkdir(parents=True, exist_ok=True)
    remove_endpoint(endpoint_path)

    if not _IS_WINDOWS:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(endpoint_path))
        server.listen(backlog)
        return server, None

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temporary_path: Path | None = None
    try:
        server.bind((_WINDOWS_HOST, 0))
        server.listen(backlog)
        token = secrets.token_urlsafe(32)
        port = server.getsockname()[1]
        data = {
            "transport": "tcp",
            "host": _WINDOWS_HOST,
            "port": port,
            "token": token,
        }
        temporary_path = endpoint_path.with_name(
            f"{endpoint_path.name}.{os.getpid()}.tmp"
        )
        temporary_path.write_text(json.dumps(data), encoding="utf-8")
        temporary_path.replace(endpoint_path)
        return server, token
    except Exception:
        server.close()
        if temporary_path is not None:
            remove_endpoint(temporary_path)
        raise


def connect(endpoint_path: Path, timeout: float) -> tuple[socket.socket, str | None]:
    """Connect to a published endpoint and return its authentication token."""
    if not _IS_WINDOWS:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect(str(endpoint_path))
        return client, None

    try:
        data = json.loads(endpoint_path.read_text(encoding="utf-8"))
        host = data["host"]
        port = data["port"]
        token = data["token"]
        if data.get("transport") != "tcp" or host != _WINDOWS_HOST:
            raise ValueError("unsupported endpoint")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("invalid port")
        if not isinstance(token, str) or not token:
            raise ValueError("invalid authentication token")
    except (KeyError, json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        raise OSError(f"Invalid daemon endpoint file: {endpoint_path}") from exc

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)
    client.connect((host, port))
    return client, token


def remove_endpoint(endpoint_path: Path) -> None:
    """Remove a stale socket or endpoint file if one exists."""
    try:
        endpoint_path.unlink()
    except FileNotFoundError:
        pass
