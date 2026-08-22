"""Local transport server for ghidra-rpc.

Accepts newline-delimited JSON requests and dispatches to tool handlers.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import sys
import threading
import traceback
import uuid
from pathlib import Path
from typing import Any

from ghidra_rpc.session import Session
from ghidra_rpc import transport

logger = logging.getLogger("ghidra-rpc.server")

# Command registry: maps command name -> handler(ctx, args) -> result dict
_HANDLERS: dict[str, Any] = {}

# Global lock that serialises all command handler invocations.  Ghidra's
# transaction machinery is not safe for concurrent writes from different
# threads — overlapping startTransaction/endTransaction calls on the same
# program cause "No transaction is open" or "Transaction not found" errors.
# Serialising at the handler level is cheap (the daemon is I/O-bound) and
# eliminates the race entirely.
_HANDLER_LOCK = threading.Lock()


def register_handler(cmd: str, handler):
    """Register a command handler function."""
    _HANDLERS[cmd] = handler


def _handle_connection(
    conn: socket.socket,
    ctx: Any,
    shutdown_event: threading.Event,
    session: Session,
    auth_token: str | None,
):
    """Handle a single client connection: read request, dispatch, send response."""
    try:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk

        line = buf.decode("utf-8").strip()
        if not line:
            return

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            response = {
                "id": None,
                "ok": False,
                "error": "InvalidJSON",
                "message": f"Malformed JSON: {e}",
            }
            conn.sendall((json.dumps(response) + "\n").encode())
            return

        req_id = request.get("id", str(uuid.uuid4()))
        cmd = request.get("cmd", "")
        args = request.get("args", {})

        request_token = request.get("auth")
        if auth_token is not None and (
            not isinstance(request_token, str)
            or not secrets.compare_digest(request_token, auth_token)
        ):
            response = {
                "id": req_id,
                "ok": False,
                "error": "Unauthorized",
                "message": "Invalid daemon authentication token",
            }
            conn.sendall((json.dumps(response) + "\n").encode())
            return

        # Built-in commands
        if cmd == "ping":
            response = {
                "id": req_id,
                "ok": True,
                "result": {
                    "status":      "alive",
                    "project_gpr": str(session.project_gpr),
                    "mode":        session.mode,
                    "pid":         os.getpid(),
                },
            }
        elif cmd == "stop":
            response = {"id": req_id, "ok": True, "result": {"status": "stopping"}}
            conn.sendall((json.dumps(response) + "\n").encode())
            shutdown_event.set()
            return
        elif cmd in _HANDLERS:
            try:
                with _HANDLER_LOCK:
                    result = _HANDLERS[cmd](ctx, args)
                response = {"id": req_id, "ok": True, "result": result}
            except Exception as e:
                error_type = type(e).__name__
                response = {
                    "id": req_id,
                    "ok": False,
                    "error": error_type,
                    "message": str(e),
                }
                logger.error(f"Error handling '{cmd}': {e}", exc_info=True)
        else:
            response = {
                "id": req_id,
                "ok": False,
                "error": "UnknownCommand",
                "message": f"Unknown command: {cmd}. Available: {sorted(list(_HANDLERS.keys()) + ['ping', 'stop'])}",
            }

        conn.sendall((json.dumps(response) + "\n").encode())

    except Exception as e:
        logger.error(f"Connection handler error: {e}", exc_info=True)
    finally:
        conn.close()


def run_server(session: Session, ctx: Any) -> None:
    """Run the RPC server on the platform's local transport.

    Blocks until a 'stop' command is received or the process is interrupted.
    """
    # Configure logging so tool handlers' messages are visible
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # Register tool handlers
    from ghidra_rpc.server.tools import register_all_tools
    register_all_tools()

    sock_path = session.socket_path

    server_sock, auth_token = transport.listen(sock_path)
    server_sock.settimeout(1.0)  # Allow periodic checking of shutdown event

    shutdown_event = threading.Event()

    logger.info(f"ghidra-rpc server listening on {sock_path}")

    try:
        while not shutdown_event.is_set():
            try:
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Handle each connection in a thread so the server stays responsive
            t = threading.Thread(
                target=_handle_connection,
                args=(conn, ctx, shutdown_event, session, auth_token),
                daemon=True,
            )
            t.start()
    finally:
        server_sock.close()
        transport.remove_endpoint(sock_path)
        logger.info("Server shut down.")
