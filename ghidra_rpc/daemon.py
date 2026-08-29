"""Daemon lifecycle management for ghidra-rpc."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from ghidra_rpc.session import Session
from ghidra_rpc import transport


def is_running(socket_path) -> bool:
    """Check if a daemon is responsive at the given transport endpoint."""
    if not transport.endpoint_exists(socket_path):
        return False

    try:
        s = transport.create_client_socket(str(socket_path), 5)
        # Send a ping
        import json
        import uuid

        request = {"id": str(uuid.uuid4()), "cmd": "ping", "args": {}}
        s.sendall((json.dumps(request) + "\n").encode())
        data = b""
        while b"\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        if data.strip():
            resp = json.loads(data.decode().strip())
            return resp.get("ok", False)
        return False
    except Exception:
        return False


def start_blocking(session: Session) -> None:
    """Start the daemon in the foreground (blocking). Shows logs to the terminal.

    This is the human-facing command — it launches Ghidra and the RPC server
    in the current process and blocks until shutdown.
    """
    from ghidra_rpc import session as session_mod
    from ghidra_rpc.server.main import run_server

    session_mod.save(session)
    session_mod.register(session)

    if session.mode == "headless":
        from ghidra_rpc.server.launcher import create_headless_context
        ctx = create_headless_context(session)
    else:
        from ghidra_rpc.server.launcher import create_gui_context
        ctx = create_gui_context(session)

    try:
        run_server(session, ctx)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if hasattr(ctx, "close"):
            ctx.close()
        session_mod.unregister(session.project_gpr)
        session_mod.remove(session.project_gpr)


def start_background(session: Session, timeout: float = 60.0) -> None:
    """Start the daemon in the background and wait for the socket to appear.

    Uses ghidra-rpcd entry point to daemonize. Waits up to `timeout` seconds
    for the socket to become responsive.
    """
    from ghidra_rpc import session as session_mod

    session_mod.save(session)
    session_mod.register(session)

    # Log file alongside the daemon, named by session hash
    log_path = transport.log_path_for_project(session.project_gpr)

    # Build subprocess environment, explicitly forwarding GHIDRA_INSTALL_DIR so
    # the daemon subprocess works even when launched from environments that strip
    # env vars (nohup, cron, sudo, launchd, etc.).
    env = dict(os.environ)
    ghidra_dir = (
        str(session.ghidra_install_dir)
        if session.ghidra_install_dir
        else env.get("GHIDRA_INSTALL_DIR")
    )
    if ghidra_dir:
        env["GHIDRA_INSTALL_DIR"] = ghidra_dir

    # Launch ghidra-rpcd as a subprocess
    cmd = [
        sys.executable, "-m", "ghidra_rpc.daemon",
        "--mode", session.mode,
        "--project", str(session.project_gpr),
    ]
    # start_new_session (setsid) is POSIX-only; on Windows use a new process
    # group instead so the daemon detaches from the console cleanly.
    popen_kwargs: dict = {"env": env}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    with open(log_path, "a") as log_fh:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=log_fh,
            **popen_kwargs,
        )

    # Wait for socket to appear and become responsive.
    # Also watch for the subprocess dying early (wrong Python, missing dep, etc.)
    # so we fail fast instead of burning the full timeout.
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_running(session.socket_path):
            return
        exit_code = proc.poll()
        if exit_code is not None:
            # Process already exited — read whatever landed in the log.
            try:
                log_tail = log_path.read_text()[-2000:]
            except OSError:
                log_tail = "(log not readable)"
            raise RuntimeError(
                f"Daemon process exited immediately with code {exit_code}.\n"
                f"Log ({log_path}):\n{log_tail}"
            )
        time.sleep(0.5)

    raise TimeoutError(
        f"Daemon did not start within {timeout}s. "
        f"Check logs at {log_path} or try: ghidra-rpc start --project {session.project_gpr}"
    )


def stop_daemon(socket_path: Path) -> bool:
    """Send a stop command to a running daemon. Returns True if stopped."""
    from ghidra_rpc.client import send_request, DaemonNotRunning

    try:
        send_request(socket_path, "stop")
        return True
    except DaemonNotRunning:
        return False
    except Exception:
        # If the daemon closed the connection before responding, that's OK
        return True


def main():
    """Entry point for ghidra-rpcd (background daemon)."""
    import argparse

    parser = argparse.ArgumentParser(description="ghidra-rpc daemon")
    parser.add_argument("--mode", choices=["gui", "headless"], required=True)
    parser.add_argument("--project", type=Path, required=True)
    args = parser.parse_args()

    from ghidra_rpc.session import Session, socket_path_for_project

    session = Session(
        mode=args.mode,
        project_gpr=args.project,
        socket_path=socket_path_for_project(args.project),
    )

    start_blocking(session)


if __name__ == "__main__":
    main()
