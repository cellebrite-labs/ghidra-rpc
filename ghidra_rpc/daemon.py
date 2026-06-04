"""Daemon lifecycle management for ghidra-rpc."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from ghidra_rpc.session import Session


def is_running(socket_path: Path) -> bool:
    """Check if a daemon is responsive at the given socket path."""
    import socket as sock_mod

    if not socket_path.exists():
        return False

    try:
        s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(socket_path))
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

    session.pid = os.getpid()
    session_mod.save(session)

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
        session_mod.remove(session.project_gpr)


def start_background(session: Session, timeout: float = 60.0) -> None:
    """Start the daemon in the background and wait for the socket to appear.

    Uses ghidra-rpcd entry point to daemonize. Waits up to `timeout` seconds
    for the socket to become responsive.
    """
    from ghidra_rpc import session as session_mod

    session_mod.save(session)

    # Log file alongside the socket, named by session hash
    socket_stem = session.socket_path.stem  # e.g. ghidra-rpc-9990be1c
    log_path = session.socket_path.parent / f"{socket_stem}.log"

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
    with open(log_path, "a") as log_fh:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=log_fh,
            start_new_session=True,
            env=env,
        )
    session.pid = proc.pid
    session_mod.save(session)

    # Wait for socket to appear and become responsive
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_running(session.socket_path):
            return
        time.sleep(0.5)

    raise TimeoutError(
        f"Daemon did not start within {timeout}s. "
        f"Check logs at {log_path} or try: ghidra-rpc start --project {session.project_gpr}"
    )


def _pid_command(pid: int) -> str:
    try:
        return subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "command="],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return ""


def _pid_matches_daemon(pid: int, project_gpr: Path | None) -> bool:
    command = _pid_command(pid)
    if not command:
        return False
    if "ghidra_rpc.daemon" not in command and "ghidra-rpcd" not in command:
        return False
    if project_gpr is not None and str(project_gpr) not in command:
        return False
    return True


def _wait_for_pid_exit(pid: int, project_gpr: Path | None, timeout: float) -> bool:
    saw_daemon = _pid_matches_daemon(pid, project_gpr)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_matches_daemon(pid, project_gpr):
            return saw_daemon
        time.sleep(0.25)

    if _pid_matches_daemon(pid, project_gpr):
        saw_daemon = True
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if not _pid_matches_daemon(pid, project_gpr):
                return saw_daemon
            time.sleep(0.25)

    if _pid_matches_daemon(pid, project_gpr):
        saw_daemon = True
        os.kill(pid, signal.SIGKILL)
    return saw_daemon


def stop_daemon(
    socket_path: Path,
    *,
    pid: int | None = None,
    project_gpr: Path | None = None,
    timeout: float = 10.0,
) -> bool:
    """Send a stop command to a running daemon. Returns True if stopped."""
    from ghidra_rpc.client import send_request, DaemonNotRunning

    stopped = False
    try:
        send_request(socket_path, "stop")
        stopped = True
    except DaemonNotRunning:
        stopped = False
    except Exception:
        # If the daemon closed the connection before responding, that's OK
        stopped = True

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_running(socket_path):
            break
        time.sleep(0.25)

    stopped_pid = False
    if pid is not None:
        stopped_pid = _wait_for_pid_exit(pid, project_gpr, timeout)

    return stopped or stopped_pid


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
