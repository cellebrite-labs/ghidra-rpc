"""Daemon lifecycle management for ghidra-rpc."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from ghidra_rpc.session import Session


def is_running(socket_path: Path) -> bool:
    """Check if a daemon is responsive at the given socket path."""
    if not socket_path.exists():
        return False

    try:
        from ghidra_rpc.client import send_request

        return send_request(socket_path, "ping", {}, socket_timeout=5).get("ok", False)
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


def default_start_timeout(mode: str) -> float:
    """Seconds to wait for a background daemon to respond: GUI startup (JVM,
    Ghidra window, project open) routinely takes 60-120 s on a cold machine."""
    return 180.0 if mode == "gui" else 60.0


def start_background(session: Session, timeout: float | None = None) -> None:
    """Start the daemon in the background and wait for the socket to appear.

    Runs ``python -m ghidra_rpc.daemon`` detached. Waits up to ``timeout``
    seconds (default: ``default_start_timeout(session.mode)``) for the socket
    to become responsive.
    """
    if timeout is None:
        timeout = default_start_timeout(session.mode)
    from ghidra_rpc import session as session_mod

    session_mod.save(session)
    session_mod.register(session)

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
    # Thread ghidra_install_dir through explicitly: the child's own main()
    # reconstructs a Session from just these argv flags and re-saves it via
    # start_blocking(), which otherwise clobbers the correct value we just
    # wrote above with None a moment later — silently breaking the "restart
    # in an environment that strips GHIDRA_INSTALL_DIR" case this field
    # exists for, on every platform, not just Windows.
    if ghidra_dir:
        cmd += ["--ghidra-install-dir", ghidra_dir]
    # Detach the child so it survives the parent's exit.  start_new_session
    # (setsid) is POSIX-only — CPython silently ignores it on Windows, which
    # left the daemon sharing the launching console and dying with it.  The
    # Windows equivalent is DETACHED_PROCESS (drop the console entirely) plus
    # CREATE_NEW_PROCESS_GROUP (so a Ctrl+C in the parent isn't broadcast to
    # it).  stdout/stderr still redirect to the log file either way.
    #
    # CREATE_BREAKAWAY_FROM_JOB is also required: OpenSSH's sshd puts every
    # process it spawns in a Job Object, and closing that job (when the ssh
    # session ends) kills every process still in it — DETACHED_PROCESS alone
    # does not remove a child from its parent's job.  Verified empirically:
    # without this flag the daemon vanished within ~1s of the launching ssh
    # session closing, with no shutdown log entry.  A job can itself forbid
    # breakaway (JOB_OBJECT_LIMIT_BREAKAWAY_OK unset), which makes CreateProcess
    # fail outright rather than ignore the flag, so retry without it in that
    # case instead of failing the start.
    detach_kwargs: dict = {}
    if sys.platform == "win32":
        detach_kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_BREAKAWAY_FROM_JOB
        )
    else:
        detach_kwargs["start_new_session"] = True

    with open(log_path, "a") as log_fh:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=log_fh,
                env=env,
                **detach_kwargs,
            )
        except OSError:
            if sys.platform != "win32" or "creationflags" not in detach_kwargs:
                raise
            detach_kwargs["creationflags"] &= ~subprocess.CREATE_BREAKAWAY_FROM_JOB
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=log_fh,
                env=env,
                **detach_kwargs,
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


# Seconds `stop`/`restart` wait for a daemon to finish shutting down (saving
# every program can take a while on large projects).
STOP_TIMEOUT: float = 120.0


def _pid_alive(pid: int) -> bool:
    """True if process *pid* is still running (on this machine)."""
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        synchronize, wait_timeout, error_access_denied = 0x00100000, 0x102, 5
        handle = kernel32.OpenProcess(synchronize, False, pid)
        if not handle:
            return ctypes.get_last_error() == error_access_denied
        try:
            return kernel32.WaitForSingleObject(handle, 0) == wait_timeout
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.waitpid(pid, os.WNOHANG)  # reap it if it is our own exited child
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def request_stop(socket_path: Path) -> int | None:
    """Ask a running daemon to stop without waiting for it.

    Returns None if no daemon was running, else its pid (0 if unknown), for
    ``wait_stopped``.  The daemon acknowledges *before* it shuts down.
    """
    from ghidra_rpc.client import send_request, DaemonNotRunning

    try:
        pid = int(send_request(socket_path, "ping", socket_timeout=5.0)
                  ["result"].get("pid") or 0)
    except DaemonNotRunning:
        return None
    except Exception:
        pid = 0
    try:
        send_request(socket_path, "stop")
    except DaemonNotRunning:
        return None
    except Exception:
        pass  # the daemon may close the connection before responding
    return pid


def wait_stopped(socket_path: Path, pid: int, timeout: float) -> None:
    """Block until a daemon told to stop has shut down: its endpoint is gone
    (until then the dying daemon still answers pings, so a new start would
    mistake it for itself) and its process has exited (in GUI mode Ghidra
    closes the project, releasing its lock, only after the endpoint is gone).
    Raises TimeoutError after *timeout* seconds."""
    deadline = time.time() + timeout
    while socket_path.exists() or (pid and _pid_alive(pid)):
        if time.time() >= deadline:
            raise TimeoutError(
                f"Daemon at {socket_path} acknowledged stop but did not shut "
                f"down within {timeout:.0f}s."
            )
        time.sleep(0.2)


def stop_daemon(socket_path: Path, *, wait: float = 0.0) -> bool:
    """Ask a running daemon to stop. Returns False if none was running.

    With ``wait`` > 0, also block until it has shut down (``wait_stopped``);
    raises TimeoutError if that takes longer than ``wait`` seconds.
    """
    pid = request_stop(socket_path)
    if pid is None:
        return False
    if wait > 0:
        wait_stopped(socket_path, pid, wait)
    return True


def main():
    """Entry point for ghidra-rpcd (background daemon)."""
    import argparse

    parser = argparse.ArgumentParser(description="ghidra-rpc daemon")
    parser.add_argument("--mode", choices=["gui", "headless"], required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--ghidra-install-dir", type=Path, default=None)
    args = parser.parse_args()

    from ghidra_rpc.session import Session, socket_path_for_project

    session = Session(
        mode=args.mode,
        project_gpr=args.project,
        socket_path=socket_path_for_project(args.project),
        ghidra_install_dir=args.ghidra_install_dir,
    )

    start_blocking(session)


if __name__ == "__main__":
    main()
