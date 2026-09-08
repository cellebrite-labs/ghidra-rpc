"""Session persistence for ghidra-rpc daemon."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl

from ghidra_rpc.transport import endpoint_directory, windows_state_dir


@dataclass
class Session:
    """Stores daemon session state so it can be reconstructed after restart."""

    mode: str  # "gui" or "headless"
    project_gpr: Path
    socket_path: Path
    ghidra_install_dir: Path | None = None  # persisted so restarts don't lose GHIDRA_INSTALL_DIR

    def __post_init__(self):
        self.project_gpr = Path(self.project_gpr)
        self.socket_path = Path(self.socket_path)
        if self.ghidra_install_dir is not None:
            self.ghidra_install_dir = Path(self.ghidra_install_dir)


def socket_path_for_project(gpr: Path) -> Path:
    """Derive a deterministic socket path from a .gpr project path.

    Uses an 8-character hash of the absolute path so each project gets
    its own socket without collisions.
    """
    digest = hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]
    return endpoint_directory() / f"ghidra-rpc-{digest}.sock"


def session_file_path(gpr: Path) -> Path:
    """Return the path where session state is persisted for a given project.

    Resolution order:
    1. ``$GHIDRA_RPC_STATE_DIR/<hash>.json`` — if the env var is set.
    2. ``<gpr-parent>/.ghidra-rpc-<hash>.json`` — alongside the project file
       (default; keeps ephemeral / sandboxed analyses self-contained).
    """
    digest = hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]
    state_dir_env = os.environ.get("GHIDRA_RPC_STATE_DIR")
    if state_dir_env:
        return Path(state_dir_env) / f"{digest}.json"
    # Default: next to the .gpr file so session data stays with the project.
    return gpr.resolve().parent / f".ghidra-rpc-{digest}.json"


def save(session: Session) -> None:
    """Persist session to disk."""
    path = session_file_path(session.project_gpr)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "mode": session.mode,
        "project_gpr": str(session.project_gpr.resolve()),
        "socket_path": str(session.socket_path),
        "ghidra_install_dir": str(session.ghidra_install_dir) if session.ghidra_install_dir else None,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load(gpr: Path) -> Session | None:
    """Load a previously saved session, or return None if not found."""
    path = session_file_path(gpr)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ghidra_dir = data.get("ghidra_install_dir")
        return Session(
            mode=data["mode"],
            project_gpr=Path(data["project_gpr"]),
            socket_path=Path(data["socket_path"]),
            ghidra_install_dir=Path(ghidra_dir) if ghidra_dir else None,
        )
    except (json.JSONDecodeError, KeyError):
        return None


def remove(gpr: Path) -> None:
    """Remove persisted session file."""
    path = session_file_path(gpr)
    if path.exists():
        path.unlink()


# ─── Global session registry ───────────────────────────────────────────────────
# The registry is a single JSON file that indexes every active session so that
# `list-instances` can enumerate them without knowing the project paths upfront.
#
# Location priority:
#   1. $GHIDRA_RPC_STATE_DIR/sessions.json   (explicit override)
#   2. ~/Library/Application Support/ghidra-rpc/sessions.json  (macOS)
#   3. $XDG_STATE_HOME/ghidra-rpc/sessions.json                (Linux, if set)
#   4. ~/.local/state/ghidra-rpc/sessions.json                 (Linux default)
#
# All reads/writes are protected by an exclusive cross-platform file lock so
# concurrent daemon starts don't corrupt the file. Registry failures are
# non-fatal — callers degrade gracefully to endpoint-directory globbing.


@contextmanager
def _registry_lock(path: Path):
    """Hold an exclusive lock associated with *path*."""
    lock_path = path.with_name(f"{path.name}.lock")
    with open(lock_path, "a+b") as lock_file:
        if os.name == "nt":
            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_file, fcntl.LOCK_UN)


def _registry_path() -> Path:
    """Return the path to the global session registry file."""
    state_dir = os.environ.get("GHIDRA_RPC_STATE_DIR")
    if state_dir:
        return Path(state_dir) / "sessions.json"
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "ghidra-rpc"
    elif sys.platform == "win32":
        base = windows_state_dir()
    else:
        xdg = os.environ.get("XDG_STATE_HOME")
        base = Path(xdg) / "ghidra-rpc" if xdg else Path.home() / ".local" / "state" / "ghidra-rpc"
    return base / "sessions.json"


def register(session: Session) -> None:
    """Upsert a session into the global registry (lock-protected, non-fatal)."""
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(str(session.project_gpr.resolve()).encode()).hexdigest()[:8]
    entry = {
        "project_gpr":       str(session.project_gpr.resolve()),
        "socket_path":       str(session.socket_path),
        "mode":              session.mode,
        "ghidra_install_dir": str(session.ghidra_install_dir) if session.ghidra_install_dir else None,
    }
    try:
        with _registry_lock(path):
            with open(path, "a+", encoding="utf-8") as fh:
                fh.seek(0)
                content = fh.read()
                try:
                    registry = json.loads(content) if content.strip() else {}
                except json.JSONDecodeError:
                    registry = {}
                registry[digest] = entry
                fh.seek(0)
                fh.truncate()
                fh.write(json.dumps(registry, indent=2))
    except OSError:
        pass  # Non-fatal: list-instances degrades to endpoint-directory globbing


def unregister(gpr: Path) -> None:
    """Remove a session from the global registry (lock-protected, non-fatal)."""
    path = _registry_path()
    if not path.exists():
        return
    digest = hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]
    try:
        with _registry_lock(path):
            with open(path, "r+", encoding="utf-8") as fh:
                content = fh.read()
                try:
                    registry = json.loads(content) if content.strip() else {}
                except json.JSONDecodeError:
                    return
                if digest not in registry:
                    return
                del registry[digest]
                fh.seek(0)
                fh.truncate()
                fh.write(json.dumps(registry, indent=2))
    except OSError:
        pass


def load_all() -> list["Session"]:
    """Return all sessions from the global registry (empty list on any error)."""
    path = _registry_path()
    if not path.exists():
        return []
    try:
        with _registry_lock(path):
            content = path.read_text(encoding="utf-8")
            registry = json.loads(content) if content.strip() else {}
    except (json.JSONDecodeError, OSError):
        return []
    sessions = []
    for entry in registry.values():
        try:
            ghidra_dir = entry.get("ghidra_install_dir")
            sessions.append(Session(
                mode=entry["mode"],
                project_gpr=Path(entry["project_gpr"]),
                socket_path=Path(entry["socket_path"]),
                ghidra_install_dir=Path(ghidra_dir) if ghidra_dir else None,
            ))
        except (KeyError, TypeError):
            continue
    return sessions
