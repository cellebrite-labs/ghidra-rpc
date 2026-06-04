"""Session persistence for ghidra-rpc daemon."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Session:
    """Stores daemon session state so it can be reconstructed after restart."""

    mode: str  # "gui" or "headless"
    project_gpr: Path
    socket_path: Path
    ghidra_install_dir: Path | None = None  # persisted so restarts don't lose GHIDRA_INSTALL_DIR
    pid: int | None = None

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
    return Path(f"/tmp/ghidra-rpc-{digest}.sock")


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
        "pid": session.pid,
    }
    path.write_text(json.dumps(data, indent=2))


def load(gpr: Path) -> Session | None:
    """Load a previously saved session, or return None if not found."""
    path = session_file_path(gpr)
    if not path.exists():
        # Backward compat: check the legacy ~/.local/share/ghidra-rpc/ location
        # used by versions before GHIDRA_RPC_STATE_DIR support was added.
        digest = hashlib.sha256(str(gpr.resolve()).encode()).hexdigest()[:8]
        legacy_path = Path.home() / ".local" / "share" / "ghidra-rpc" / f"{digest}.json"
        if legacy_path.exists():
            path = legacy_path
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        ghidra_dir = data.get("ghidra_install_dir")
        return Session(
            mode=data["mode"],
            project_gpr=Path(data["project_gpr"]),
            socket_path=Path(data["socket_path"]),
            ghidra_install_dir=Path(ghidra_dir) if ghidra_dir else None,
            pid=data.get("pid"),
        )
    except (json.JSONDecodeError, KeyError):
        return None


def remove(gpr: Path) -> None:
    """Remove persisted session file."""
    path = session_file_path(gpr)
    if path.exists():
        path.unlink()
