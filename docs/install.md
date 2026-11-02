# Installing ghidra-rpc

## Prerequisites

1. **Ghidra** (11.0+): Download from [ghidra-sre.org](https://ghidra-sre.org/), unzip somewhere.
2. **Python 3.11+**: Check with `python3 --version`.
3. **uv**: Install with `curl -LsSf https://astral.sh/uv/install.sh | sh`.
4. **Java 17+**: Required by Ghidra. Check with `java --version`.

## Set GHIDRA_INSTALL_DIR

Point this at your Ghidra installation directory (the one containing `ghidraRun`):

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.3
```

On Windows PowerShell, point it at the directory containing `ghidraRun.bat`:

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_11.3'
```

The daemon will refuse to start without this.

## Install ghidra-rpc

```bash
# From the ghidra-rpc directory
uv tool install /path/to/ghidra-rpc

# Or for development
uv pip install -e /path/to/ghidra-rpc
```

The same `uv tool install` command works on Windows with a Windows path.

## Windows Notes

Prerequisites are the same as on Unix: Ghidra 11+, Python 3.11+, Java 17+, uv.
A few things differ.

**GUI mode works, including `goto`** — verified end-to-end on a real Windows
VM: `start` (no `--headless`), `load`, and `goto` all confirmed working
against a live GUI session. It needed one fix first: Ghidra's
`ProjectLocator.getLocation()` returns Windows paths with a leading slash
before the drive letter (`/C:/test/`), which `pathlib` silently misparsed as
a drive-relative path rather than an absolute one — so the daemon's own
readiness check could never recognize the project as open, and every
GUI-mode `start` timed out after 240s regardless of whether Ghidra had
actually opened it correctly. See `docs/internals.md` for the fix
(`GuiContext._normalize_project_location`).

**Transport.** CPython on Windows exposes no `AF_UNIX`, so the daemon listens on
a TCP socket bound to `127.0.0.1` instead of a socket file. A loopback port is
reachable by every process on the machine, so the daemon mints a random token at
startup and rejects any request that does not carry it. The port and token live
in a per-user descriptor at
`%LOCALAPPDATA%\ghidra-rpc\ghidra-rpc-<hash>.sock` — treat that file as a
credential. Nothing changes on Linux or macOS, and the wire protocol and CLI are
identical on all three.

Set `GHIDRA_INSTALL_DIR` with Windows syntax — in `cmd`:

```bat
set GHIDRA_INSTALL_DIR=C:\Tools\ghidra_11.3
```

or persist it with `setx GHIDRA_INSTALL_DIR "C:\Tools\ghidra_11.3"`.

## Verify Installation

```bash
ghidra-rpc --version
# Should print: ghidra-rpc, version 0.3.0
```

## What Gets Installed

- `ghidra-rpc` — the CLI you'll use for all commands
- `ghidra-rpcd` — standalone daemon entry point (`ghidra_rpc.daemon:main`); `start --detach`,
  `restart` and auto-restart run the same module via `python -m ghidra_rpc.daemon`

Both are Python entry points managed by uv. No global packages are modified.

## Dependencies

Installed automatically:
- `pyghidra` — Python bindings for Ghidra
- `click` — CLI framework
- `jpype1` — Java/Python bridge (used by pyghidra)
