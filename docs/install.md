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

The daemon will refuse to start without this.

## Install ghidra-rpc

```bash
# From the ghidra-rpc directory
uv tool install /path/to/ghidra-rpc

# Or for development
uv pip install -e /path/to/ghidra-rpc
```

## Verify Installation

```bash
ghidra-rpc --version
# Should print: ghidra-rpc, version 0.2.0
```

## What Gets Installed

- `ghidra-rpc` — the CLI you'll use for all commands
- `ghidra-rpcd` — the background daemon entry point (used internally by `ghidra-rpc restart`)

Both are Python entry points managed by uv. No global packages are modified.

## Dependencies

Installed automatically:
- `pyghidra` — Python bindings for Ghidra
- `click` — CLI framework
- `jpype1` — Java/Python bridge (used by pyghidra)

## Windows support

ghidra-rpc is Unix-first, but the daemon can run on Windows thanks to the
cross-platform transport module (`ghidra_rpc/transport.py`).

- **IPC transport**: on Windows CPython does not reliably expose `AF_UNIX` /
  `AF_PIPE`, so the daemon listens on a **TCP loopback** endpoint
  (`tcp:127.0.0.1:<port>`) instead of a Unix socket file. The port is derived
  deterministically from the project-path hash (`40000..59999`), so client and
  daemon agree across restarts. On POSIX nothing changes (still a Unix socket).
- **Env var**: set `GHIDRA_INSTALL_DIR` with Windows syntax, e.g. in cmd
  `set GHIDRA_INSTALL_DIR=C:\tools\ghidra_12.1.3_PUBLIC`, or persist via
  `setx GHIDRA_INSTALL_DIR "C:\tools\ghidra_12.1.3_PUBLIC"`.
- **Daemon detach**: `start_new_session` (POSIX `setsid`) is replaced by
  `CREATE_NEW_PROCESS_GROUP` on Windows.
- **Registry locking**: the global session registry uses `fcntl` (POSIX-only);
  on Windows the lock degrades to a best-effort no-op. A stale-registry prune
  still works.

Caveats:
- The deterministic TCP port has a low collision probability; if it is already
  in use the daemon's `bind` fails (rare).
- The `/tmp` socket scan path in `cli.py` is POSIX-only; `list-instances` still
  works on Windows because the session registry is the source of truth.
- Windows prerequisites are the same as POSIX: Ghidra 11+, Python 3.11+,
  Java 17+, uv.
