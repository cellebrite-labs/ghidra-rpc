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
Two things differ.

**Headless only.** Run the daemon with `--headless`. GUI mode has not been
verified on Windows and the `goto` command, which is GUI-only, is unavailable
there in practice.

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
