# Quick Start

This guide walks you through a first session with ghidra-rpc.

## 1. Start the Daemon

Open a terminal and start the daemon. This blocks and shows logs:

```bash
# Headless (no GUI) — good for automated analysis
ghidra-rpc start --project /tmp/my-project.gpr --headless

# Or with GUI — see Ghidra's interface while working
ghidra-rpc start --project /tmp/my-project.gpr
```

For automation, start in the background (returns once the socket is responsive):
```bash
ghidra-rpc start --project /tmp/my-project.gpr --headless --detach
```

The project `.gpr` file will be created if it doesn't exist. Leave the foreground
terminal open (or use `--detach`).

## 2. Load a Binary

In a second terminal (or via the assistant's bash tool):

```bash
export GHIDRA_RPC_PROJECT=/tmp/my-project.gpr

# Load a binary — this imports it into the Ghidra project and runs auto-analysis
ghidra-rpc load /usr/bin/ls
```

Output:
```json
{"id": "...", "ok": true, "result": {"binary": "/ls-a1b2c3"}}
```

The binary key (e.g., `/ls-a1b2c3`) is what you'll use in subsequent commands.

## 3. Explore

```bash
# What architecture?
ghidra-rpc metadata ls

# List functions (use --limit/--offset for large binaries)
ghidra-rpc functions ls
ghidra-rpc functions ls --limit 50 --offset 0

# Search for interesting strings
ghidra-rpc strings ls "error" --limit 20

# Decompile a function (--timeout for slow/complex functions)
ghidra-rpc decompile ls main
ghidra-rpc decompile ls main --timeout 120
```

## 4. Investigate

```bash
# Who calls a particular function?
ghidra-rpc xrefs-to ls "strcmp"

# What does a function call? (--no-stack removes Stack[-0x…] noise)
ghidra-rpc xrefs-from ls main --no-stack
```

## 5. Annotate

```bash
# Rename a function you've identified
ghidra-rpc rename-function ls FUN_00401234 parse_arguments

# Add a comment
ghidra-rpc set-comment ls 0x00401234 "Parses CLI arguments" --type pre
```

## 6. Stop

```bash
ghidra-rpc stop
```

Or just Ctrl+C the daemon terminal. All programs are saved automatically on clean
shutdown. Write operations (rename, set-comment, etc.) also auto-save after each
change, so your edits survive restarts.

## Tips

- **Binary names are flexible**: You can use the full key (`/ls-a1b2c3`), just the name
  part (`ls-a1b2c3`), or even a substring if it's unambiguous (`ls`).
- **Function targets are flexible**: Use function name (`main`), hex address (`0x401000`),
  or partial name if unambiguous.
- **Auto-restart**: If the daemon crashes, commands will try to restart it automatically
  from the saved session. If that fails, you'll get a clear error message.
- **Write verification**: All write operations (rename, set-comment, set-signature,
  retype-variable, rename-variable) return a `verified` boolean confirming the change
  was committed.
- **Auto-save**: Every write operation saves to the project database on disk
  automatically. Changes survive daemon restarts and are visible when you reopen the
  project in the Ghidra GUI.
- **Signature semicolons**: Trailing `;` is stripped automatically — you can paste
  C prototypes verbatim.
- **Project programs vs loaded binaries**: `list-binaries` shows programs open in the
  daemon. `list-project-programs` shows everything in the project repo on disk.
