# Agent Instructions for ghidra-rpc

## What This Is

`ghidra-rpc` is a skill that wraps Ghidra's reverse engineering capabilities in a
CLI daemon communicating over Unix domain sockets. It lets an AI assistant analyze
binaries, decompile functions, trace cross-references, rename symbols, and annotate
findings — all by running `ghidra-rpc` commands from the shell.

## Project Layout

```
ghidra-rpc/
├── SKILL.md              — Skill prompt (what the assistant sees when triggered)
├── package.json          — pi package metadata
├── pyproject.toml        — Python package config (entry points, deps)
├── README.md             — Human-facing overview
├── CHANGELOG.md          — Notable changes per release (Keep a Changelog format)
│
├── docs/                 — Extended documentation (loaded on demand from SKILL.md)
│   ├── install.md        — Prerequisites, installation, GHIDRA_INSTALL_DIR setup
│   ├── quickstart.md     — First-session walkthrough
│   ├── troubleshooting.md — Common failure modes and fixes
│   ├── internals.md      — Implementation details: session persistence, known gotchas,
│   │                        Ghidra API reference, background-start mechanics
│   └── flows/            — Workflow guides for specific RE tasks
│       ├── binary-audit.md
│       ├── patch-analysis.md
│       ├── vulnerability-research.md
│       └── android-apk.md   — APK/DEX (Dalvik) loading + multi-dex caveat
│
├── ghidra_rpc/           — Python package
│   ├── __init__.py       — Version
│   ├── cli.py            — Click CLI (ghidra-rpc entry point, all user commands)
│   ├── client.py         — Unix socket client (send_request, auto-restart logic)
│   ├── daemon.py         — Daemon lifecycle (start_blocking, start_background, stop)
│   │                       start_background() explicitly forwards GHIDRA_INSTALL_DIR
│   │                       from session or current env to the child process.
│   ├── session.py        — Session persistence
│   │                       • Socket path: /tmp/ghidra-rpc-<hash>.sock
│   │                       • Session file: <gpr-dir>/.ghidra-rpc-<hash>.json (default)
│   │                         or $GHIDRA_RPC_STATE_DIR/<hash>.json
│   │                       • Fields: mode, project_gpr, socket_path, ghidra_install_dir
│   │
│   └── server/           — Daemon internals (runs inside Ghidra's JVM via pyghidra)
│       ├── __init__.py
│       ├── main.py       — Socket server, request dispatch, handler registry
│       ├── launcher.py   — Ghidra init (headless & GUI), macOS framework Python re-exec
│       ├── _gui_launcher.py — GUI launcher (adapted from pyghidra-mcp)
│       ├── context.py    — HeadlessContext, GuiContext, DecompilerPool, ProgramInfo,
│       │                   _run_analysis() (supports timeout + best-effort cancel)
│       └── tools/        — Command handlers (one module per domain)
│           ├── __init__.py     — register_all_tools()
│           ├── analysis.py     — load (analyze=, analysis_timeout=), list_binaries,
│           │                     list_project_programs, save, functions (with
│           │                     address_min/max range filter and with_body),
│           │                     imports, exports, metadata, relocations,
│           │                     list_calling_conventions
│           ├── decompiler.py   — decompile, _find_function (name/address resolution),
│           │                     search_decompiled (regex-search decompiled C across
│           │                     many functions in one call; optional class_filter)
│           ├── search.py       — strings, symbols, find_bytes (byte pattern search)
│           ├── xrefs.py        — xrefs_to (optional all_binaries: also searches every
│           │                     other loaded program for a matching fully-qualified
│           │                     symbol name and merges in real callers, tagged with
│           │                     a "binary" field — see _collect_xrefs_at/_program_key),
│           │                     xrefs_from
│           ├── navigation.py   — goto (GUI-only)
│           ├── bookmarks.py    — set_bookmark, list_bookmarks (type/category/address
│           │                     filters), remove_bookmark
│           ├── memory.py       — read_bytes (raw memory inspection), read_pointers
│           │                     (read + symbol-resolve a pointer table),
│           │                     write_bytes (raw memory patching),
│           │                     memory_map (list all memory segments/sections)
│           ├── cpp.py          — list_vtable (walk a vtable, resolve slots to
│           │                     methods; builds on read_pointers + xrefs)
│           ├── disassembly.py  — disassemble (warning field when address skipped;
│           │                     listing by default, with_instructions flag adds
│           │                     the structured per-instruction array),
│           │                     assemble (SLEIGH assembler: text → bytes)
│           ├── cfg.py          — basic_blocks (CFG from BasicBlockModel),
│           │                     pcode (raw listing P-code or high SSA P-code)
│           ├── tags.py         — tag_function, untag_function, list_tags,
│           │                     functions_by_tag
│           ├── data_types.py   — create_struct, create_union, create_enum,
│           │                     modify_enum, modify_struct,
│           │                     clear_data_range, apply_data_type_range,
│           │                     list_labels, list_data_types,
│           │                     set_equate (with enum-linking), list_equates
│           ├── version_tracking.py — version_track (Auto VT + BSim between
│           │                     two loaded binaries), match_function (find
│           │                     corresponding function via correlators),
│           │                     decompile_all (bulk decompile all functions),
│           │                     function_diff (normalised unified diff)
│           ├── processor_context.py — get_processor_context (read ISA register
│           │                     values at an address), set_processor_context
│           │                     (write ISA register over range — ARM TMode fix)
│           └── modifications.py — create_label, create_function,
│                                  delete_function (remove function definition),
│                                  rename_function (with --namespace), rename_symbol,
│                                  set_comment, batch_rename (many renames, one tx),
│                                  batch_set_comment (many comments, one tx),
│                                  set_function_signature, set_data_type,
│                                  retype_variable (with --timeout), rename_variable (with --timeout),
│                                  batch_edit_variables (rename/retype many locals
│                                    against one decompiler snapshot),
│                                  set_calling_convention, set_thunk, set_flow_override,
│                                  create_namespace, list_namespaces
│                                  _resolve_data_type() — type-name → Ghidra DataType
│                                  _resolve_namespace() — namespace path resolution
│                                  _sanitize_signature() — strips trailing `;` and
│                                    extracts inline calling conventions (__thiscall, etc.)
│
└── tests/
    ├── test_protocol.py         — Wire protocol tests (no Ghidra needed)
    ├── test_client.py           — Client + session tests (no Ghidra needed)
    ├── test_session_registry.py — Registry, discover-instances, list-instances CLI
    ├── test_cli.py              — General CLI-parsing tests (no Ghidra needed): the
    │                              JSON-usage-error contract in main(), set-comment's
    │                              --comment option, list-bookmarks --category
    ├── test_search_decompiled.py — search_decompiled handler logic (regex matching,
    │                              class_filter, limit/max_functions truncation) against
    │                              a fully mocked program; no Ghidra needed
    ├── test_integration.py      — End-to-end integration tests against a real headless
    │                              Ghidra daemon loading tests/fixtures/testapp, covering
    │                              every API domain.  Skipped unless GHIDRA_INSTALL_DIR is
    │                              set.  Uses a single module-scoped daemon fixture so
    │                              Ghidra starts only once per pytest run.
    └── fixtures/                — testapp (x86-64 ELF) + testapp.c, the committed test
                                    binary loaded by test_integration.py, plus
                                    dex/ (two real-world DEX fixtures for
                                    Dalvik-specific behavior; see fixtures/README.md)
```

## Architecture

```
User Terminal                      Background Process (same machine)
┌──────────────┐                  ┌─────────────────────────────────────┐
│  ghidra-rpc  │ ── Unix sock ──→ │  ghidra-rpc daemon                  │
│  CLI         │ ←── JSON ──────  │                                     │
│  (cli.py)    │                  │  server/main.py (socket listener)   │
│              │                  │  ├─ tools/*.py  (command handlers)  │
│  client.py   │                  │  └─ context.py  (Ghidra API calls)  │
│  (transport) │                  │                                     │
└──────────────┘                  │  PyGhidra (JVM + Ghidra in-process) │
                                  └─────────────────────────────────────┘
```

- **Wire protocol**: newline-delimited JSON over Unix domain socket
- **Request**: `{"id": "uuid", "cmd": "decompile", "args": {"binary": "...", "func": "..."}}`
- **Response**: `{"id": "uuid", "ok": true, "result": {...}}` or `{"id": "uuid", "ok": false, "error": "...", "message": "..."}`
- **Threading**: each client connection runs in its own thread; a global `_HANDLER_LOCK` in `main.py` serialises all command handler invocations to prevent Ghidra transaction conflicts
- **CLI-level errors are JSON too**: `cli.main()` calls `cli(standalone_mode=False)` and
  catches `click.ClickException` (bad options, unknown subcommands, invalid choices,
  missing required args) so they're reported as `{"ok": false, "error": ..., "message":
  ...}` on stdout with the same exit code Click would have used, instead of a plain-text
  usage string. `--help`/`--version` are unaffected (Click handles those via `Exit`,
  which is caught internally in non-standalone mode and returned as an exit code).

## Key Design Patterns

### Adding a New Command

1. Create or edit a file in `ghidra_rpc/server/tools/`.
2. Write a handler: `def _handle_foo(ctx, args: dict) -> dict`
   - `ctx` is a `HeadlessContext` or `GuiContext` (from `context.py`)
   - `args` is the `"args"` dict from the request
   - Return a dict (becomes `"result"` in the response)
   - Raise exceptions for errors (become `"error"` + `"message"`)
3. Register: `register_handler("foo", _handle_foo)` at module level.
4. Import the module in `tools/__init__.py` → `register_all_tools()` auto-registers it.
5. Add a CLI subcommand in `cli.py` that calls `_rpc_command(gpr, "foo", {...})`.

### Write Operations (Transactions + Save)

All Ghidra mutations need a transaction:
```python
from ghidra_rpc.server.tools.modifications import ghidra_transaction

with ghidra_transaction(pi.program, "description"):
    # Ghidra API calls that modify program state
```

After every write, call:
```python
ctx.save_program(pi)
```
`save_program` works in both modes: headless calls `project.save(program)`; GUI calls
`domainFile.save()` on the Swing EDT.

In GUI mode, wrap the full operation (transaction included) in `ctx.run_on_swing(fn)`.
The `_maybe_swing()` helper in `modifications.py` shows the pattern.

### Data-Type Resolution

Use `_resolve_data_type(program, type_str)` in `modifications.py` — it handles built-ins,
pointer decoration (`char *`), array decoration (`char[11]`), and DTM lookup by name/path.
Works in both headless and GUI mode. **Do not use** `ghidra.util.data.DataTypeParser` —
it requires a `DataTypeQueryService` that is only available in GUI mode.

### Function/Address Resolution

`_find_function(pi, target)` in `decompiler.py`:
- Hex addresses: `0x401000` → `getFunctionAt` / `getFunctionContaining`
- Exact name match (case-insensitive)
- Partial name match (if unambiguous)
- Clear errors for ambiguous or not-found

### GUI vs Headless

Both modes use the same tool handlers. Differences:
- **Headless**: `HeadlessContext` uses `GhidraProject` API directly. No Swing thread needed.
- **GUI**: `GuiContext` uses `run_on_swing()` for all Ghidra API calls. The `goto` command
  is GUI-only.

The check `if hasattr(ctx, "run_on_swing")` distinguishes modes.

## Development Workflow

### Setup
```bash
cd /path/to/ghidra-rpc
export GHIDRA_INSTALL_DIR=/path/to/ghidra
uv venv && uv pip install -e .
```

### Running Tests (no Ghidra needed)
```bash
python -m pytest tests/test_protocol.py tests/test_client.py tests/test_session_registry.py \
  tests/test_cli.py tests/test_search_decompiled.py -v
```

### Running Integration Tests (requires Ghidra)
```bash
# Starts a real headless daemon, loads tests/fixtures/testapp, exercises every API domain.
# First run is slow (JVM + analysis); budget ~10 min on a typical laptop.
GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/test_integration.py -v
```

### Manual Testing with Ghidra
```bash
# Terminal 1: foreground daemon (shows logs)
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  .venv/bin/python -m ghidra_rpc.cli start --project /tmp/test.gpr --headless

# Terminal 2: run commands
export GHIDRA_RPC_PROJECT=/tmp/test.gpr
uv run ghidra-rpc load /usr/bin/ls
uv run ghidra-rpc decompile ls main
```

## Key Gotchas

1. **Saving freshly imported programs**: Use `saveAs()` → `close()` → `openProgram()`,
   not `save()` directly — Ghidra raises `ReadOnlyException` on a freshly imported program.

2. **`DataTypeParser` is GUI-only**: Use `_resolve_data_type()` in `modifications.py`
   instead of `ghidra.util.data.DataTypeParser` (needs `DataTypeQueryService`).

3. **JVM memory**: Set `_JAVA_OPTIONS="-Xmx8g"` for large binaries to avoid OOM.

4. **Ghidra imports before JVM start**: Never import `ghidra.*` at module level in tool
   files — the JVM may not be started yet. Import inside handler functions.

5. **GUI restart timeout**: GUI startup can take > 60 s. `restart` defaults to 180 s and
   returns `ok: true` with a `"warning"` field if the socket exists but ping timed out.

6. **Handler serialisation**: All handler invocations are serialised by `_HANDLER_LOCK`.
   Never hold long-running resources across handler boundaries; the lock blocks all
   other commands until the current one completes.

7. **`list-instances`/`stop --all` glob real `/tmp`, not just the registry**: sockets
   always live in `/tmp` (not covered by `GHIDRA_RPC_STATE_DIR`), so any test touching
   `_discover_instances()` must also monkeypatch `cli._SOCKET_SCAN_DIR` to a `tmp_path` —
   otherwise it can see, and `stop --all` can actually kill, real daemons on the host.

8. **`ReferenceManager`/`SymbolTable` are per-`Program`, not per-project**: two loaded
   binaries never share reference/symbol data, even byte-identical ones. A reference
   whose source and target live in two different loaded programs is invisible to any
   single-program lookup — there is no cross-program equivalent to call. When a feature
   needs to look something up across every loaded binary (e.g. `xrefs_to`'s
   `all_binaries` option), iterate `ctx.programs` yourself and match by fully-qualified
   symbol name (`Symbol.getName(True)`) via `SymbolTable.getSymbols(leafName)` (indexed
   by leaf name, then filter on the full qualified name) — don't assume Ghidra resolves
   this for you. First hit on DEX (`invoke-*` to a method in another `classesN.dex`
   resolves only to a local placeholder symbol, not the real function), but it's a
   general multi-binary limitation, not Dalvik-specific.

> For more detail on all gotchas plus the Ghidra API reference and session/daemon
> internals, read **`docs/internals.md`**.
