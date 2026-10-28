# ghidra-rpc — Implementation Internals

Read this when you are **adding new commands, debugging Ghidra API issues, or working
on the daemon internals**. For everyday RE workflows, `SKILL.md` is enough.

## Session Persistence

Session files are JSON blobs that let `restart` and `send_request_with_auto_restart`
recreate the daemon without the user having to pass `--mode` / `--headless` again.

**File location** (resolution order):
1. `$GHIDRA_RPC_STATE_DIR/<hash>.json` — if the env var is set
2. `<gpr-parent>/.ghidra-rpc-<hash>.json` — alongside the project file (default)
3. Backward compat: `~/.local/share/ghidra-rpc/<hash>.json` — checked by `load()` only

**Fields stored**: `mode`, `project_gpr`, `socket_path`, `ghidra_install_dir`
(`ghidra_install_dir` is `null` when not explicitly provided).

**`GHIDRA_INSTALL_DIR` propagation**: `start_background()` builds the subprocess env
from `session.ghidra_install_dir` → current `GHIDRA_INSTALL_DIR` → nothing, in that
order. This ensures the daemon child gets the right env var even when launched from
cron/systemd/nohup contexts that strip non-standard env vars.

**The session file gets written twice, by two different processes** — once by
`start_background()` in the parent (CLI) process, and again moments later by the
detached child's own `main()` → `start_blocking()`, which reconstructs a fresh
`Session` from its own argv (`--mode`, `--project`, `--ghidra-install-dir`) and
re-saves it as part of normal startup. If the child doesn't receive
`--ghidra-install-dir` too, its re-save silently overwrites the parent's correct
value with `null` — this was a real bug (fixed in `start_background()`'s subprocess
`cmd` construction and `main()`'s argparse), not a hypothetical one. Anything that
changes what the child process is launched with needs to keep this in mind.

## Background Start & Logs

`start_background()` in `daemon.py`:
1. Saves the session file.
2. Spawns `python -m ghidra_rpc.daemon --mode … --project … [--ghidra-install-dir …]`
   detached so the child survives the parent's exit — `start_new_session=True`
   (setsid) on POSIX, `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
   CREATE_BREAKAWAY_FROM_JOB` on Windows, where `start_new_session` is silently
   ignored. The breakaway flag is not optional decoration: a launcher that puts its
   children in a Job Object (OpenSSH's `sshd` does) kills every process still in
   that job when the job closes, and neither `DETACHED_PROCESS` nor
   `CREATE_NEW_PROCESS_GROUP` removes a child from its parent's job — only
   `CREATE_BREAKAWAY_FROM_JOB` does. Verified on a real Windows VM: without it, a
   detached daemon vanished within ~1s of the launching ssh session closing, no
   shutdown log entry, nothing left in `tasklist`. A job can itself forbid
   breakaway (`JOB_OBJECT_LIMIT_BREAKAWAY_OK` unset), which makes `CreateProcess`
   fail outright rather than silently ignore the flag, so `start_background()`
   retries once without it in that case rather than failing the start.
3. Polls the local endpoint (0.5 s interval) until it's responsive or the timeout expires.
4. On timeout the error message includes the log file path.

Log file: `/tmp/ghidra-rpc-<hash>.log` on Unix or
`%LOCALAPPDATA%\ghidra-rpc\ghidra-rpc-<hash>.log` on Windows (same stem as the
endpoint). On Unix, inspect it with:
```
tail -50 /tmp/ghidra-rpc-*.log
```

## GUI Mode Project Matching

`GuiContext._wait_for_project()` polls `AppInfo.getActiveProject()` (0.5 s interval,
240 s timeout) until it returns a project matching the one requested, since
`GuiRpcLauncher._launch()` opens Ghidra's GUI in a background Java thread with no
other synchronous signal that the project actually opened. `_project_matches()`
identifies a match by comparing `ProjectLocator.getLocation()` (the containing
directory) and `.getName()` (the project name) against `session.project_gpr`.

**Windows-only bug, fixed**: `ProjectLocator.getLocation()` is URL-derived and on
Windows returns a leading slash before the drive letter, e.g. `/C:/test/` (the
same convention as `file:///C:/test/`'s path component). `pathlib` does not know
this convention — `Path("/C:/test/").resolve()` parses it as *drive-relative*
(`WindowsPath('C:test')`, no root) rather than absolute, so it can never equal an
expected absolute path. This made `_project_matches()` unconditionally `False` on
Windows, for every project, forever: `_wait_for_project()` always ran out its full
240 s and raised, even when Ghidra had opened the exact right project seconds
after starting — confirmed by watching a real Windows GUI session open normally
while the daemon's own `status` still reported `running: false`.
`GuiContext._normalize_project_location()` strips that leading slash before the
comparison (no-op on POSIX, where a location never starts with `/<letter>:`).
Covered by `tests/test_gui_context.py` (pure Python, no Ghidra needed — a fake
locator stands in for the real `ProjectLocator`).

## Local Transport

Linux and macOS use the original Unix domain socket transport. Windows Python
builds do not consistently provide `AF_UNIX`, so Windows uses a TCP listener bound
only to `127.0.0.1`. Its temporary endpoint file contains the chosen port and a
random authentication token; every client request must present that token. The
wire format remains newline-delimited JSON on every platform.

## Address Format

Every address in a result goes through `_fmt_address()` in `context.py`, the
inverse of `_parse_address()`:

| Space | `Address.toString()` | Emitted |
|-------|---------------------|---------|
| default (`ram`) | `00101139` | `0x00101139` |
| other (`EXTERNAL`, `register`, `const`, `unique`, ...) | `EXTERNAL:00000001` | `EXTERNAL:0x00000001` |
| overlay | `ov1::00001000` | `ov1::0x00001000` |
| stack | `Stack[-0x10]` | `Stack[-0x10]` (unchanged) |

Ghidra's zero-padding is kept, so `0x00101139` lines up with `FUN_00101139`.
`AddressFactory.getAddress()` itself accepts `0x` and `space:`/`overlay::`
qualifiers, so `_parse_address()` passes the string straight through; the
round-trip was verified for every space of the test ELF plus an overlay.

`_looks_like_address()` (the `0x<hex>` tail, optionally space-qualified) is
what `_find_function()` and `xrefs._resolve_address()` use to decide that a
target is an address. Address-shaped input that hits no function raises rather
than falling through to name matching. Bare hex stays a name query, but never
partial-matches `SourceType.DEFAULT` names (`FUN_...`): otherwise `1139` would
silently resolve to whichever auto-named function contains those digits.

New handlers must emit addresses with `_fmt_address()`, never `str(addr)`.

## Analysis Control (`load --no-analyze`, `--analysis-timeout`)

`_run_analysis(flat_api, program, *, timeout)` in `context.py`:
- `timeout=None` → runs `flat_api.analyzeAll(program)` synchronously (blocks).
- `timeout=N` → runs analysis in a daemon thread; after N seconds tries to cancel via
  `AutoAnalysisManager.cancelCurrentAnalysis()` (best-effort). Returns `True` if
  analysis finished normally, `False` if interrupted by timeout.

`HeadlessContext.load_binary` only calls `GhidraProgramUtilities.setAnalyzedFlag(True)`
when `_run_analysis` returns `True`, so partial-analysis programs remain marked as
unanalyzed in Ghidra's database.

The `load` RPC response always includes `"analysis_complete": bool`.

## Known Implementation Gotchas

### 1. DecompilerPool lock
`acquire()` checks pool capacity *under* the lock but calls `_create()` *outside* it to
avoid holding the lock during the (slow) decompiler init. The lock is a non-reentrant
`threading.Lock`. Don't call `acquire()` from inside a context that already holds it.

### 2. Saving freshly imported programs
Ghidra raises `ReadOnlyException` if you call `project.save()` on a program that was
just imported and has never been saved to the project repo. The correct sequence is:
`saveAs(prog, "/", name, True)` → `close(prog)` → `openProgram("/", name, False)`.

### 3. JVM heap for large binaries
Set `_JAVA_OPTIONS="-Xmx8g"` (or more) before starting the daemon when analysing
binaries > 50 MB. Ghidra's analysis engine is memory-hungry.

### 4. venv conflicts
Don't run `uv pip install -e .` while a daemon is alive from the same venv — it may
replace entry-point scripts that the running daemon has open. Use
`python -m ghidra_rpc.cli` directly, or stop the daemon first.

### 5. `DataTypeParser` is GUI-only
`ghidra.util.data.DataTypeParser` requires a `DataTypeQueryService` which is only
available in GUI mode. Use `_resolve_data_type()` in `modifications.py` instead —
it works in both headless and GUI mode by implementing the common cases directly.

### 6. `HighFunctionDBUtil.updateDBVariable` signature
Takes a `HighSymbol` (not `HighVariable`). Obtain it from
`HighFunction.getLocalSymbolMap().getSymbols()`. See `_handle_retype_variable` in
`modifications.py` for the full pattern.

### 7. GUI program discovery
`GuiContext.refresh_programs` uses two sources:
1. Programs open in running tools (via `ProgramManager` service).
2. Project-folder files (via `getDomainObject`).
Source 2 is a fallback; opening a program in CodeBrowser first (source 1) is the most
reliable path. Document this clearly to users.

### 8. GUI restart timeout
Ghidra GUI startup (JVM boot + window + project load) regularly takes 60–120 s on cold
hardware. `restart` defaults to **180 s** in GUI mode to accommodate this. The CLI
returns `ok: true` with a `"warning"` field (not an error) when the daemon starts but
doesn't become ping-responsive within the timeout, because the socket file exists and
the server is almost certainly alive.

### 9. macOS framework Python
GUI mode requires the macOS "framework Python" for proper Swing integration. `launcher.py`
detects this and re-execs via the framework path before the JVM is started. If the
framework Python does not exist (non-standard install), GUI mode will fail; use
`--headless` as a fallback.

### 10. `_JAVA_OPTIONS` vs module-level import
`pyghidra.start()` (headless) and `GuiRpcLauncher.start()` (GUI) must be called before
any `ghidra.*` Java imports. Importing Ghidra classes at module level in a tool file
will cause `NoClassDefFoundError` on daemon start.

### 11. Namespace resolution
`_resolve_namespace()` in `modifications.py` handles both simple names (direct child
of global namespace) and path-style names with `::` or `/` separators. Example:
`"Outer::Inner"` resolves by walking from the global namespace through `Outer` to `Inner`.

### 12. BasicBlockModel vs DecompilerBasicBlocks
`basic-blocks` uses `BasicBlockModel` from the listing (no decompilation needed).
This is faster and works even on functions the decompiler fails on. The decompiler's
`HighFunction.getBasicBlocks()` gives an SSA-optimized view but requires a full
decompilation pass — not used here.

### 13. P-code modes
- **Raw P-code** (`Instruction.getPcode()`): one-to-one with machine instructions.
  Fast, no decompiler dependency.
- **High P-code** (`HighFunction.getPcodeOps()`): SSA form with resolved variable
  names and data types. Requires a decompilation pass (60 s default timeout).

### 14. Function tags vs bookmarks
Both are annotation mechanisms. **Tags** attach to functions (classification) while
**bookmarks** attach to addresses (location markers). An AI should use tags for
function-level progress tracking and bookmarks for address-level findings.

### 15. `_discover_instances()` socket glob and test isolation
`cli._discover_instances()` (backing `list-instances` and `stop --all`) merges the
session registry with a raw glob over `cli._SOCKET_SCAN_DIR` (the platform temporary
directory) to catch endpoints from daemons that predate the registry, or were started
manually. Because endpoints always live in that directory
(`session.socket_path_for_project` is not configurable),
this glob is **not** covered by the `GHIDRA_RPC_STATE_DIR` env var that isolates the
registry file in tests. Any test that exercises `list-instances`/`stop --all` (or calls
`_discover_instances()` directly) must also monkeypatch `cli._SOCKET_SCAN_DIR` to a
`tmp_path`, or it will see — and `stop --all` will actually stop — real daemons running
on the host. See `tests/test_session_registry.py`'s `isolate_registry` fixtures for the
pattern.

## Ghidra API Quick Reference

Full javadoc: `$GHIDRA_INSTALL_DIR/docs/GhidraAPI_javadoc.zip`  
Quick extraction:
```bash
unzip -p $GHIDRA_INSTALL_DIR/docs/GhidraAPI_javadoc.zip api/<path>.html | python3 -c "
import sys, re
txt = re.sub('<[^>]+>', ' ', sys.stdin.read())
print(re.sub(r'\s+', ' ', txt)[:2000])
"
```

| Package | Contents |
|---------|----------|
| `ghidra.program.model.listing` | `Program`, `Listing`, `Function`, `CodeUnit`, `Data` |
| `ghidra.program.model.data` | All data types: `CharDataType`, `ArrayDataType`, `PointerDataType`, … |
| `ghidra.program.model.symbol` | `SymbolTable`, `Symbol`, `SourceType`, `ReferenceManager` |
| `ghidra.program.model.pcode` | `HighFunction`, `HighSymbol`, `HighFunctionDBUtil` |
| `ghidra.program.model.mem` | `Memory`, `MemoryBlock`, `MemoryAccessException` |
| `ghidra.app.decompiler` | `DecompInterface`, `DecompileOptions`, `DecompileResults` |
| `ghidra.util.data` | `DataTypeParser` (GUI-only, needs `DataTypeQueryService`) |
| `ghidra.program.flatapi` | `FlatProgramAPI` — high-level scripting helpers (`getBytes`, etc.) |
| `ghidra.app.plugin.core.analysis` | `AutoAnalysisManager` — start/cancel analysis |

## Reference Project: pyghidra-mcp

The original design was based on [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp).
Useful files to consult when working on low-level Ghidra integration:

| File | Useful for |
|------|-----------|
| `gui_launcher.py` | GUI mode JVM lifecycle, macOS framework Python re-exec |
| `gui_context.py` | Swing thread safety, program management, `run_on_swing` pattern |
| `context.py` | Headless project management, `ProgramInfo` dataclass patterns |
| `tools.py` | Reference implementations: decompile, rename, xrefs, etc. |
| `decompiler_pool.py` | Thread-safe decompiler instance pool |
