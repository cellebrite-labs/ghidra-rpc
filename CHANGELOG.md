# Changelog

## [Unreleased]

### Added

- `search-decompiled` reports which functions it actually covered:
  `scanned_range` (`{min, max}` entry addresses searched) and
  `next_unscanned_address` (where to resume, `null` when coverage is
  complete). New `--address-min`/`--address-max` restrict the sweep, so a
  truncated search can be resumed without re-decompiling what was covered.
- **Full Windows support: headless and GUI mode.**
  - **Transport**: `ghidra_rpc/transport.py` abstracts the IPC layer.
    Windows (no `AF_UNIX`) uses a token-authenticated TCP listener on
    `127.0.0.1` instead of a Unix domain socket; port/token live in
    `%LOCALAPPDATA%\ghidra-rpc\ghidra-rpc-<hash>.sock`. Wire format and CLI
    are unchanged on all platforms.
  - **`--detach`**: uses `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
    CREATE_BREAKAWAY_FROM_JOB` on Windows (`start_new_session` is a no-op
    there). `CREATE_BREAKAWAY_FROM_JOB` is required for the daemon to
    survive launchers that use Job Objects, e.g. OpenSSH's `sshd`.
  - **GUI mode**: now works on Windows. Fixed
    `GuiContext._normalize_project_location()` to handle
    `ProjectLocator.getLocation()`'s leading-slash-before-drive-letter form
    (`/C:/test/`), which `pathlib` misparsed as a relative path, making the
    daemon's project-open check always fail.
  - **CI**: `tests.yml` (unit suite, Ubuntu/macOS/Windows) and
    `integration.yml` (Ghidra integration suite) cover headless Windows. GUI
    mode has no CI coverage (no display in the runner).

### Changed

- `version-track` and `match-function` take `--socket-timeout` (default
  1800 s) like the other bulk commands, instead of the 120 s client default.
- Removed `version-track --ref-min-score`/`--ref-min-conf`; they were never
  passed to the correlators.
- **Breaking:** every address in command output is now `0x`-prefixed
  (`0x00101139`; space-qualified as `EXTERNAL:0x00000001` /
  `ov1::0x00001000`; stack offsets unchanged as `Stack[-0x10]`), so output
  addresses can be passed back to any command as-is. Includes the
  `read-bytes` hexdump and `disassemble` listing address columns.
- **Breaking:** a bare-hex function target (e.g. `00101139`) no longer
  partial-matches auto-generated names like `FUN_00101139`; pass `0x00101139`.
  A `0x` target with no function at or containing it now errors instead of
  falling back to name matching.
- Function lookups that find nothing now suggest passing addresses with a `0x`
  prefix, and ambiguous-name suggestions print entry addresses as `0x...`.
- `search-decompiled` rejects `--limit`/`--max-scan` below 1.
- `functions` and `search-decompiled` reject an `--address-min` above
  `--address-max` instead of returning an empty result.
- **Breaking:** `disassemble` no longer returns the `instructions` array by
  default — it was a verbatim duplicate of the `listing` string, which already
  carries every field it did (address, bytes, mnemonic, operands, EOL comment;
  only `length` is absent, and that is the byte count). Pass
  `--with-instructions` when you need the machine-parseable array. The default
  response is roughly a quarter the size, measured across `--count` 8 to 500.
  `ghidra-rpc disassemble <binary> <address>` now returns
  `{address, count, listing}`; add `--with-instructions` for the previous shape.

### Fixed

- `set-equate` VALUE and `create-enum` VALUEs accept negative numbers (`-1`,
  `-0x10`, `-0b1`); Click rejected them as unknown options. A mistyped option
  on these commands is still reported as `No such option`.
- `create-struct`/`create-union`/`create-enum --or-replace` remove the old
  type in the same transaction that builds the new one, so a definition that
  fails (e.g. an unknown field type) leaves the existing type intact instead
  of deleting it.
- Name lookups for `set-comment`, `xrefs-to`/`xrefs-from` and `list-vtable`
  prefer an exact label over a function that merely contains the name
  (`g_config` no longer resolves to `init_g_config`).
- `start --detach` and `restart` report a daemon that exits during startup
  (e.g. a bad `GHIDRA_INSTALL_DIR`) as JSON (`StartFailed`/`RestartFailed`,
  with the log tail) instead of a Python traceback.
- Auto-restart of a GUI-mode daemon waits 180 s like `start`/`restart` (was
  60 s), and its error keeps the underlying cause.
- `tag-function` trims the tag once: whitespace around `--tag` no longer
  leaves an unused tag behind.
- `retype-variable`/`rename-variable` verify with the `--timeout` decompile
  budget instead of a fixed 30 s, so a slow function no longer reports
  `verified: false` for an edit that applied.
- The CLI no longer gives up on long-running commands while the daemon is
  still working: `load` without `--analysis-timeout` waits for analysis to
  finish (was 120 s); `function-diff` and `batch-edit-variable` wait for both
  of their decompiles, as do `retype-variable`/`rename-variable` (edit plus
  verify).
- `version-track` and `match-function` reject the same binary as both source
  and destination, and are rejected in GUI mode, instead of dropping the
  binary from the daemon until it is re-`load`ed. A failure while opening the
  programs or creating the VT session no longer drops them either.
- GUI mode: closing the CodeBrowser that had a program open no longer
  leaves the daemon serving the closed program (`ClosedException: File is
  closed`) until restart; it switches to the project-folder copy. Programs
  opened from the project folder are no longer re-opened on every command,
  which stacked an unreleased Ghidra consumer each time.
- **Breaking:** `set-comment`/`batch-set-comment` follow the 0x-prefix rule: a function
  named like hex (`add`, `cafe`) is resolved by name, not taken as address
  `0xadd`. Bare hex is now a name query, as in every other command. A name
  that matches no function now also resolves as a label, as in `xrefs-to`.
- `xrefs-to`/`xrefs-from`/`list-vtable`/`set-comment` keep the function
  lookup's error when a name resolves to nothing, so an ambiguous name lists
  its candidates instead of "Cannot resolve target".
- Argument errors found after option parsing now use the JSON error envelope
  with exit code 2, like other usage errors. Before, a malformed
  `--json-file` on `batch-rename`/`batch-set-comment`/`batch-edit-variable`
  and a non-integer VALUE for `create-enum`, `modify-enum --add` or
  `set-equate` crashed with a Python traceback. Bad inline `--json`, missing
  `--json`/`--json-file`, unpaired `create-struct`/`create-union`/`create-enum`
  tokens, `modify-struct` without a field or change, and a missing project
  printed plain text to stderr with exit code 1.
- `write-bytes` docs (`SKILL.md`, `--help`, handler docstring) said a patch
  only leaves the listing stale and suggested `disassemble` to refresh it.
  Writing over a disassembled instruction is rejected, and `disassemble` only
  reads. They now describe the working route: `clear-data-range`, then
  `write-bytes`, then `assemble`.
- `xrefs-to` on an import's `EXTERNAL:` address now follows the full thunk
  chain, so it returns the real call sites instead of only the GOT slot and
  thunk (on x86-64 ELF the PLT thunk targets an intermediate thunk, not the
  EXTERNAL function).
- `--detach`'d daemons lost their persisted `ghidra_install_dir` moments
  after starting, on every platform: the detached child re-saves its own
  `Session` from bare `--mode`/`--project` argv, clobbering the parent's
  value with `null`. This broke `send_request_with_auto_restart` healing a
  dead daemon from an environment without `GHIDRA_INSTALL_DIR` set (cron,
  sudo, a bare ssh call). Fixed by passing `--ghidra-install-dir` to the
  child too.

- Tests: socket-binding tests now use a short temp directory. macOS caps
  `AF_UNIX` `sun_path` at 104 bytes (Linux allows 108) and pytest's `tmp_path`
  there is rooted under `/private/var/folders/<random>/T/...`, already ~120
  bytes, so every test that bound a socket failed with
  `OSError: AF_UNIX path too long`. A `short_tmp_path` fixture in
  `tests/conftest.py` roots those under `/tmp` instead. Test-harness only —
  real endpoints are `/tmp/ghidra-rpc-<hash>.sock` at 29 bytes and were never
  affected. This is what kept macOS out of the CI matrix.

- Headless mode: a write that aborted mid-transaction could silently discard
  the *next* successful write on the following save, even an unrelated write
  from a later command (see
  https://github.com/NationalSecurityAgency/ghidra/issues/9347).
- GUI mode: `load` hung until someone clicked Ghidra's modal "Analyze now?"
  dialog (shown when CodeBrowser opens an unanalyzed program). The imported
  program is now flagged not to ask before it is saved and opened; analysis
  still runs as part of `load`.
- GUI mode: `stop` left the daemon running behind Ghidra's "Save Tool Changes?"
  dialog when more than one binary had been loaded (each `load` opens its own
  CodeBrowser). Duplicate tool instances are now marked unchanged before
  shutdown.

## [0.2.0] - 2026-07-06

### Fixed

- `symbols` missed labels containing spaces (including CJK/multi-word strings
  with a space anywhere in them), because Ghidra's `SymbolUtilities` replaces
  literal ASCII spaces — and only spaces, no other character, ASCII or not —
  with `_` when it auto-generates a label from string content (e.g. DEX
  `strings::`/`string_data::` labels). A query pasted verbatim from `strings`
  output therefore had spaces where the label had underscores and never
  matched. `symbols` now normalizes spaces/underscores as equivalent before
  comparing. Confirmed against a real multidex APK project and reproduced at
  the Ghidra bytecode level (`SymbolUtilities.INVALIDCHARS` is `{' '}`) before
  fixing.
- CLI usage errors (unknown options, invalid `--type`/`--mode` choices, unknown
  subcommands, missing required arguments) previously printed a plain-text Click
  usage string, breaking the documented "all output is JSON" contract for scripted
  callers. `main()` now runs Click in non-standalone mode and reports these as the
  same `{"ok": false, "error": ..., "message": ...}` envelope as RPC errors, with
  the same exit code Click would have used. `--help`/`--version` are unaffected.
- `list-instances`/`stop --all` globbed the *real* `/tmp` for orphaned sockets with
  no way for tests to redirect it, so a test-invoked `stop --all` could stop a real
  daemon running on the developer's machine (observed while testing this release).
  The scan directory is now `cli._SOCKET_SCAN_DIR`, a module attribute tests can
  monkeypatch to a `tmp_path`; production behaviour (`/tmp`) is unchanged.
- `list-namespaces` returned an empty list for DEX/Dalvik programs. The handler
  scanned `getSymbolIterator()`, which only yields memory-location labels and so
  missed DEX package (`createNameSpace`) and class (`createClass`) namespaces
  — none of which are memory labels. It now walks the namespace tree from the
  global namespace via `getChildren()`, which works uniformly for native
  (ELF/PE) and DEX programs. Added integration regression tests
  (`TestDexNamespaces`, `TestNamespacesNative`).

### Added

- `search-decompiled` command: regex-search decompiled C across many functions in
  one RPC call, optionally scoped to a namespace/class with `--class`. Replaces the
  one-RPC-per-function `symbols` + `decompile` + grep loop previously needed to find
  which function calls a given callee, builds a given string, etc. — especially
  valuable on multidex Android projects, where `xrefs-to` on a method only sees
  callers within the same DEX program (see below). Bounded by `--limit` (matching
  functions returned) and
  `--max-scan` (functions actually decompiled, default 5000) so an unscoped sweep on
  a 50k+-function binary can't run away; both `search-decompiled` and `decompile-all`
  gained a `--socket-timeout` option (default 1800s) since a bulk sweep's wall-clock
  cost scales with function count, not with the per-function `--timeout`.
- `list-bookmarks --category`: case-insensitive substring filter on bookmark
  category, alongside the existing `--type` filter. Helps isolate user-created
  bookmarks from Ghidra's auto-generated `Analysis`-type ones (commonly category
  `Address Table`), which can otherwise number in the hundreds on large/heavily
  analyzed programs and bury a handful of user bookmarks in the default listing.
- `xrefs-to --all-binaries`: also search every other currently loaded binary
  for a symbol with the same fully-qualified name and merge in real callers
  found there (each merged entry carries a `binary` field). Fixes the common
  multidex case where a method's only callers live in a *different* loaded
  `classesN.dex` — Ghidra's `ReferenceManager`/`SymbolTable` are per-`Program`,
  so a single-binary `xrefs-to` can't see a reference whose source and target
  live in two different loaded programs; this isn't a Dalvik-analyzer gap,
  and isn't DEX-specific — the same limitation applies to any ghidra-rpc
  project with more than one binary loaded. Documented in
  `docs/flows/android-apk.md`.

- Android APK / DEX analysis guidance: new `docs/flows/android-apk.md` flow and a
  SKILL.md section covering Ghidra's built-in Dalvik/APK/DEX loaders, the
  class-qualified `::` symbol naming, ambiguous-method handling, the
  **multi-dex caveat** (`load app.apk` imports only the primary `classes.dex`;
  extract each `classes*.dex` and load them individually to cover the whole app),
  and the DEX **string vs. symbol address** behavior (`strings` reports the
  string-content address; use the `strings::`-labeled address from `symbols` for
  `xrefs-to`, since the two differ by the variable-length uleb128 prefix).

- `create-struct` explicit-offset layout: pass `--field OFFSET TYPE NAME`
  (repeatable; OFFSET is decimal or `0x` hex) to place fields at exact byte
  offsets. Gaps are auto-padded with undefined bytes — no manual pad fields —
  and overlapping fields are rejected. The original sequential `TYPE NAME`
  form is unchanged.
- `read-pointers` command: read N pointer-sized words at an address and resolve
  each to its function/symbol (respecting endianness and pointer size). Useful for
  vtables, import/jump tables, and RTTI pointer arrays.
- `list-vtable` command: dump a C++ vtable's slots as resolved methods. Accepts a
  symbol name or address; without an explicit count it stops at the next vftable
  symbol or the first non-function pointer, reporting `stopped_reason`.
- `batch-edit-variable` command: rename and/or retype many local variables in a
  single decompiler snapshot and one transaction. Fixes the auto-name renumbering
  that breaks chained single `rename-variable`/`retype-variable` calls, and lets you
  address a variable by its stable `storage` string (e.g. `Stack[-0x18]:4`, `EAX:4`)
  in addition to its current name. Per-item results carry a `verified` read-back flag.
- `rename-variable` command for renaming local variables in decompiler output.
- `list-instances` command to show all running daemon instances, and a
  `stop --all` flag to stop them all at once.
- Global session registry so daemons register/unregister themselves on
  start/stop; `ping` now reports `project_gpr`, `mode`, and `pid`.
- Integration test suite exercising every API domain against a real headless
  Ghidra daemon, plus supporting test fixtures.

### Changed

- **Breaking:** `set-comment` now takes comment text via `--comment` instead of a
  positional argument, matching `set-bookmark`'s `--comment` option (previously the
  only command in the annotate-at-address family using a bare positional for the
  same field — a natural source of `Error: No such option '--comment'`).
  `ghidra-rpc set-comment <binary> <address> "text" --type plate` becomes
  `ghidra-rpc set-comment <binary> <address> --comment "text" --type plate`.
- Background daemon startup now fails fast with the captured daemon log if
  the subprocess exits early, instead of waiting out the full timeout.

### Fixed

- `find-bytes` tool.
- `xrefs` address resolution now prefers non-external symbols and handles
  thunk functions correctly, fixing inaccurate cross-reference lookups.
- GUI mode project mismatch detection: the daemon passes the `.gpr` path to
  `GhidraRun` so Ghidra opens the requested project on startup instead of
  restoring the last-used one, and `list-project-programs` now detects and
  warns about post-startup project switches in GUI mode.

## [0.1.0] - 2026-06-04

Initial public release.

