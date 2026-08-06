# Changelog

## [Unreleased]

### Changed

- **Breaking:** `disassemble` no longer returns the `instructions` array by
  default — it was a verbatim duplicate of the `listing` string, which already
  carries every field it did (address, bytes, mnemonic, operands, EOL comment;
  only `length` is absent, and that is the byte count). Pass
  `--with-instructions` when you need the machine-parseable array. The default
  response is roughly a quarter the size, measured across `--count` 8 to 500.
  `ghidra-rpc disassemble <binary> <address>` now returns
  `{address, count, listing}`; add `--with-instructions` for the previous shape.

### Fixed

- Headless mode: a write that aborted mid-transaction could silently discard
  the *next* successful write on the following save, even an unrelated write
  from a later command (see
  https://github.com/NationalSecurityAgency/ghidra/issues/9347).

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

