---
name: ghidra-rpc
description: >
  Reverse engineering assistant powered by Ghidra. Use for binary analysis,
  decompilation, vulnerability research, auditing compiled code, renaming symbols,
  annotating disassembly, cross-references, or any RE task - even without explicit
  mention of Ghidra.
---

# Ghidra RPC

A CLI daemon that exposes Ghidra reverse engineering capabilities over a Unix domain socket.
You interact with it by running `ghidra-rpc` commands via the bash tool - every command
outputs JSON to stdout.

## Running Commands

**All `ghidra-rpc` commands must be run with `uv run` from the ghidra-rpc skill directory
(the directory containing this SKILL.md file):**
```bash
cd <skill-dir> && uv run ghidra-rpc <command> ...
```

## Prerequisites Check

Before using any commands, verify the setup:

1. **Is the daemon running?** Run `uv run ghidra-rpc status --project <path>`. If not running,
   the user needs to start it in a separate terminal: `uv run ghidra-rpc start --project /path/to/project.gpr`
   (blocking, human-only). The `--headless` flag skips the GUI. For non-blocking / automated
   startup use `start --detach --headless` or `restart --headless`. Both commands accept
   `--timeout SECS` (default: 60 s headless, 180 s GUI) and log daemon output to
   `/tmp/ghidra-rpc-<hash>.log`.
2. **GUI mode: open the binary in CodeBrowser.** In GUI mode the daemon discovers programs
   via the running CodeBrowser tool. If the binary is in the project but not currently open
   in CodeBrowser, `list-binaries` will return empty and all commands will fail with
   "Binary not found". Use `list-project-programs` to see what's stored in the project,
   then double-click the program in Ghidra's Project window to open it.
3. **Is `GHIDRA_INSTALL_DIR` set?** The daemon will fail loudly if this is missing.

Once the daemon is running, all commands below work automatically. If the daemon dies,
commands will attempt auto-restart from the saved session.

## Command Reference

Every command accepts `--project <path>` (or reads `GHIDRA_RPC_PROJECT` env var).
All output is JSON. Exit code 0 = success, 1 = error.

### Project Management

| Command | Description | Example |
|---------|-------------|---------|
| `ghidra-rpc start --project <gpr> [--headless] [--detach] [--ghidra-install-dir DIR]` | Start daemon (blocking by default; `--detach` backgrounds it) | `ghidra-rpc start -p /tmp/re.gpr --headless --detach` |
| `ghidra-rpc stop --project <gpr>` | Stop the daemon | `ghidra-rpc stop -p /tmp/re.gpr` |
| `ghidra-rpc status --project <gpr>` | Check if daemon is running | `ghidra-rpc status -p /tmp/re.gpr` |

`status` output: `{running, socket, mode, mode_source, project, binaries}`. `binaries` is the loaded-binary list when the daemon is running, `null` when stopped (one-shot health check without a second `list-binaries` call). `mode_source` is
`"running"` when the daemon is live, `"session"` when the mode is from the saved
session only (daemon stopped), and `null` if no session exists.
| `ghidra-rpc restart --project <gpr> [--headless] [--timeout SECS] [--ghidra-install-dir DIR]` | Restart daemon in background (`--headless` to override mode) | `ghidra-rpc restart -p /tmp/re.gpr --headless` |
| `ghidra-rpc list-binaries --project <gpr>` | List binaries loaded in daemon | `ghidra-rpc list-binaries -p /tmp/re.gpr` |
| `ghidra-rpc list-project-programs --project <gpr>` | List all programs in the project repo (no GUI required) | `ghidra-rpc list-project-programs -p /tmp/re.gpr` |
| `ghidra-rpc save [binary] --project <gpr>` | Save program(s) to disk (auto-save also runs after every write) | `ghidra-rpc save -p /tmp/re.gpr` |

### Loading & Analysis

| Command | Description | Example |
|---------|-------------|---------|
| `ghidra-rpc load <path> -p <gpr> [--no-analyze] [--analysis-timeout SECS]` | Import & analyze a binary | `ghidra-rpc load /usr/bin/target -p /tmp/re.gpr` |
| `ghidra-rpc metadata <binary> -p <gpr>` | Binary metadata (arch, bits, format) | `ghidra-rpc metadata target -p /tmp/re.gpr` |

`load` flags:
- `--no-analyze` - skip auto-analysis entirely (fast; useful when you only need the
  listing or plan to run analysis later via Ghidra GUI).
- `--analysis-timeout SECS` - abort auto-analysis after the given wall-clock budget
  (best-effort); the binary is saved with whatever analysis completed in time.

### Listing

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc functions <binary> [--offset N] [--limit N] [--address-min ADDR] [--address-max ADDR] [--with-body]` | List functions (paginated); `--address-min/max` for server-side range filter; `--with-body` adds body range fields | `{functions: [{name, address, signature[, body_min, body_max, body_size]}], count, total, offset}` |
| `ghidra-rpc imports <binary>` | List imports | `{imports: [{name, address, library}], count}` |
| `ghidra-rpc exports <binary>` | List exports | `{exports: [{name, address}], count}` |
| `ghidra-rpc relocations <binary> [--address ADDR] [--limit N]` | List relocation table entries | `{relocations: [{address, type, symbol, bytes, status}], count, total}` |
| `ghidra-rpc list-calling-conventions <binary>` | List valid calling convention names for the architecture | `{conventions: [str], default, count}` |

### Decompilation

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc decompile <binary> <func> [--timeout SECS]` | Decompile to pseudo-C (default **120 s**) | `{name, address, signature, c_code}` |
| `ghidra-rpc basic-blocks <binary> <func> [--limit N]` | Get basic blocks (CFG) of a function | `{name, address, blocks:[{start,end,size,instructions,successors,predecessors}], num_blocks, edges}` |
| `ghidra-rpc pcode <binary> <func> [--high] [--timeout SECS] [--limit N]` | Get P-code (Ghidra IR); raw or high SSA form (--high) | `{name, address, mode, ops:[{address,seq,opcode,output,inputs}], count, truncated}` |

`<func>` can be a function name or hex address (e.g., `main` or `0x401000`). If the name
is ambiguous, the error message lists matches so you can use the address instead.

### Search

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc find-bytes <binary> <pattern> [--limit N] [--address ADDR]` | Search for byte pattern with wildcards (e.g. `"55 8b ?? 83 ec"`) | `{pattern, matches: [{address, context_hex}], count, truncated}` |
| `ghidra-rpc strings <binary> <query> [--limit N]` | Search strings (substring) | `{strings: [{address, value, type}], count}` |
| `ghidra-rpc symbols <binary> <query> [--limit N] [--offset N]` | Search symbols | `{symbols: [{name, address, type}], count, total}` |

### Cross-References

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc xrefs-to <binary> <target> [--limit N]` | Who references this? | `{xrefs: [{from_address, from_function, type}], count}` |
| `ghidra-rpc xrefs-from <binary> <target> [--limit N] [--no-stack]` | What does this reference? (`--no-stack` hides `Stack[-0x...]` entries) | `{xrefs: [{to_address, to_function, type}], count}` |

### Navigation (GUI mode only)

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc goto <binary> <target> [function\|address]` | Navigate GUI | `{address, success}` |

### Memory & Disassembly

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc memory-map <binary>` | List all memory segments (name, address range, size, rwx flags, type) | `{segments: [{name, start, end, size, read, write, execute, initialized, type, source_name}], count}` |
| `ghidra-rpc write-bytes <binary> <address> <hex>` | Write raw bytes to an address; does NOT auto-redisassemble | `{address, length, hex, verified}` |
| `ghidra-rpc read-bytes <binary> <address> <length>` | Read raw bytes; LENGTH accepts decimal or `0x` hex | `{address, length, hex, hexdump}` |
| `ghidra-rpc disassemble <binary> <address> [--count N]` | Disassemble N instructions (default 20); `warning` field if start address had no instruction | `{address, count, instructions:[{address,bytes,mnemonic,operands,length,comment}], listing[, warning]}` |
| `ghidra-rpc assemble <binary> <address> <instr> [<instr> ...]` | Assemble instruction text at address (Ghidra SLEIGH assembler) | `{address, bytes_written, hex, instructions:[{address,bytes,mnemonic,operands,length}]}` |

### Modifications

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc create-function <binary> <address> [--name NAME]` | Create a function at an address (auto-detects body from flow) | `{name, address, size, body}` |
| `ghidra-rpc delete-function <binary> <target>` | Remove a function definition (bytes unchanged; address reverts to undefined) | `{address, name, deleted}` |
| `ghidra-rpc rename-function <binary> <target> <new_name> [--namespace NS]` | Rename function; `--namespace` moves it into a namespace | `{address, old_name, new_name, verified[, old_namespace, new_namespace]}` |
| `ghidra-rpc rename-symbol <binary> <address> <new_name> [--create]` | Rename symbol; `--create` makes a new label if none exists | `{address, old_name, new_name, created, verified}` |
| `ghidra-rpc create-label <binary> <address> <name>` | Create-or-rename a label at any address (upsert) | `{address, name, old_name, action, created, verified}` |
| `ghidra-rpc set-comment <binary> <address> <comment> [--type TYPE]` | Set comment | `{address, comment_type, comment, verified}` |
| `ghidra-rpc batch-rename <binary> --json \|--json-file FILE [--mode function\|label]` | Rename 40+ functions/labels in one transaction; per-item error reporting | `{results:[{ok, index, address, old_name, new_name}], count, ok_count, error_count}` |
| `ghidra-rpc batch-set-comment <binary> --json \|--json-file FILE` | Set comments at many addresses in one transaction | `{results:[{ok, index, address, comment_type, comment}], count, ok_count, error_count}` |
| `ghidra-rpc set-signature <binary> <target> <signature>` | Set function signature | `{address, old_signature, new_signature, verified}` |
| `ghidra-rpc set-data-type <binary> <address> <type>` | Define data type in listing | `{address, data_type, length, value}` |
| `ghidra-rpc retype-variable <binary> <func> <variable> <type> [--timeout SECS]` | Retype decompiler variable | `{function, variable, old_type, new_type, verified}` |
| `ghidra-rpc rename-variable <binary> <func> <variable> <new_name> [--timeout SECS]` | Rename decompiler variable | `{function, variable, new_name, verified}` |
| `ghidra-rpc set-calling-convention <binary> <target> <convention>` | Change a function's calling convention | `{address, name, old_convention, new_convention, verified}` |
| `ghidra-rpc set-thunk <binary> <thunk> <target>` | Mark a function as a thunk (forwarding wrapper) | `{thunk_address, thunk_name, target_address, target_name, verified}` |
| `ghidra-rpc set-flow-override <binary> <address> <override>` | Override instruction flow type (NONE/BRANCH/CALL/CALL_RETURN/RETURN) | `{address, override, old_override, verified}` |
| `ghidra-rpc get-processor-context <binary> <address> [--register REG]` | Inspect ISA context register values (e.g. TMode on ARM) | `{address, registers:{name:value}}` |
| `ghidra-rpc set-processor-context <binary> <address> <register> <value> [--end ADDR]` | Set ISA context register over a range — fixes ARM Thumb mis-classification | `{address, end, register, value, verified}` |
| `ghidra-rpc create-namespace <binary> <name> [--parent NS]` | Create or look up a namespace | `{name, path, id, created}` |
| `ghidra-rpc list-namespaces <binary> [--limit N]` | List all namespaces with symbol counts | `{namespaces:[{name,path,id,type,symbol_count}], count}` |

Comment types: `plate`, `pre`, `post`, `eol` (default), `repeatable`.

Signature input is sanitised automatically: trailing semicolons are stripped,
whitespace is trimmed, and inline calling conventions (`__thiscall`, `__fastcall`,
`__stdcall`, `__cdecl`, `__vectorcall`, `__pascal`) are extracted from the string
and applied via the proper Ghidra API. So you can paste a C prototype directly
(e.g. `void __thiscall Foo::Bar(int x);` works without manual cleanup).

Type expressions for `set-data-type`, `retype-variable`, and struct field types:
- Built-ins: `byte`, `char`, `int`, `uint`, `short`, `long`, `float`, `double`, `void`, `string`, `unicode`
- Pointer: `char *`, `void *`, `int **`
- Array: `char[11]`, `int[4]`
- Any type in the program's data type manager by name or path: `MyStruct`, `/POSIX/size_t`

### Bookmarks

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc set-bookmark <binary> <address> [--type TYPE] [--category CAT] [--comment TEXT]` | Create/update a bookmark at an address | `{address, type, category, comment, action}` |
| `ghidra-rpc list-bookmarks <binary> [--type TYPE] [--address ADDR] [--limit N]` | List bookmarks (all, by type, or at address) | `{bookmarks: [{address, type, category, comment}], count, total}` |
| `ghidra-rpc remove-bookmark <binary> <address> [--type TYPE] [--category CAT]` | Remove a bookmark at an address | `{address, type, removed}` |

Bookmark types: `Note` (default), `Warning`, `Error`, `Info`, `Analysis`.

Bookmarks are visible in the Ghidra GUI's Bookmarks window. Use them to
persistently mark interesting locations, track analysis progress, or flag
findings for human review.

### Function Tags

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc tag-function <binary> <target> --tag TAG` | Add a tag to a function for classification | `{address, name, tag, all_tags}` |
| `ghidra-rpc untag-function <binary> <target> --tag TAG` | Remove a tag from a function | `{address, name, tag, removed, all_tags}` |
| `ghidra-rpc list-tags <binary>` | List all defined tags with use counts | `{tags:[{name,count}], count}` |
| `ghidra-rpc functions-by-tag <binary> --tag TAG [--limit N]` | List functions with a specific tag | `{tag, functions:[{name,address,signature}], count, total}` |

Tags are string labels (e.g. `crypto`, `vuln-sink`, `analyzed`, `needs-review`)
visible in Ghidra's Function Tags window. Use them to classify functions
and track analysis progress.

### Data-Type Authoring

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc create-struct <binary> <name> TYPE FIELD [TYPE FIELD ...] [--if-not-exists\|--or-replace]` | Create a named struct; `--if-not-exists` is idempotent, `--or-replace` rebuilds it | `{name, path, size, fields:[...], already_existed}` |
| `ghidra-rpc create-union <binary> <name> TYPE FIELD [TYPE FIELD ...] [--if-not-exists\|--or-replace]` | Create a named union; all fields share offset 0 | `{name, path, size, fields:[...], already_existed}` |
| `ghidra-rpc modify-struct <binary> <struct_name> --field-offset N\|--field-name NAME [--new-type TYPE] [--new-name NAME]` | Retype, rename, or re-comment a struct field | `{name, path, size, fields:[...], modified_field:{...}}` |
| `ghidra-rpc clear-data-range <binary> <start> <end>` | Reset inclusive byte range to undefined | `{start, end, cleared}` |
| `ghidra-rpc apply-data-type-range <binary> <start> <end> <type> [--clear]` | Stamp a type repeatedly across an inclusive range; `--clear` clears the region atomically before stamping | `{start, end, data_type, type_size, applied_count, cleared}` |
| `ghidra-rpc list-labels <binary> <address> [--end ADDR] [--limit N]` | List symbols at an address or in a range, including data type at each location | `{labels:[{address,name,type,source,is_primary,data_type,data_length}], count, total}` |
| `ghidra-rpc create-enum <binary> <name> NAME VAL [NAME VAL ...] [--size 1|2|4|8] [--if-not-exists|--or-replace]` | Create a named enum in the DTM | `{name, path, size, values:[{name,value}], already_existed}` |
| `ghidra-rpc modify-enum <binary> <name> [--add NAME:VAL ...] [--remove NAME ...]` | Add/remove individual entries from an existing enum | `{name, path, size, values:[{name,value}]}` |
| `ghidra-rpc set-equate <binary> <addr> <equate_name> <value> [--operand-index N] [--enum-path PATH]` | Attach a named scalar constant to an instruction operand; auto-links to enum if found | `{address, operand_index, equate_name, value, enum_linked, verified}` |
| `ghidra-rpc list-equates <binary> [address] [--limit N]` | List all equates in the program or only those applied at an address | `{equates:[{name,value[,operand_index,address]}], count, total}` |
| `ghidra-rpc list-data-types <binary> [--category CAT] [--query SUBSTR] [--limit N]` | List types in the DTM; category: struct, enum, union, typedef, pointer, array, all | `{data_types:[{name,path,category,size}], count, total}` |

### Version Tracking & Diff

| Command | Description | Output shape |
|---------|-------------|--------------|
| `ghidra-rpc version-track <old> <new> [--changed-only] [--limit N] [--min-similarity F]` | Match functions between two versions; find what changed. Results deduplicated per source function. | `{matched:[{source_name,destination_name,similarity,confidence,correlator}], unmatched_source, unmatched_destination, summary:{source_functions_total, changed_functions, identical_functions, ...}}` |
| `ghidra-rpc function-diff <bin1> <func1> <bin2> <func2> [--mode decompile\|disassembly]` | Unified diff of a function between two versions; normalises auto-generated names (`FUN_*`, `DAT_*`, `local_*`, `param_*`) to suppress relocation noise | `{is_identical, diff, raw_code1, raw_code2, func1_address, func2_address}` |
| `ghidra-rpc match-function <bin1> <func> <bin2> [--threshold F]` | Find best match for a function in another binary using BSim + correlators | `{source:{name,address}, candidates:[{name,address,similarity,confidence,correlator}], count}` |
| `ghidra-rpc decompile-all <binary> [--limit N] [--offset N] [--timeout SECS]` | Bulk decompile all functions; for export and external diff tools | `{functions:[{name,address,signature,c_code}], count, total, offset, errors}` |

For the full patch-diff workflow see `docs/flows/patch-analysis.md`.

## Error Handling

Error responses look like:
```json
{"id": "...", "ok": false, "error": "FunctionNotFound", "message": "Function 'foo' not found."}
```

Common errors:
- **DaemonNotRunning**: Daemon isn't started. Tell the user to run `ghidra-rpc start`.
- **ValueError**: Bad argument (ambiguous name, invalid address). The message usually tells
  you what to do - e.g., use a more specific name or an address.
- **RuntimeError**: Ghidra-level error. For GUI-only commands in headless mode, the error
  says so explicitly.

## Write Operations & Persistence

Write operations (rename, create-label, create-function, delete-function, set-comment, batch-rename, batch-set-comment, set-signature, set-data-type, retype-variable, rename-variable, set-calling-convention, set-thunk, set-flow-override, set-processor-context, create-struct, create-union, modify-struct, create-enum, modify-enum, set-equate, set-bookmark, clear-data-range, apply-data-type-range, write-bytes, assemble, tag-function, untag-function, create-namespace)
use Ghidra transactions internally. **Every write is automatically saved to the project
database on disk** after the transaction commits, so changes survive daemon restarts and
are visible when the project is reopened in the Ghidra GUI.

Every write response includes a `verified` boolean that confirms whether the change was
read back successfully after committing.

You can also save explicitly at any time:
```bash
ghidra-rpc save              # saves all loaded programs
ghidra-rpc save <binary>     # saves one program
```

On clean shutdown (`stop` or Ctrl+C), all programs are saved automatically.

## Patch / Diff Analysis Quick Start

```bash
# 1. Load both versions
ghidra-rpc load /path/to/binary_v1 -p project.gpr
ghidra-rpc load /path/to/binary_v2 -p project.gpr

# 2. Find changed functions (summary counts all changes; matched list is filtered)
ghidra-rpc version-track binary_v1 binary_v2 --changed-only

# 3. Diff a specific changed function
ghidra-rpc function-diff binary_v1 <func> binary_v2 <func>
```

Full workflow — correlator details, unmatched analysis, bulk decompile:
read `docs/flows/patch-analysis.md`.

## Typical Workflow

1. User starts daemon: `cd <skill-dir> && uv run ghidra-rpc start --project /path/to/project.gpr --headless`
   For automation / non-blocking start: `uv run ghidra-rpc start --project /path/to/project.gpr --headless --detach`
2. Load binary: `uv run ghidra-rpc load /path/to/binary -p /path/to/project.gpr`
   Response includes `short_name` (usable alias in all subsequent commands).
   (add `--no-analyze` to skip analysis, `--analysis-timeout SECS` to cap it)
3. Get overview: `metadata`, `functions`, `imports`, `exports`
4. Investigate: `decompile` interesting functions, `xrefs-to` to trace callers
5. Annotate: `rename-function`, `set-comment` to document findings
6. Search: `strings` for hardcoded values, `symbols` for specific patterns

## FAQ / Common Gotchas

**`create-label` properly replaces DEFAULT (auto-analysis) symbols**:
`create-label` creates a USER_DEFINED label and sets it as the primary symbol at the
address. If a DEFAULT symbol (e.g. `DAT_00418138`) already exists, it is demoted to
secondary. The decompiler will then use the new name. `rename-symbol` renames in
place but requires an existing symbol; `create-label` is preferred for annotating
addresses regardless of existing symbols.

**Annotating an address with no existing symbol** (`rename-symbol` fails with "No symbol found"):
`rename-symbol` requires a symbol to already exist at the address. Auto-analysis only
places `DAT_` symbols where it detects data; inside arrays or dense struct regions
many addresses have no symbol. Use `create-label` instead - it creates a new USER_DEFINED
label if none exists, or renames the existing one:
```bash
ghidra-rpc create-label <binary> 0x0040e4ac topPtrErrorMsg
```
You can also add `--create` to `rename-symbol` for the same upsert behaviour.

**Defining and applying a struct across a memory region**:
Full workflow to stamp a struct across a repeated data table:
```bash
# 1. Create the struct type in the DTM (--if-not-exists makes the call idempotent)
ghidra-rpc create-struct binary ErrorEntry int errorNumber "char *" ptrErrorMsg --if-not-exists

# 2. Stamp the struct across the range with --clear to atomically clear + apply
#    (23 × 8-byte ErrorEntry structs, both endpoints inclusive)
ghidra-rpc apply-data-type-range binary 0x0040e4a8 0x0040e55f ErrorEntry --clear
```
After this, each address `0x0040e4a8`, `0x0040e4b0`, ... has type `ErrorEntry`.
Without `--clear`, `apply-data-type-range` skips positions where existing data
conflicts and reports them in the `errors` list. Use `clear-data-range` first if
you need finer control over which region is cleared.

**Discovering what labels exist at an address or range**:
```bash
# Single address
ghidra-rpc list-labels binary 0x0040e4a8

# Range
ghidra-rpc list-labels binary 0x0040e4a8 --end 0x0040e55f --limit 50
```

**Using the binary name after `load`**:
`load` returns both a full key (`binary`) with a hash suffix and a `short_name`
(the original filename). Use `short_name` in all subsequent commands - it works
because commands match binary names by substring:
```bash
# Load response: {"binary": "/WinHelloCPP.exe-85cbcc", "short_name": "WinHelloCPP.exe", ...}
ghidra-rpc decompile WinHelloCPP.exe main        # short_name works
ghidra-rpc decompile WinHelloCPP main            # even without extension, if unambiguous
```
If two binaries share the same stem, use the full key to disambiguate.

**Trailing semicolons in signatures**: Ghidra's parser rejects C prototypes that end
with `;`. ghidra-rpc strips trailing semicolons automatically, so you can paste verbatim.

**`list-binaries` is empty but I loaded a binary**: In GUI mode, the binary must be
open in CodeBrowser. Use `list-project-programs` to see what's stored in the project
repo, then open it in CodeBrowser's Project window.

**Daemon log file**: When started in the background (`start --detach` or `restart`),
logs are written to `/tmp/ghidra-rpc-<hash>.log` (same directory and stem as the Unix
socket). If the daemon fails to start or become responsive, check that file first:
```bash
tail -50 /tmp/ghidra-rpc-*.log
```
The timeout error message always prints the exact log path.

**`GHIDRA_INSTALL_DIR` not found after backgrounding**: Environment variables may be
lost when daemonising (nohup, cron, systemd units, etc.). Fix options, in order of preference:
1. Pass `--ghidra-install-dir /path/to/ghidra` to `start` or `restart` - the value is
   persisted in the session file and forwarded to every subsequent restart automatically.
2. Export `GHIDRA_INSTALL_DIR` in your shell profile (`~/.bashrc`, `~/.zshrc`) so it
   survives login sessions.
3. Use `start --detach --headless` from the same terminal where the env var is set.

**Session file location**: By default the session file (`.ghidra-rpc-<hash>.json`) is
written alongside the `.gpr` project file, keeping all state self-contained. To use a
custom directory (e.g. a shared location or a RAM-disk), set `GHIDRA_RPC_STATE_DIR`:
```bash
export GHIDRA_RPC_STATE_DIR=/tmp/ghidra-sessions
```

**Changes not visible in the Ghidra GUI**: Make sure you open the project copy
(e.g. `basic_code-501243` in the Project window), not the raw binary via File → Open.
Also ensure you are not running two separate Ghidra instances on the same project
(causes lock conflicts). Changes made by ghidra-rpc are auto-saved to disk and will
be visible the next time the program is opened in the GUI.

**`restart` without a prior session**: Pass `--headless` so `restart` can create
a fresh headless session instead of requiring a prior `start`.

**Decompiler timeout on certain functions**: Some functions trigger expensive
decompiler analysis paths and time out even with simple assembly. Use
`decompile --timeout 300` (or higher) for stubborn functions. The default timeout
is **120 s** (increased from 60 s to handle large firmware functions). The
`retype-variable` and `rename-variable` commands also accept `--timeout` since it
triggers an internal decompilation pass.

**`decompile` returns bad-instruction warnings — use `pcode --high` as fallback**:
When `decompile` produces output like *"Bad instruction data"* or fails to decode
a function body (common on ARM Thumb code in regions that auto-analysis
mis-classified as data), try `pcode --high` instead:
```bash
ghidra-rpc pcode binary 0x03288102 --high
```
The P-code engine re-decodes bytes from the *function object's* context rather
than from the listing-level disassembler, so it often succeeds where `decompile`
fails. High P-code also reveals all CALL / CALLIND / BRANCHIND targets and data
flow, making it useful for tracing arguments even without valid decompilation.
Fix the root cause with `set-processor-context` (see below).

**`disassemble` starts from the wrong address** (B2 warning):
If `disassemble` is called at an address with no instruction (e.g. an address
that is mid-instruction or undefined), the response now includes a `warning`
field explaining that disassembly started from the next available instruction.
Check for `warning` in the JSON response when the listing looks wrong.

**ARM Thumb mis-classification — `set-processor-context` is the fix** (F1/F5):
When ARM auto-analysis classifies Thumb code as data, the listing disassembler
decodes it as 32-bit ARM (TMode=0) and produces garbage. The full recovery
workflow:
```bash
# 1. Diagnose: check TMode at the affected address
ghidra-rpc get-processor-context binary 0x03288100 --register TMode
# Expected: {"TMode": 0}  ← this is the problem

# 2. Clear the bad data/code classification
ghidra-rpc clear-data-range binary 0x03288100 0x032883ff

# 3. Set Thumb mode for the range
ghidra-rpc set-processor-context binary 0x03288100 TMode 1 --end 0x032883ff

# 4. Verify disassembly now shows Thumb-2 instructions
ghidra-rpc disassemble binary 0x03288100 --count 20

# 5. Re-create the function
ghidra-rpc create-function binary 0x03288100
```
If `create-function` fails because a bad stub still exists at the address,
use `delete-function` first to remove it.

**Bad stubs blocking re-creation — use `delete-function`** (F2):
If `create-function 0x03288103` (wrong parity) left a stub, and now
`create-function 0x03288102` (correct address) fails with *"already exists at
overlapping address"*, delete the bad stub first:
```bash
ghidra-rpc delete-function binary 0x03288103
ghidra-rpc create-function  binary 0x03288102
```

**Batch rename / comment 40+ functions without round-trip overhead** (F7):
Use `batch-rename` and `batch-set-comment` to apply many annotations in a single
server round-trip and Ghidra transaction:
```bash
# Rename functions from a JSON file
ghidra-rpc batch-rename binary --json-file renames.json

# Or inline
ghidra-rpc batch-rename binary --json \
  '[{"target":"sub_401234","new_name":"init_uart"},{"target":"0x400200","new_name":"isr_handler"}]'

# Label-mode (symbol/label rename by address)
ghidra-rpc batch-rename binary --mode label --json \
  '[{"address":"0x0333afcc","new_name":"g_debugStr"}]'

# Batch comments
ghidra-rpc batch-set-comment binary --json \
  '[{"address":"0x03288102","comment":"Thumb ISR entry","comment_type":"plate"}]'
```
All items that succeed are committed in one transaction; failed items are
reported per-item in `results[].ok=false` and do not roll back the successes.

**Concurrent write operations are serialised**: The daemon serialises all command
handler invocations internally to prevent Ghidra transaction conflicts. You do
not need to serialize write commands externally — parallel writes are queued
automatically. This is slightly slower than concurrent execution but eliminates
silent partial failures.

## Reporting Bugs and Missing Features

While using ghidra-rpc you may encounter bugs, errors, or missing capabilities.
**Please report them** - real-world usage drives continuous improvement.

At the end of any analysis session where you hit a problem, save a brief report:

```bash
cat > /tmp/ghidra-rpc-issues-$(date +%Y%m%d-%H%M%S).md << 'EOF'
## ghidra-rpc Issue Report

**Date:** $(date)
**Binary:** <name of binary analysed>

### Bugs encountered
<!-- Describe: command used, error message / unexpected output, expected behaviour -->

### Missing features
<!-- Describe what you needed but couldn't do with the current command set -->

### Suggestions
<!-- Any UX improvements or new commands that would have helped -->
EOF
```

Then inform the user:
> "I saved a ghidra-rpc issue report to `/tmp/ghidra-rpc-issues-<timestamp>.md`.
>  If you'd like to submit it, run: `cat /tmp/ghidra-rpc-issues-*.md`"

The report is written to `/tmp` so it stays local to the machine and is lost on reboot -
it is never sent anywhere automatically.

## Further Documentation

For detailed guidance on specific workflows:
- **Installation & setup**: read `docs/install.md`
- **Quick start tutorial**: read `docs/quickstart.md`
- **Troubleshooting**: read `docs/troubleshooting.md`
- **Binary audit workflow**: read `docs/flows/binary-audit.md`
- **Multi-binary analysis**: read `docs/flows/multi-binary.md`
- **Vulnerability research**: read `docs/flows/vulnerability-research.md`
- **Patch/diff analysis**: read `docs/flows/patch-analysis.md`
