# Android APK / DEX Analysis Workflow

Analyze Android apps by loading their Dalvik bytecode into Ghidra. Ghidra ships
with native APK and DEX support (the **Dalvik** processor plus the FileFormats
loaders `Android APK`, `DEX`, and `CDEX`) — **no extension install is needed**.

The decompiler produces Java-like pseudocode, so `decompile`, `functions`,
`strings`, `symbols`, `xrefs-*`, and the annotation commands all work the same
way they do on native binaries.

## What Ghidra Loads

| Input | Loader | Result |
|-------|--------|--------|
| `classes.dex` (raw DEX) | `DEX` | One program (all classes in that dex) |
| `*.apk` (single-dex) | `Android APK` | One program (the app's `classes.dex`) |
| `*.apk` (multi-dex) | `Android APK` | **Only the primary `classes.dex`** — see the caveat below |

Every loaded program reports `arch: Dalvik`, `bits: 32`, `format: Android APK`
or `Dalvik Executable (DEX)`.

## Single-dex APK (or a raw .dex)

Just `load` it directly:

```bash
ghidra-rpc load /path/to/app.apk           # or classes.dex
ghidra-rpc metadata app.apk                # confirm arch=Dalvik
ghidra-rpc functions app.apk --limit 20
```

## Multi-dex APK — extract and load each dex

**Important:** `ghidra-rpc load app.apk` imports **only the primary
`classes.dex`**. Additional dex files (`classes2.dex`, `classes3.dex`, …) present
in a multi-dex APK are silently dropped. To analyze the whole app, extract every
dex from the APK (it is a ZIP) and load each as its own program:

```bash
# 1. List the dex files inside the APK
unzip -l app.apk | grep '\.dex$'

# 2. Extract them all (rename so each program name is distinct in the project)
mkdir -p /tmp/app-dex && cd /tmp/app-dex
unzip -o /path/to/app.apk 'classes*.dex'
for d in classes*.dex; do mv "$d" "app-$d"; done

# 3. Load each dex as a separate binary
ghidra-rpc load /tmp/app-dex/app-classes.dex
ghidra-rpc load /tmp/app-dex/app-classes2.dex
ghidra-rpc list-binaries
```

Each dex becomes an independent program. A class defined in `classes2.dex` is
only searchable in that program, so run `symbols` / `strings` against each dex
when hunting for something across the whole app.

## Working with Dalvik programs

**Symbols are class-qualified with `::` separators.** A method appears as
`com::example::MainActivity::onCreate`. Search by any fragment:

```bash
ghidra-rpc symbols app.apk MainActivity
ghidra-rpc symbols app.apk onCreate
```

**Method names are often ambiguous** across classes (`onCreate`, `asInterface`,
`<init>`, …). When `decompile <name>` reports an ambiguous match, use the
address it lists, or first find the class-qualified symbol:

```bash
ghidra-rpc decompile app.apk 0x5005c5bc       # decompile by address
```

**Decompiler output includes class metadata** in a plate comment (class access
flags, superclass, implemented interfaces, source file, method signature) ahead
of the Java-like body — handy for orienting yourself inside obfuscated code.

**Class descriptors appear as strings** in DEX type-descriptor form
(`Lcom/example/Foo;`). Use `strings` to locate them and `xrefs-to` to find where
a class is referenced:

```bash
ghidra-rpc strings app.apk "Lcom/example"
```

**DEX strings: `strings` and `symbols` report different addresses (by design).**
A DEX string is stored as a `string_data_item` — a uleb128 length prefix
followed by the MUTF-8 bytes. As a result:

- `strings <bin> <query>` returns the address of the **string content** (the
  characters). This address has no symbol and `xrefs-to` on it returns
  `{"xrefs": [], "count": 0}`.
- `symbols <bin> <query>` returns the `strings::…`-labeled address of the
  **enclosing `string_data_item`**, which *is* the reference target. `xrefs-to`
  on this address returns the referencing entry (from the DEX `string_id` table).

This is inherent to the DEX format, not an addressing error — the two addresses
differ by the length of the uleb128 prefix (**1 byte for strings under 128
chars, 2+ bytes for longer strings**, so it is *not* a fixed offset). To trace
references to a string, use the `strings::`-labeled address from `symbols`, not
the content address from `strings`:

```bash
ghidra-rpc symbols app.apk "Lcom/example/Foo;"   # gives the strings:: label addr
ghidra-rpc xrefs-to app.apk <strings::-label-address>
```

Note that even with the correct address, DEX `xrefs-to` on a class/string
typically shows only the `string_id`/`type_id` **table** reference, not the
actual `new-instance` / `const-class` / `invoke-*` bytecode call sites — Ghidra's
Dalvik analyzer does not build references from those.

**`xrefs-to` on a *method* works correctly for callers in the same dex file.**
Ghidra's Dalvik analyzer does resolve `invoke-*` bytecode to the real caller
when the target method is defined in the same DEX program — `xrefs-to
<method>` returns genuine `UNCONDITIONAL_CALL`/`CONDITIONAL_CALL` entries with
real `from_function` names, the same as native ELF/PE.

**It only degrades to table-only (`method_id` entry + `Entry Point`/`EXTERNAL`
row, no real callers) when every caller lives in a *different* DEX program**
(the common case in a multidex app, e.g. `classes3.dex` calling into
`classes5.dex`). This is not a Dalvik-analyzer gap — it's the same limitation
any multi-binary ghidra-rpc project has: each loaded binary is an independent
Ghidra `Program` with its own database, so no single `xrefs-to` call can see
a reference whose source and target live in two different programs. A caller
in another dex calls through its *own* local placeholder symbol for the
method (visible in that dex's own `symbols`/decompiled output, not the
target dex's), so `xrefs-to <method>` on the defining dex alone will miss it.

Pass `--all-binaries` to have `xrefs-to` search every other currently loaded
dex for a symbol with the same fully-qualified name and merge in real callers
found there — the other dex(es) must already be `load`ed for this to see them:

```bash
ghidra-rpc load app-classes3.dex
ghidra-rpc load app-classes5.dex   # must be loaded for --all-binaries to see its callers
ghidra-rpc xrefs-to app-classes3.dex 0x501e4ab8 --all-binaries   # or an unambiguous bare function name
```

`search-decompiled` remains useful as a complementary regex-search tool — e.g. to find
usage sites by pattern rather than exact symbol name, or to confirm a `--all-binaries`
placeholder match isn't a name collision between two unrelated classes that happen to
share a short obfuscated name (common in heavily obfuscated multidex apps):

```bash
ghidra-rpc search-decompiled app.apk "targetF1" --class com::example::Foo
```

**R8/ProGuard-minified apps** decompile fine but have obfuscated names
(`a.b.c`). Lean on `strings`, string xrefs, and Android framework API calls
(e.g. `queryLocalInterface`, `getSystemService`) to recover intent, then use
`rename-function` / `set-comment` / bookmarks to annotate as you go.

## Notes & limitations

- DEX/APK analysis is fast (seconds); `--analysis-timeout` is rarely needed.
- `imports`/`exports` are less meaningful than on native code — Dalvik resolves
  everything against the class pool; prefer `symbols` and `strings`.
- To read `AndroidManifest.xml`, resource files, or native `.so` libraries
  bundled in the APK, unzip the APK and load/inspect those files separately
  (native `lib/*/*.so` files load as ordinary ELF programs).
- `.odex`, `.oat`, `.vdex`, and boot images are supported by Ghidra's FileSystem
  browser but are not exposed through `ghidra-rpc load`; extract the embedded
  dex with Ghidra's GUI (File → Open File System) if you need them.
