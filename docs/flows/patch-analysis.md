# Patch Analysis Workflow

Compare two versions of a binary to understand what changed — useful for analyzing
security patches, update diffs, or understanding version differences.

## Step 1: Load Both Versions

```bash
# Load the old version
ghidra-rpc load /path/to/binary_v1

# Load the new version
ghidra-rpc load /path/to/binary_v2

# Verify both are loaded
ghidra-rpc list-binaries
```

## Step 2: Run Version Tracking

Use Ghidra's Auto Version Tracking to automatically match functions between the
two binaries.  This runs multiple correlators (exact bytes, exact instructions,
symbol name, reference, BSim) to find corresponding functions and flag which
ones differ.

```bash
# Show only functions that changed (fastest for patch analysis)
ghidra-rpc version-track binary_v1 binary_v2 --changed-only

# Show all matches (identical + changed) — useful for coverage stats
ghidra-rpc version-track binary_v1 binary_v2
```

The output includes:
- **`matched`**: Function pairs matched between both binaries, with similarity scores.
  Functions with `similarity < 1.0` have changed.  With `--changed-only` only these
  are returned.
- **`unmatched_source`**: Functions in v1 with no match in v2 (possibly removed).
- **`unmatched_destination`**: Functions in v2 with no match in v1 (possibly added).
- **`summary`**: Coverage stats — `source_functions_total`, `source_functions_matched`,
  `changed_functions`, `identical_functions`, `destination_functions_unmatched`.

Options:
- `--changed-only` — only return matched pairs where similarity < 1.0.
- `--min-similarity 0.5` — filter out low-confidence matches.
- `--include-data` — include data matches (not just functions).
- `--limit 1000` — increase the match result limit (default 500).
- `--socket-timeout 3600` — wait longer for very large binaries (default 1800 s).

`version-track` and `match-function` run in headless mode only.

> **Note on deduplication**: `version-track` automatically deduplicates by source
> function — for each source function only the single best-scoring destination match
> is kept.  This prevents the `DuplicateFunctionMatch` correlator from generating
> dozens of entries for small stub functions and crowding out the BSim matches that
> identify the actually-changed code.

## Step 3: Diff Changed Functions

For matched functions that are not identical, use `function-diff` to see exactly
what changed:

```bash
ghidra-rpc function-diff binary_v1 <func_name> binary_v2 <func_name>
```

This decompiles both functions, normalises auto-generated variable names to
suppress noise, and returns a unified diff.  The output includes:
- `is_identical` — whether the two listings are identical after normalisation.
- `diff` — a unified diff with noise removed.
- `raw_code1` / `raw_code2` — the original decompiled code for both sides.

Focus on:
- **Added bounds checks**: Suggests a buffer overflow fix.
- **Changed string handling**: Suggests format string or injection fix.
- **New error handling**: Suggests robustness improvement.
- **Removed functionality**: Suggests feature deprecation or backdoor removal.

## Step 4: Match Specific Functions

When auto-generated names (`FUN_XXXXX`) make it hard to identify corresponding
functions, use `match-function` to find the best match in the other binary:

```bash
ghidra-rpc match-function binary_v1 FUN_00401234 binary_v2
```

This uses BSim (feature-vector similarity) and instruction-level correlators
to find candidates even when addresses and names differ.

## Step 5: Bulk Decompile for External Diffing

For comprehensive comparison, export all decompiled code and use external tools:

```bash
# Decompile all functions in both binaries
ghidra-rpc decompile-all binary_v1 > /tmp/v1_all.json
ghidra-rpc decompile-all binary_v2 > /tmp/v2_all.json
```

Then extract per-function files and use standard `diff -r` for full coverage.
Use `--limit`/`--offset` for pagination on large binaries.

## Step 6: Investigate New Functions

New functions in the patched version may be:
- Security mitigations (stack canary checks, input sanitizers)
- Replacements for vulnerable functions
- New features

```bash
# Decompile each new function
ghidra-rpc decompile binary_v2 <new_function>

# See who calls it
ghidra-rpc xrefs-to binary_v2 <new_function>
```

## Step 7: Cross-Reference Analysis

For patched functions, check if the fix is complete:

```bash
# Find all callers of the patched function
ghidra-rpc xrefs-to binary_v2 <patched_function>

# Check if similar patterns exist elsewhere (variant analysis)
ghidra-rpc strings binary_v2 "strcpy" --limit 50
ghidra-rpc xrefs-to binary_v2 strcpy
```

## Tips

- **Start with `version-track`**: It matches hundreds of functions in seconds and
  immediately shows which ones changed.  Don't manually decompile + diff unless
  Version Tracking misses something.
- **Use `function-diff` for changed matches**: The normalised diff filters out noise
  from variable renaming and address shifts, letting you focus on real changes.
- **Use `match-function` for unnamed functions**: BSim can match functions even when
  both sides have auto-generated names like `FUN_XXXXX`.
- **Focus on the diff, not the whole binary.** Most code will be identical — zero in on
  what changed.
- **Check nearby functions too.** A patch might change a helper function that's used by
  the function you're interested in.
