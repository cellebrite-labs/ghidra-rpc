"""Helpers shared by the tool handlers: transactions, committing writes,
and resolving functions, addresses, data types, namespaces and comment
types from user input.

Like every tool module, nothing here imports ``ghidra.*`` at module level
(the JVM may not be running yet); the Ghidra imports live inside the
functions.  The old import locations (``modifications``, ``decompiler``,
``xrefs``) re-export these names.
"""

from __future__ import annotations

import re
from contextlib import contextmanager

from ghidra_rpc.server.context import _fmt_address, _looks_like_address, _parse_address


# ── Writes ───────────────────────────────────────────────────────────────────

@contextmanager
def ghidra_transaction(program, description: str):
    """Context manager for Ghidra transactions. Ensures proper commit/rollback.

    A short sleep after ``endTransaction`` prevents the intermittent
    ``IllegalStateException: No transaction is open`` that occurs when
    consecutive write commands are issued rapidly.  Ghidra's transaction
    machinery posts commit notifications asynchronously; without the sleep the
    next ``startTransaction`` can race with those notifications.
    """
    import time as _time
    tx_id = program.startTransaction(description)
    committed = False
    try:
        yield
        committed = True
    finally:
        program.endTransaction(tx_id, committed)
        # Brief yield so Ghidra can finish posting commit events before the
        # next transaction opens.  Eliminates the ~20% failure rate seen when
        # back-to-back write commands arrive without any inter-command delay.
        _time.sleep(0.05)


def _maybe_swing(ctx, fn):
    """Run fn on Swing EDT if the context is GUI mode, else run directly."""
    if hasattr(ctx, "run_on_swing"):
        return ctx.run_on_swing(fn)
    return fn()


def _commit(ctx, pi, fn, invalidate: bool = True):
    """Run write *fn* via ``_maybe_swing``, then flush the decompiler cache
    and save the program. Returns *fn*'s result.

    Pass ``invalidate=False`` only for writes the decompiler never reads
    (bookmarks, tags, namespaces).  A helper rather than a decorator so a
    handler can decompile off the EDT before committing.
    """
    result = _maybe_swing(ctx, fn)
    if invalidate:
        pi.decompiler_pool.invalidate_all()
    ctx.save_program(pi)
    return result


# ── Decompiling ──────────────────────────────────────────────────────────────

def _decompile(pi, func, timeout: int):
    """Decompile *func* with a pooled decompiler; returns ``DecompileResults``.

    Callers check ``getErrorMessage()`` themselves, since they differ in
    whether a failure raises, is recorded per function, or is ignored.
    """
    from ghidra.util.task import TaskMonitor

    with pi.decompiler_pool.acquire() as decompiler:
        return decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)


def _decompile_high(pi, func, timeout: int):
    """Decompile *func* and return its ``HighFunction``; raises RuntimeError
    if decompilation fails or yields no high function."""
    result = _decompile(pi, func, timeout)

    err = result.getErrorMessage()
    if err and str(err).strip():
        raise RuntimeError(f"Decompilation failed for '{func.getName()}': {err}")

    high_func = result.getHighFunction()
    if high_func is None:
        raise RuntimeError(f"Could not obtain high function for '{func.getName()}'")
    return high_func


# ── Resolving user input ─────────────────────────────────────────────────────

def _find_function(pi, name_or_address: str):
    """Resolve a function by name or hex address. Raises ValueError if not found or ambiguous.

    Only 0x-prefixed input (optionally space-qualified, as _fmt_address emits
    it) is treated as an address.  Bare hex is a name query, but never
    partial-matches auto-generated names like FUN_00101139 — that would
    silently pick whichever FUN_ happens to contain the digits.
    """
    prog = pi.program
    fm = prog.getFunctionManager()

    if _looks_like_address(name_or_address):
        addr = _parse_address(prog, name_or_address)
        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if func:
            return func
        raise ValueError(f"No function at or containing address {name_or_address}")

    return _pick_function(name_or_address, *_function_candidates(pi, name_or_address))


def _function_candidates(pi, name: str) -> tuple[list, list]:
    """One pass over the functions: those named exactly *name*, and those whose
    name contains it (case-insensitive).  Bare hex never partial-matches an
    auto-generated (DEFAULT-source) name."""
    from ghidra.program.model.symbol import SourceType

    name_lower = name.lower()
    bare_hex = bool(re.fullmatch(r"[0-9a-f]+", name_lower))
    exact_matches = []
    partial_matches = []

    for func in pi.program.getFunctionManager().getFunctions(True):
        func_name = str(func.getName())
        if func_name.lower() == name_lower:
            exact_matches.append(func)
        elif name_lower in func_name.lower():
            if bare_hex and func.getSymbol().getSource() == SourceType.DEFAULT:
                continue
            partial_matches.append(func)
    return exact_matches, partial_matches


def _pick_function(name: str, exact_matches: list, partial_matches: list):
    """The single exact match, else the single partial match; raises
    ValueError (listing candidates) when ambiguous or nothing matches."""
    if len(exact_matches) == 1:
        return exact_matches[0]
    elif len(exact_matches) > 1:
        suggestions = [f"{f.getName()} @ {_fmt_address(f.getEntryPoint())}" for f in exact_matches]
        raise ValueError(
            f"Ambiguous function name '{name}'. Matches: {suggestions}"
        )

    if len(partial_matches) == 1:
        return partial_matches[0]
    elif len(partial_matches) > 1:
        suggestions = [f"{f.getName()} @ {_fmt_address(f.getEntryPoint())}" for f in partial_matches[:10]]
        raise ValueError(
            f"Ambiguous function name '{name}'. Partial matches: {suggestions}"
        )

    raise ValueError(f"Function '{name}' not found. If '{name}' is an address, pass it with a 0x prefix.")


def _resolve_address(pi, target: str):
    """Resolve a target to a Ghidra Address: a 0x address as-is, else the
    entry of a function with exactly that name, else a symbol (label) with
    exactly that name, else a function whose name contains it.

    An address is used exactly (not snapped to its containing function).
    If nothing matches, the function lookup's error is raised, so an
    ambiguous name still lists its candidates.
    """
    prog = pi.program

    if _looks_like_address(target):
        return _parse_address(prog, target)

    # An exact function name wins; a partial (substring) match only after
    # labels, so "g_config" finds the label, not a function "init_g_config".
    exact, partial = _function_candidates(pi, target)
    if len(exact) == 1:
        return exact[0].getEntryPoint()
    # Several functions with exactly this name are ambiguous, unless they are
    # one import's thunk chain (an ELF PLT thunk and the intermediate thunk
    # both named "printf"), which the symbol scan below handles.
    if len(exact) > 1 and not _one_function_family(exact):
        _pick_function(target, exact, partial)   # raises the ambiguity error

    # Try as symbol — prefer non-external (e.g. PLT thunk) over EXTERNAL space symbols.
    # In ELF binaries an imported function like 'malloc' has both a PLT thunk at a real
    # code address AND an entry in the EXTERNAL address space.  Callers reference the PLT
    # thunk, so we must prefer that address for xref lookups.
    st = prog.getSymbolTable()
    external_fallback = None
    for sym in st.getAllSymbols(False):
        if str(sym.getName()).lower() == target.lower():
            addr = sym.getAddress()
            if not addr.getAddressSpace().isExternalSpace():
                return addr  # non-external (PLT thunk / IAT entry) — use immediately
            if external_fallback is None:
                external_fallback = addr

    if external_fallback is not None:
        return external_fallback
    return _pick_function(target, exact, partial).getEntryPoint()


def _one_function_family(funcs) -> bool:
    """True if *funcs* has at most one member once each thunk is followed to
    the function it ultimately forwards to."""
    targets = set()
    for f in funcs:
        final = f.getThunkedFunction(True) if f.isThunk() else f
        targets.add(str((final or f).getEntryPoint()))
    return len(targets) <= 1


def _resolve_data_type(program, type_str: str):
    """Resolve a type-name string to a Ghidra DataType.

    Supports (all work in headless and GUI mode):
    - Built-in aliases: ``byte``, ``char``, ``int``, ``uint``, ``string``, …
    - Pointer decoration: ``char *``, ``void *``, ``int **``, …
    - Array decoration:  ``char[11]``, ``int[4]``, …
    - DTM lookup by name or full path: any type already in the program's
      data type manager (structs, enums, typedefs, …)

    Note: Ghidra's DataTypeParser requires a GUI DataTypeQueryService so it
    cannot be used in headless mode. This function implements the common cases
    directly via the Ghidra data-model API.
    """
    import re as _re
    t = type_str.strip()

    # ---- pointer: strip trailing '*', resolve base recursively ---------------
    if t.endswith("*"):
        base_dt = _resolve_data_type(program, t[:-1].strip())
        from ghidra.program.model.data import PointerDataType
        return PointerDataType(base_dt, program.getDataTypeManager())

    # ---- array: e.g. "char[11]" or "int [4]" ---------------------------------
    m = _re.fullmatch(r"(.+?)\s*\[(\d+)\]", t)
    if m:
        base_dt = _resolve_data_type(program, m.group(1).strip())
        count = int(m.group(2))
        from ghidra.program.model.data import ArrayDataType
        return ArrayDataType(base_dt, count)

    # ---- string / unicode aliases (variable-length, scanned to null) ---------
    if t.lower() in ("string", "cstring", "c_string", "terminated_string"):
        for cls_name in ("TerminatedCStringDataType", "StringDataType"):
            try:
                mod = __import__("ghidra.program.model.data", fromlist=[cls_name])
                cls = getattr(mod, cls_name)
                return getattr(cls, "dataType", cls())
            except Exception:
                pass

    if t.lower() in ("unicode", "wstring", "terminated_unicode"):
        for cls_name in ("TerminatedUnicode32DataType", "TerminatedUnicodeDataType"):
            try:
                mod = __import__("ghidra.program.model.data", fromlist=[cls_name])
                cls = getattr(mod, cls_name)
                return getattr(cls, "dataType", cls())
            except Exception:
                pass

    # ---- simple fixed-length built-ins ----------------------------------------
    _BUILTINS = {
        "byte":    "ByteDataType",
        "char":    "CharDataType",
        "word":    "WordDataType",
        "dword":   "DWordDataType",
        "qword":   "QWordDataType",
        "int":     "IntegerDataType",
        "uint":    "UnsignedIntegerDataType",
        "short":   "ShortDataType",
        "ushort":  "UnsignedShortDataType",
        "long":    "LongDataType",
        "ulong":   "UnsignedLongDataType",
        "float":   "FloatDataType",
        "double":  "DoubleDataType",
        "void":    "VoidDataType",
        "bool":    "BooleanDataType",
        "boolean": "BooleanDataType",
        "pointer": "PointerDataType",
    }
    cls_name = _BUILTINS.get(t.lower())
    if cls_name:
        try:
            mod = __import__("ghidra.program.model.data", fromlist=[cls_name])
            cls = getattr(mod, cls_name)
            return getattr(cls, "dataType", cls())
        except Exception:
            pass

    # ---- program data-type manager lookup (structs, enums, typedefs, …) ------
    dtm = program.getDataTypeManager()
    # Exact path match first (e.g. "/MyStruct" or "/POSIX/size_t")
    dt = dtm.getDataType(t if t.startswith("/") else f"/{t}")
    if dt is not None:
        return dt
    # Substring / name search across all categories
    from java.util import ArrayList  # type: ignore
    hits = ArrayList()
    dtm.findDataTypes(t, hits)
    if hits.size() == 1:
        return hits.get(0)
    if hits.size() > 1:
        paths = [str(hits.get(i).getPathName()) for i in range(hits.size())]
        raise ValueError(
            f"Ambiguous type '{t}'. Matches: {paths}. "
            f"Use the full path (e.g. '/SomeDir/{t}') to disambiguate."
        )

    raise ValueError(
        f"Unknown data type '{type_str}'. Use a built-in name (byte, char, int, string, "
        f"char *, char[11], …) or a type defined in the program's data type manager."
    )


def _resolve_namespace(program, ns_path: str):
    """Resolve a namespace by name or path. Raises ValueError if not found."""
    st = program.getSymbolTable()
    global_ns = program.getGlobalNamespace()

    # Try the simple case: direct child of global namespace
    ns = st.getNamespace(ns_path, global_ns)
    if ns is not None:
        return ns

    # Try walking a path like "Outer::Inner"
    parts = ns_path.replace("::", "/").split("/")
    current = global_ns
    for part in parts:
        part = part.strip()
        if not part:
            continue
        child = st.getNamespace(part, current)
        if child is None:
            raise ValueError(
                f"Namespace '{ns_path}' not found. "
                f"Could not resolve component '{part}' under '{current.getName(True)}'."
            )
        current = child
    return current


def _comment_types() -> dict:
    """Map comment-type names (plate, pre, post, eol, repeatable) to Ghidra's
    constants: ``CommentType`` on newer Ghidra, ``CodeUnit`` ints on older."""
    try:
        from ghidra.program.model.listing import CommentType
        return {
            "plate":      CommentType.PLATE,
            "pre":        CommentType.PRE,
            "post":       CommentType.POST,
            "eol":        CommentType.EOL,
            "repeatable": CommentType.REPEATABLE,
        }
    except ImportError:
        from ghidra.program.model.listing import CodeUnit
        return {
            "plate":      CodeUnit.PLATE_COMMENT,
            "pre":        CodeUnit.PRE_COMMENT,
            "post":       CodeUnit.POST_COMMENT,
            "eol":        CodeUnit.EOL_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT,
        }
