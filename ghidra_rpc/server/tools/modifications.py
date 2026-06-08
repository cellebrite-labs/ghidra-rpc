"""Modification tools: rename, set comments, set types, change signatures.

All write operations are wrapped in Ghidra transactions. In GUI mode,
Ghidra API calls go through Swing.runNow() for thread safety.
"""

from __future__ import annotations

from contextlib import contextmanager

from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.decompiler import _find_function


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


# ── Data-type resolution ──────────────────────────────────────────────────────

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


def _handle_create_label(ctx, args: dict) -> dict:
    """Create or rename a label at an address.

    Creates a USER_DEFINED label and makes it the *primary* symbol at the
    address so the decompiler uses it.  If a DEFAULT (auto-analysis) symbol
    like ``DAT_...`` already exists, the new label is created alongside it
    and set as primary — the DEFAULT symbol is demoted to secondary.  If a
    USER_DEFINED symbol already exists, it is renamed in place.

    This is the idiomatic way to pin a name at any listing address regardless
    of whether auto-analysis generated a symbol there.
    """
    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    name        = args.get("name", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not name:
        raise ValueError("Missing required argument: name")

    pi = ctx.get_program(binary)

    def do_create():
        from ghidra.program.model.symbol import SourceType
        from ghidra_rpc.server.context import _parse_address

        addr = _parse_address(pi.program, address_str)
        st   = pi.program.getSymbolTable()
        syms = list(st.getSymbols(addr))

        with ghidra_transaction(pi.program, f"ghidra-rpc: label {name} @ {addr}"):
            if syms:
                primary = syms[0]
                old_name = str(primary.getName())
                source = primary.getSource()
                # If the existing primary is DEFAULT (auto-analysis DAT_/LAB_),
                # create a new USER_DEFINED label and set it primary so the
                # decompiler picks up the user name instead.
                if source == SourceType.DEFAULT:
                    new_sym = st.createLabel(addr, name, SourceType.USER_DEFINED)
                    new_sym.setPrimary()
                    created = True
                else:
                    # Existing USER_DEFINED symbol — rename in place
                    primary.setName(name, SourceType.USER_DEFINED)
                    created = False
            else:
                old_name = None
                new_sym = st.createLabel(addr, name, SourceType.USER_DEFINED)
                new_sym.setPrimary()
                created = True

        # Read back to verify — check the primary symbol
        syms_after = list(st.getSymbols(addr))
        primary_after = None
        for s in syms_after:
            if s.isPrimary():
                primary_after = s
                break
        if primary_after is None and syms_after:
            primary_after = syms_after[0]
        actual = str(primary_after.getName()) if primary_after else None
        return {
            "address":  str(addr),
            "name":     actual,
            "old_name": old_name,
            "created":  created,   # kept for backward compatibility
            "action":   "created" if created else "renamed",
            "verified": actual == name,
        }

    result = _maybe_swing(ctx, do_create)
    ctx.save_program(pi)
    return result


def _handle_rename_function(ctx, args: dict) -> dict:
    """Rename a function, optionally moving it into a namespace."""
    binary    = args.get("binary", "")
    target    = args.get("target", "")
    new_name  = args.get("new_name", "")
    namespace = args.get("namespace", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    pi = ctx.get_program(binary)

    def do_rename():
        from ghidra.program.model.symbol import SourceType

        func = _find_function(pi, target)
        old_name = str(func.getName())
        old_ns = str(func.getParentNamespace().getName(True))
        address = str(func.getEntryPoint())

        with ghidra_transaction(pi.program, f"ghidra-rpc: rename {old_name} -> {new_name}"):
            func.setName(new_name, SourceType.USER_DEFINED)
            if namespace:
                ns = _resolve_namespace(pi.program, namespace)
                func.setParentNamespace(ns)

        pi.decompiler_pool.invalidate_all()
        # Read back to verify
        actual = str(func.getName())
        actual_ns = str(func.getParentNamespace().getName(True))
        result = {
            "address":   address,
            "old_name":  old_name,
            "new_name":  actual,
            "verified":  actual == new_name,
        }
        if namespace:
            result["old_namespace"] = old_ns
            result["new_namespace"] = actual_ns
        return result

    result = _maybe_swing(ctx, do_rename)
    ctx.save_program(pi)
    return result


def _handle_rename_symbol(ctx, args: dict) -> dict:
    """Rename a symbol at a given address.

    If ``create`` is True and no symbol exists at the address, a new
    USER_DEFINED label is created instead of raising an error.
    """
    binary   = args.get("binary", "")
    address  = args.get("address", "")
    new_name = args.get("new_name", "")
    create   = bool(args.get("create", False))

    if not address:
        raise ValueError("Missing required argument: address")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    pi = ctx.get_program(binary)

    def do_rename():
        from ghidra.program.model.symbol import SourceType
        from ghidra_rpc.server.context import _parse_address

        addr = _parse_address(pi.program, address)
        st   = pi.program.getSymbolTable()
        syms = list(st.getSymbols(addr))

        if not syms:
            if create:
                # No symbol exists — create a new one.
                with ghidra_transaction(
                    pi.program, f"ghidra-rpc: create label {new_name} @ {addr}"
                ):
                    st.createLabel(addr, new_name, SourceType.USER_DEFINED)
                return {
                    "address":  str(addr),
                    "old_name": None,
                    "new_name": new_name,
                    "created":  True,
                    "verified": True,
                }
            raise ValueError(f"No symbol found at address {address}")

        sym      = syms[0]
        old_name = str(sym.getName())

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: rename symbol {old_name} -> {new_name}"
        ):
            sym.setName(new_name, SourceType.USER_DEFINED)

        actual = str(sym.getName())
        return {
            "address":  str(addr),
            "old_name": old_name,
            "new_name": actual,
            "created":  False,
            "verified": actual == new_name,
        }

    result = _maybe_swing(ctx, do_rename)
    ctx.save_program(pi)
    return result


def _handle_set_comment(ctx, args: dict) -> dict:
    """Set a comment at an address or function."""
    binary = args.get("binary", "")
    address = args.get("address", "")
    comment = args.get("comment", "")
    comment_type = args.get("comment_type", "eol")

    if not address:
        raise ValueError("Missing required argument: address")

    pi = ctx.get_program(binary)

    def do_set_comment():
        from ghidra_rpc.server.context import _parse_address

        # Map comment type names to Ghidra constants
        try:
            from ghidra.program.model.listing import CommentType
            type_map = {
                "plate": CommentType.PLATE,
                "pre": CommentType.PRE,
                "post": CommentType.POST,
                "eol": CommentType.EOL,
                "repeatable": CommentType.REPEATABLE,
            }
        except ImportError:
            from ghidra.program.model.listing import CodeUnit
            type_map = {
                "plate": CodeUnit.PLATE_COMMENT,
                "pre": CodeUnit.PRE_COMMENT,
                "post": CodeUnit.POST_COMMENT,
                "eol": CodeUnit.EOL_COMMENT,
                "repeatable": CodeUnit.REPEATABLE_COMMENT,
            }

        ct = comment_type.lower()
        ghidra_ct = type_map.get(ct)
        if ghidra_ct is None:
            raise ValueError(
                f"Invalid comment_type '{comment_type}'. "
                f"Use one of: {list(type_map.keys())}"
            )

        # Resolve address — try hex first, then function name
        try:
            addr = _parse_address(pi.program, address)
        except ValueError:
            func = _find_function(pi, address)
            addr = func.getEntryPoint()

        with ghidra_transaction(pi.program, f"ghidra-rpc: set {ct} comment @ {addr}"):
            pi.program.getListing().setComment(addr, ghidra_ct, comment)

        pi.decompiler_pool.invalidate_all()
        # Read back the comment to verify
        actual = pi.program.getListing().getComment(ghidra_ct, addr)
        return {
            "address": str(addr),
            "comment_type": ct,
            "comment": str(actual) if actual else None,
            "verified": str(actual) == comment if actual else comment == "",
        }

    result = _maybe_swing(ctx, do_set_comment)
    ctx.save_program(pi)
    return result


# Calling conventions that may appear inline in a C-style signature string.
# The parser strips them and returns the convention separately so callers can
# apply them via the proper Ghidra API after setting the signature.
_CALLING_CONVENTIONS = (
    "__thiscall", "__fastcall", "__stdcall", "__cdecl",
    "__vectorcall", "__pascal",
)


def _sanitize_signature(sig: str) -> tuple[str, str | None]:
    """Normalize a user-provided signature string.

    Strips leading/trailing whitespace, removes a trailing semicolon,
    and extracts an inline calling convention keyword (e.g. ``__thiscall``)
    that Ghidra's ``FunctionSignatureParser`` cannot parse.

    Returns ``(cleaned_signature, calling_convention_or_None)``.
    """
    sig = sig.strip()
    if sig.endswith(";"):
        sig = sig[:-1].rstrip()

    # Extract inline calling convention (e.g. "void __thiscall Foo(...)")
    extracted_cc = None
    for cc in _CALLING_CONVENTIONS:
        # Match as a standalone token (space/start-of-string on left,
        # space on right) so we don't mangle identifiers that happen to
        # contain the substring.
        import re as _re
        pattern = r"(?<=\s)" + _re.escape(cc) + r"(?=\s)"
        if _re.search(pattern, sig):
            extracted_cc = cc
            sig = _re.sub(pattern, "", sig, count=1)
            # Collapse any resulting double-spaces
            sig = " ".join(sig.split())
            break
        # Also check at the very start of the string
        if sig.startswith(cc + " "):
            extracted_cc = cc
            sig = sig[len(cc):].lstrip()
            break

    return sig, extracted_cc


def _handle_set_function_signature(ctx, args: dict) -> dict:
    """Set a function's signature/prototype."""
    binary = args.get("binary", "")
    target = args.get("target", "")
    signature = args.get("signature", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not signature:
        raise ValueError("Missing required argument: signature")

    signature, extracted_cc = _sanitize_signature(signature)

    pi = ctx.get_program(binary)

    def do_set_sig():
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor

        func = _find_function(pi, target)
        old_sig = str(func.getSignature())
        address = str(func.getEntryPoint())

        parser = FunctionSignatureParser(pi.program.getDataTypeManager(), None)
        parsed = parser.parse(func.getSignature(False), signature)
        cmd = ApplyFunctionSignatureCmd(
            func.getEntryPoint(), parsed, SourceType.USER_DEFINED,
        )

        with ghidra_transaction(pi.program, f"ghidra-rpc: set signature for {func.getName()}"):
            if not cmd.applyTo(pi.program, TaskMonitor.DUMMY):
                msg = cmd.getStatusMsg() or f"Failed to apply signature: {signature}"
                raise ValueError(msg)

        # If a calling convention was extracted from the signature string,
        # apply it in a separate transaction so the user doesn't need a
        # follow-up set-calling-convention call.
        cc_applied = None
        if extracted_cc:
            try:
                with ghidra_transaction(
                    pi.program,
                    f"ghidra-rpc: set calling convention {extracted_cc}",
                ):
                    func.setCallingConvention(extracted_cc)
                cc_applied = str(func.getCallingConventionName())
            except Exception:
                # Non-fatal: the signature itself was applied successfully.
                cc_applied = None

        pi.decompiler_pool.invalidate_all()
        # Read back the committed signature to verify it applied correctly.
        new_sig = str(func.getSignature())
        result = {
            "address": address,
            "old_signature": old_sig,
            "new_signature": new_sig,
            # Legacy alias — kept for backward compat
            "signature": new_sig,
            "verified": new_sig != old_sig,
        }
        if cc_applied:
            result["calling_convention"] = cc_applied
        return result

    result = _maybe_swing(ctx, do_set_sig)
    ctx.save_program(pi)
    return result


def _handle_set_data_type(ctx, args: dict) -> dict:
    """Define the data type at an address in the listing (disassembler view).

    Clears the existing code unit at the address and creates a new one with
    the requested type.  For variable-length types such as ``string``, Ghidra
    scans forward to the null terminator automatically.
    """
    binary       = args.get("binary", "")
    address_str  = args.get("address", "")
    type_str     = args.get("data_type", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not type_str:
        raise ValueError("Missing required argument: data_type")

    pi = ctx.get_program(binary)

    def do_set():
        from ghidra_rpc.server.context import _parse_address

        addr = _parse_address(pi.program, address_str)
        dt   = _resolve_data_type(pi.program, type_str)
        listing = pi.program.getListing()

        with ghidra_transaction(pi.program, f"ghidra-rpc: set data type at {addr}"):
            # Clear the current code unit first; if that fails, clear the
            # containing unit to handle being mid-instruction/mid-data.
            try:
                listing.clearCodeUnits(addr, addr, False)
                data = listing.createData(addr, dt)
            except Exception:
                cu = listing.getCodeUnitContaining(addr)
                if cu:
                    listing.clearCodeUnits(cu.getMinAddress(), cu.getMaxAddress(), False)
                data = listing.createData(addr, dt)

        pi.decompiler_pool.invalidate_all()

        length = data.getLength() if data else None
        try:
            value = str(data.getValue()) if data else None
        except Exception:
            value = None

        return {
            "address":   str(addr),
            "data_type": str(dt.getName()),
            "length":    length,
            "value":     value,
        }

    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


def _handle_retype_variable(ctx, args: dict) -> dict:
    """Retype a local variable or parameter in the decompiler's high-level view.

    Decompilation is performed on the calling thread to avoid blocking the Swing
    EDT; only the database mutation is dispatched to the EDT in GUI mode.
    """
    binary        = args.get("binary", "")
    func_name     = args.get("func", "")
    variable_name = args.get("variable", "")
    type_str      = args.get("data_type", "")
    timeout       = int(args.get("timeout", 60))

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not variable_name:
        raise ValueError("Missing required argument: variable")
    if not type_str:
        raise ValueError("Missing required argument: data_type")

    pi = ctx.get_program(binary)
    func     = _find_function(pi, func_name)
    new_type = _resolve_data_type(pi.program, type_str)

    # ---- Step 1: decompile to get HighFunction (blocking; not on Swing EDT) --
    from ghidra.util.task import TaskMonitor

    with pi.decompiler_pool.acquire() as decompiler:
        result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)

    err = result.getErrorMessage()
    if err and str(err).strip():
        raise RuntimeError(f"Decompilation failed for '{func.getName()}': {err}")

    high_func = result.getHighFunction()
    if high_func is None:
        raise RuntimeError(f"Could not obtain high function for '{func.getName()}'")

    # Find the symbol by name in the local symbol map
    found_sym = None
    all_names = []
    for sym in high_func.getLocalSymbolMap().getSymbols():
        sym_name = str(sym.getName())
        all_names.append(sym_name)
        if sym_name == variable_name:
            found_sym = sym
            break

    if found_sym is None:
        raise ValueError(
            f"Variable '{variable_name}' not found in '{func.getName()}'. "
            f"Available: {sorted(all_names)}"
        )

    old_type = str(found_sym.getDataType())

    # ---- Step 2: commit the type change (on Swing EDT in GUI mode) -----------
    def do_update():
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: retype {variable_name} -> {type_str}"
        ):
            HighFunctionDBUtil.updateDBVariable(
                found_sym, found_sym.getName(), new_type, SourceType.USER_DEFINED
            )

    _maybe_swing(ctx, do_update)
    pi.decompiler_pool.invalidate_all()
    ctx.save_program(pi)

    # Read back via a fresh decompilation to verify the change took effect.
    verified = False
    actual_type = str(new_type.getName())
    try:
        with pi.decompiler_pool.acquire() as decompiler:
            from ghidra.util.task import TaskMonitor as _TM
            result2 = decompiler.decompileFunction(func, 30, _TM.DUMMY)
        hf2 = result2.getHighFunction()
        if hf2:
            for sym2 in hf2.getLocalSymbolMap().getSymbols():
                if str(sym2.getName()) == variable_name:
                    actual_type = str(sym2.getDataType())
                    verified = actual_type == str(new_type.getName()) or \
                               actual_type == str(new_type)
                    break
    except Exception:
        pass

    return {
        "function":  str(func.getName()),
        "variable":  variable_name,
        "old_type":  old_type,
        "new_type":  actual_type,
        "verified":  verified,
    }


def _handle_rename_variable(ctx, args: dict) -> dict:
    """Rename a local variable or parameter in the decompiler's high-level view.

    Decompilation is performed on the calling thread to avoid blocking the Swing
    EDT; only the database mutation is dispatched to the EDT in GUI mode.
    """
    binary        = args.get("binary", "")
    func_name     = args.get("func", "")
    variable_name = args.get("variable", "")
    new_name      = args.get("new_name", "")
    timeout       = int(args.get("timeout", 60))

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not variable_name:
        raise ValueError("Missing required argument: variable")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    pi = ctx.get_program(binary)
    func     = _find_function(pi, func_name)

    # ---- Step 1: decompile to get HighFunction (blocking; not on Swing EDT) --
    from ghidra.util.task import TaskMonitor

    with pi.decompiler_pool.acquire() as decompiler:
        result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)

    err = result.getErrorMessage()
    if err and str(err).strip():
        raise RuntimeError(f"Decompilation failed for '{func.getName()}': {err}")

    high_func = result.getHighFunction()
    if high_func is None:
        raise RuntimeError(f"Could not obtain high function for '{func.getName()}'")

    # Find the symbol by name in the local symbol map
    found_sym = None
    all_names = []
    for sym in high_func.getLocalSymbolMap().getSymbols():
        sym_name = str(sym.getName())
        all_names.append(sym_name)
        if sym_name == variable_name:
            found_sym = sym
            break

    if found_sym is None:
        raise ValueError(
            f"Variable '{variable_name}' not found in '{func.getName()}'. "
            f"Available: {sorted(all_names)}"
        )

    # ---- Step 2: commit the type change (on Swing EDT in GUI mode) -----------
    def do_update():
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: rename {variable_name} -> {new_name}"
        ):
            HighFunctionDBUtil.updateDBVariable(
                found_sym, new_name, None, SourceType.USER_DEFINED
            )

    _maybe_swing(ctx, do_update)
    pi.decompiler_pool.invalidate_all()
    ctx.save_program(pi)

    # Read back via a fresh decompilation to verify the change took effect.
    verified = False
    try:
        with pi.decompiler_pool.acquire() as decompiler:
            from ghidra.util.task import TaskMonitor as _TM
            result2 = decompiler.decompileFunction(func, 30, _TM.DUMMY)
        hf2 = result2.getHighFunction()
        if hf2:
            for sym2 in hf2.getLocalSymbolMap().getSymbols():
                if str(sym2.getName()) == new_name:
                    verified = True
                    break
    except Exception:
        pass

    return {
        "function":  str(func.getName()),
        "variable":  variable_name,
        "new_name":  new_name,
        "verified":  verified,
    }


def _handle_create_function(ctx, args: dict) -> dict:
    """Create a function at an address where Ghidra hasn't auto-detected one.

    Uses ``FlatProgramAPI.createFunction()`` which auto-detects the function
    body by following flow from the entry point.  Fails if the address is
    already inside another function.

    Args (in ``args`` dict):
        binary  -- program name / key
        address -- entry point address (hex string)
        name    -- optional function name (default: auto-generated by Ghidra)

    Returns a dict with:
        name    -- function name (auto-generated if not provided)
        address -- entry point address
        size    -- function body size in bytes
        body    -- list of address range strings ["start-end", ...]
    """
    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    name        = args.get("name", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    pi = ctx.get_program(binary)

    def do_create():
        from ghidra_rpc.server.context import _parse_address

        addr = _parse_address(pi.program, address_str)

        # Check if address is already inside a function
        fm = pi.program.getFunctionManager()
        existing = fm.getFunctionAt(addr)
        if existing is not None:
            raise ValueError(
                f"A function already exists at {addr}: {existing.getName()}. "
                f"Use rename-function to rename it."
            )
        containing = fm.getFunctionContaining(addr)
        if containing is not None:
            raise ValueError(
                f"Address {addr} is inside function '{containing.getName()}' "
                f"({containing.getEntryPoint()}-{containing.getBody().getMaxAddress()}). "
                f"Cannot create an overlapping function."
            )

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: create function @ {addr}"
        ):
            func = pi.flat_api.createFunction(addr, name or None)

        if func is None:
            raise RuntimeError(
                f"Failed to create function at {addr}. The address may not "
                f"contain valid code, or Ghidra could not determine the "
                f"function body from flow analysis."
            )

        # Collect body ranges
        body = func.getBody()
        body_ranges = []
        for r in body:
            body_ranges.append(f"{r.getMinAddress()}-{r.getMaxAddress()}")

        pi.decompiler_pool.invalidate_all()

        return {
            "name":    str(func.getName()),
            "address": str(func.getEntryPoint()),
            "size":    int(body.getNumAddresses()),
            "body":    body_ranges,
        }

    result = _maybe_swing(ctx, do_create)
    ctx.save_program(pi)
    return result


def _handle_set_calling_convention(ctx, args: dict) -> dict:
    """Change a function's calling convention.

    The convention name must be one returned by ``list-calling-conventions``.
    Invalid names raise a clear error with the list of valid options.

    Args (in ``args`` dict):
        binary     -- program name / key
        target     -- function name or address
        convention -- calling convention name (e.g. ``__fastcall``)

    Returns a dict with:
        address        -- function entry point
        name           -- function name
        old_convention -- previous calling convention
        new_convention -- newly set calling convention
        verified       -- whether read-back matches
    """
    binary     = args.get("binary", "")
    target     = args.get("target", "")
    convention = args.get("convention", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not convention:
        raise ValueError("Missing required argument: convention")

    pi = ctx.get_program(binary)

    def do_set():
        from ghidra.program.model.symbol import SourceType

        func = _find_function(pi, target)
        old_cc = str(func.getCallingConventionName())
        address = str(func.getEntryPoint())

        # Validate the convention name against the compiler spec
        compiler_spec = pi.program.getCompilerSpec()
        valid = [str(cc.getName()) for cc in compiler_spec.getCallingConventions()]
        if convention not in valid:
            raise ValueError(
                f"Unknown calling convention '{convention}'. "
                f"Valid options for this architecture: {valid}"
            )

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: set calling convention {convention}"
        ):
            func.setCallingConvention(convention)

        pi.decompiler_pool.invalidate_all()
        new_cc = str(func.getCallingConventionName())
        return {
            "address":        address,
            "name":           str(func.getName()),
            "old_convention": old_cc,
            "new_convention": new_cc,
            "verified":       new_cc == convention,
        }

    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


def _handle_set_thunk(ctx, args: dict) -> dict:
    """Mark a function as a thunk (forwarding wrapper) to another function.

    A thunk is a function that simply forwards to another (PLT stubs, import
    trampolines, C++ virtual dispatch stubs). Marking them propagates the
    target's name/signature to all call sites and cleans up xrefs and
    decompilation output.

    Args (in ``args`` dict):
        binary    -- program name / key
        thunk     -- function to mark as a thunk (name or address)
        target    -- the function the thunk forwards to (name or address)

    Returns a dict with:
        thunk_address    -- thunk function entry point
        thunk_name       -- thunk function name
        target_address   -- target function entry point
        target_name      -- target function name
        verified         -- whether the thunk relationship was set
    """
    binary      = args.get("binary", "")
    thunk_name  = args.get("thunk", "")
    target_name = args.get("target", "")

    if not thunk_name:
        raise ValueError("Missing required argument: thunk")
    if not target_name:
        raise ValueError("Missing required argument: target")

    pi = ctx.get_program(binary)

    def do_set():
        thunk_func  = _find_function(pi, thunk_name)
        target_func = _find_function(pi, target_name)

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: set thunk {thunk_func.getName()} -> {target_func.getName()}",
        ):
            thunk_func.setThunkedFunction(target_func)

        pi.decompiler_pool.invalidate_all()

        # Verify
        thunked = thunk_func.getThunkedFunction(False)
        verified = (thunked is not None and
                    str(thunked.getEntryPoint()) == str(target_func.getEntryPoint()))

        return {
            "thunk_address":  str(thunk_func.getEntryPoint()),
            "thunk_name":     str(thunk_func.getName()),
            "target_address": str(target_func.getEntryPoint()),
            "target_name":    str(target_func.getName()),
            "verified":       verified,
        }

    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


def _handle_set_flow_override(ctx, args: dict) -> dict:
    """Override the flow type of an instruction.

    Needed when Ghidra misclassifies a jump as a branch vs. a tail call,
    or doesn't recognize a CALL that never returns as CALL_RETURN.

    Valid flow override values: NONE, BRANCH, CALL, CALL_RETURN, RETURN.

    Args (in ``args`` dict):
        binary   -- program name / key
        address  -- instruction address
        override -- flow override string

    Returns a dict with:
        address      -- instruction address
        override     -- the override that was set
        old_override -- previous override value
        verified     -- whether the override was set
    """
    binary       = args.get("binary", "")
    address_str  = args.get("address", "")
    override_str = args.get("override", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not override_str:
        raise ValueError("Missing required argument: override")

    pi = ctx.get_program(binary)

    def do_set():
        from ghidra.program.model.listing import FlowOverride
        from ghidra_rpc.server.context import _parse_address

        addr = _parse_address(pi.program, address_str)

        # Parse the override string
        override_upper = override_str.upper().strip()
        valid_overrides = {
            "NONE":        FlowOverride.NONE,
            "BRANCH":      FlowOverride.BRANCH,
            "CALL":        FlowOverride.CALL,
            "CALL_RETURN": FlowOverride.CALL_RETURN,
            "RETURN":      FlowOverride.RETURN,
        }
        flow_override = valid_overrides.get(override_upper)
        if flow_override is None:
            raise ValueError(
                f"Invalid flow override '{override_str}'. "
                f"Valid values: {list(valid_overrides.keys())}"
            )

        listing = pi.program.getListing()
        instr = listing.getInstructionAt(addr)
        if instr is None:
            raise ValueError(
                f"No instruction at address {address_str}. "
                f"Use 'disassemble' to check the listing."
            )

        old_override = str(instr.getFlowOverride())

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: set flow override {override_upper} @ {addr}",
        ):
            instr.setFlowOverride(flow_override)

        pi.decompiler_pool.invalidate_all()
        new_override = str(instr.getFlowOverride())

        return {
            "address":      str(addr),
            "override":     new_override,
            "old_override": old_override,
            "verified":     new_override == override_upper,
        }

    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


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


def _handle_create_namespace(ctx, args: dict) -> dict:
    """Create or look up a namespace.

    Namespaces group symbols (e.g. C++ classes). Creating a namespace first,
    then renaming functions into it, produces clean decompiler output.

    Args (in ``args`` dict):
        binary -- program name / key
        name   -- namespace name to create
        parent -- parent namespace path (default: global)

    Returns a dict with:
        name      -- namespace name
        path      -- full namespace path
        id        -- namespace ID
        created   -- whether a new namespace was created (False if existing)
    """
    binary      = args.get("binary", "")
    ns_name     = args.get("name", "")
    parent_name = args.get("parent", "")

    if not ns_name:
        raise ValueError("Missing required argument: name")

    pi = ctx.get_program(binary)

    def do_create():
        from ghidra.program.model.symbol import SourceType

        st = pi.program.getSymbolTable()

        # Resolve parent namespace
        if parent_name:
            parent_ns = _resolve_namespace(pi.program, parent_name)
        else:
            parent_ns = pi.program.getGlobalNamespace()

        # Check if namespace already exists
        existing = st.getNamespace(ns_name, parent_ns)
        if existing is not None:
            return {
                "name":    str(existing.getName()),
                "path":    str(existing.getName(True)),
                "id":      int(existing.getID()),
                "created": False,
            }

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: create namespace {ns_name}"
        ):
            ns = st.createNameSpace(
                parent_ns, ns_name, SourceType.USER_DEFINED
            )

        return {
            "name":    str(ns.getName()),
            "path":    str(ns.getName(True)),
            "id":      int(ns.getID()),
            "created": True,
        }

    result = _maybe_swing(ctx, do_create)
    ctx.save_program(pi)
    return result


def _handle_list_namespaces(ctx, args: dict) -> dict:
    """List all namespaces in the program.

    Args (in ``args`` dict):
        binary -- program name / key
        limit  -- max results (default 500)

    Returns a dict with:
        namespaces -- list of {name, path, id, symbol_count} dicts
        count      -- number of namespaces returned
    """
    binary = args.get("binary", "")
    limit  = int(args.get("limit", 500))

    pi = ctx.get_program(binary)

    def do_list():
        from ghidra.program.model.symbol import SymbolType

        st = pi.program.getSymbolTable()
        namespaces = []

        # Iterate all namespace symbols
        for sym in st.getSymbolIterator():
            if sym.getSymbolType() == SymbolType.NAMESPACE or \
               sym.getSymbolType() == SymbolType.CLASS:
                ns = sym.getObject()
                # Count children
                child_count = 0
                child_iter = st.getChildren(sym)
                for _ in child_iter:
                    child_count += 1

                namespaces.append({
                    "name":         str(sym.getName()),
                    "path":         str(ns.getName(True)) if ns else str(sym.getName()),
                    "id":           int(sym.getID()),
                    "type":         str(sym.getSymbolType()),
                    "symbol_count": child_count,
                })
                if len(namespaces) >= limit:
                    break

        return {
            "namespaces": namespaces,
            "count":      len(namespaces),
        }

    return _maybe_swing(ctx, do_list)


def _handle_batch_rename(ctx, args: dict) -> dict:
    """Batch rename functions or labels in a single round-trip.

    Executes all renames in a single Ghidra transaction, so a 40-item
    batch takes roughly the same wall-clock time as a single rename.

    Args (in ``args`` dict):
        binary     -- program name / key
        operations -- list of dicts:
                       function mode: {target, new_name[, namespace]}
                       label mode:    {address, new_name[, create]}
        mode       -- ``"function"`` (default) or ``"label"``

    Returns a dict with:
        results     -- per-item list of {ok, index, address, old_name, new_name}
                       or {ok:False, index, error, message} for failures
        count       -- total items processed
        ok_count    -- items that succeeded
        error_count -- items that failed
    """
    binary     = args.get("binary", "")
    operations = args.get("operations", [])
    mode       = args.get("mode", "function")

    if not isinstance(operations, list) or not operations:
        raise ValueError("'operations' must be a non-empty list")

    pi = ctx.get_program(binary)

    def do_batch():
        from ghidra.program.model.symbol import SourceType
        from ghidra_rpc.server.context import _parse_address

        results = [None] * len(operations)

        # Phase 1: pre-resolve all items without touching the DB.
        # Resolution failures are recorded immediately; the rest proceed.
        resolved = []
        for idx, op in enumerate(operations):
            new_name = str(op.get("new_name", "")).strip()
            if not new_name:
                results[idx] = {
                    "ok": False, "index": idx,
                    "error": "ValueError", "message": "missing new_name",
                }
                continue

            if mode == "label":
                address = op.get("address", "")
                if not address:
                    results[idx] = {
                        "ok": False, "index": idx,
                        "error": "ValueError", "message": "missing address",
                    }
                    continue
                try:
                    addr  = _parse_address(pi.program, address)
                    st    = pi.program.getSymbolTable()
                    syms  = list(st.getSymbols(addr))
                    create = bool(op.get("create", True))
                    if not syms and not create:
                        raise ValueError(f"No symbol at {address}")
                    resolved.append((idx, "label", addr, syms, new_name, create))
                except Exception as e:
                    results[idx] = {
                        "ok": False, "index": idx,
                        "address": address, "new_name": new_name,
                        "error": type(e).__name__, "message": str(e),
                    }
            else:  # function
                target    = op.get("target", op.get("address", ""))
                namespace = op.get("namespace", "")
                if not target:
                    results[idx] = {
                        "ok": False, "index": idx,
                        "error": "ValueError", "message": "missing target or address",
                    }
                    continue
                try:
                    func = _find_function(pi, target)
                    resolved.append((idx, "function", func, new_name, namespace))
                except Exception as e:
                    results[idx] = {
                        "ok": False, "index": idx,
                        "target": target, "new_name": new_name,
                        "error": type(e).__name__, "message": str(e),
                    }

        # Phase 2: apply resolved ops in one transaction (one sleep, not N).
        if resolved:
            with ghidra_transaction(
                pi.program,
                f"ghidra-rpc: batch-rename ({len(resolved)} ops)",
            ):
                for item in resolved:
                    idx  = item[0]
                    kind = item[1]
                    if kind == "label":
                        _, _, addr, syms, new_name, create = item
                        try:
                            st = pi.program.getSymbolTable()
                            if syms:
                                old_name = str(syms[0].getName())
                                syms[0].setName(new_name, SourceType.USER_DEFINED)
                            else:
                                old_name = None
                                st.createLabel(addr, new_name, SourceType.USER_DEFINED)
                            results[idx] = {
                                "ok": True, "index": idx,
                                "address": str(addr),
                                "old_name": old_name, "new_name": new_name,
                            }
                        except Exception as e:
                            results[idx] = {
                                "ok": False, "index": idx,
                                "address": str(addr), "new_name": new_name,
                                "error": type(e).__name__, "message": str(e),
                            }
                    else:  # function
                        _, _, func, new_name, namespace = item
                        old_name = str(func.getName())
                        address  = str(func.getEntryPoint())
                        try:
                            func.setName(new_name, SourceType.USER_DEFINED)
                            if namespace:
                                ns = _resolve_namespace(pi.program, namespace)
                                func.setParentNamespace(ns)
                            results[idx] = {
                                "ok": True, "index": idx,
                                "address": address,
                                "old_name": old_name,
                                "new_name": str(func.getName()),
                            }
                        except Exception as e:
                            results[idx] = {
                                "ok": False, "index": idx,
                                "address": address, "new_name": new_name,
                                "error": type(e).__name__, "message": str(e),
                            }

            pi.decompiler_pool.invalidate_all()

        return [r for r in results if r is not None]

    final_results = _maybe_swing(ctx, do_batch)
    ctx.save_program(pi)

    ok_count = sum(1 for r in final_results if r.get("ok"))
    return {
        "results":     final_results,
        "count":       len(final_results),
        "ok_count":    ok_count,
        "error_count": len(final_results) - ok_count,
    }


def _handle_batch_set_comment(ctx, args: dict) -> dict:
    """Batch set comments at multiple addresses in a single round-trip.

    Args (in ``args`` dict):
        binary     -- program name / key
        operations -- list of {address, comment[, comment_type]}
                       comment_type defaults to ``"eol"``

    Returns a dict with:
        results     -- per-item list of {ok, index, address, comment_type, comment}
                       or {ok:False, index, error, message} for failures
        count, ok_count, error_count
    """
    binary     = args.get("binary", "")
    operations = args.get("operations", [])

    if not isinstance(operations, list) or not operations:
        raise ValueError("'operations' must be a non-empty list")

    pi = ctx.get_program(binary)

    def do_batch():
        from ghidra_rpc.server.context import _parse_address

        try:
            from ghidra.program.model.listing import CommentType
            type_map = {
                "plate":      CommentType.PLATE,
                "pre":        CommentType.PRE,
                "post":       CommentType.POST,
                "eol":        CommentType.EOL,
                "repeatable": CommentType.REPEATABLE,
            }
        except ImportError:
            from ghidra.program.model.listing import CodeUnit
            type_map = {
                "plate":      CodeUnit.PLATE_COMMENT,
                "pre":        CodeUnit.PRE_COMMENT,
                "post":       CodeUnit.POST_COMMENT,
                "eol":        CodeUnit.EOL_COMMENT,
                "repeatable": CodeUnit.REPEATABLE_COMMENT,
            }

        results  = [None] * len(operations)
        resolved = []

        for idx, op in enumerate(operations):
            address = op.get("address", "")
            comment = op.get("comment", "")
            ct_name = op.get("comment_type", "eol").lower()

            if not address:
                results[idx] = {
                    "ok": False, "index": idx,
                    "error": "ValueError", "message": "missing address",
                }
                continue

            ghidra_ct = type_map.get(ct_name)
            if ghidra_ct is None:
                results[idx] = {
                    "ok": False, "index": idx, "address": address,
                    "error": "ValueError",
                    "message": (
                        f"Invalid comment_type '{ct_name}'. "
                        f"Use one of: {list(type_map.keys())}"
                    ),
                }
                continue

            try:
                try:
                    addr = _parse_address(pi.program, address)
                except ValueError:
                    func = _find_function(pi, address)
                    addr = func.getEntryPoint()
                resolved.append((idx, addr, comment, ghidra_ct, ct_name))
            except Exception as e:
                results[idx] = {
                    "ok": False, "index": idx, "address": address,
                    "error": type(e).__name__, "message": str(e),
                }

        if resolved:
            with ghidra_transaction(
                pi.program,
                f"ghidra-rpc: batch-set-comment ({len(resolved)} ops)",
            ):
                listing = pi.program.getListing()
                for idx, addr, comment, ghidra_ct, ct_name in resolved:
                    try:
                        listing.setComment(addr, ghidra_ct, comment if comment else None)
                        results[idx] = {
                            "ok": True, "index": idx,
                            "address": str(addr),
                            "comment_type": ct_name,
                            "comment": comment,
                        }
                    except Exception as e:
                        results[idx] = {
                            "ok": False, "index": idx, "address": str(addr),
                            "error": type(e).__name__, "message": str(e),
                        }

            pi.decompiler_pool.invalidate_all()

        return [r for r in results if r is not None]

    final_results = _maybe_swing(ctx, do_batch)
    ctx.save_program(pi)

    ok_count = sum(1 for r in final_results if r.get("ok"))
    return {
        "results":     final_results,
        "count":       len(final_results),
        "ok_count":    ok_count,
        "error_count": len(final_results) - ok_count,
    }


def _handle_delete_function(ctx, args: dict) -> dict:
    """Delete (remove) a function definition from the program.

    Only removes the function record — the underlying bytes are unchanged
    and the address becomes undefined code.  Use after creating bad stubs
    (e.g. wrong Thumb parity) or to reset a misidentified function so it
    can be re-created at the correct address.

    Args (in ``args`` dict):
        binary -- program name / key
        target -- function name or hex address

    Returns a dict with:
        address -- function entry point
        name    -- function name that was deleted
        deleted -- True if the function was removed
    """
    binary = args.get("binary", "")
    target = args.get("target", args.get("address", ""))

    if not target:
        raise ValueError("Missing required argument: target (function name or address)")

    pi = ctx.get_program(binary)

    def do_delete():
        func      = _find_function(pi, target)
        func_name = str(func.getName())
        func_addr = func.getEntryPoint()

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: delete function {func_name} @ {func_addr}",
        ):
            removed = pi.program.getFunctionManager().removeFunction(func_addr)

        pi.decompiler_pool.invalidate_all()
        return {
            "address": str(func_addr),
            "name":    func_name,
            "deleted": bool(removed),
        }

    result = _maybe_swing(ctx, do_delete)
    ctx.save_program(pi)
    return result


register_handler("create_label",              _handle_create_label)
register_handler("create_function",           _handle_create_function)
register_handler("rename_function",           _handle_rename_function)
register_handler("rename_symbol",             _handle_rename_symbol)
register_handler("set_comment",               _handle_set_comment)
register_handler("set_function_signature",    _handle_set_function_signature)
register_handler("set_data_type",             _handle_set_data_type)
register_handler("retype_variable",           _handle_retype_variable)
register_handler("rename_variable",           _handle_rename_variable)
register_handler("set_calling_convention",    _handle_set_calling_convention)
register_handler("set_thunk",                 _handle_set_thunk)
register_handler("set_flow_override",         _handle_set_flow_override)
register_handler("create_namespace",          _handle_create_namespace)
register_handler("list_namespaces",           _handle_list_namespaces)
register_handler("batch_rename",              _handle_batch_rename)
register_handler("batch_set_comment",         _handle_batch_set_comment)
register_handler("delete_function",           _handle_delete_function)
