"""Analysis and listing tools: binaries, functions, imports, exports, metadata."""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler


def _handle_load(ctx, args: dict) -> dict:
    """Load a binary into the project."""
    from pathlib import Path as _Path

    path = args.get("path")
    if not path:
        raise ValueError("Missing required argument: path")
    analyze = bool(args.get("analyze", True))
    analysis_timeout = args.get("analysis_timeout")  # int | None
    if analysis_timeout is not None:
        analysis_timeout = int(analysis_timeout)
    key = ctx.load_binary(path, analyze=analyze, analysis_timeout=analysis_timeout)
    pi = ctx.get_program(key)
    # short_name is the original filename without the hash suffix — it works as
    # an alias in all subsequent commands because get_program() supports
    # substring matching (as long as only one binary with that stem is loaded).
    short_name = _Path(path).name
    return {
        "binary":            key,
        "short_name":        short_name,
        "analysis_complete": pi.analysis_complete,
    }


def _handle_list_binaries(ctx, args: dict) -> dict:
    """List binaries currently opened/attached in the daemon."""
    with ctx._programs_lock:
        binaries = []
        for key, pi in ctx.programs.items():
            binaries.append({
                "name": pi.name,
                "path": key,
                "analysis_complete": pi.analysis_complete,
            })
    return {"binaries": binaries}


def _handle_list_project_programs(ctx, args: dict) -> dict:
    """List all programs stored in the Ghidra project (repo on disk).

    Unlike list_binaries, this does not require the program to be open in
    CodeBrowser (GUI mode) or loaded into the daemon — it enumerates the
    project folder directly.
    """
    programs = []
    warning = None

    project = getattr(ctx, "project", None)

    # In GUI mode, always fetch the freshest active project from AppInfo and
    # validate it matches the project the daemon was started against.  ctx.project
    # is set at daemon startup and can become stale if the user switches projects
    # inside the Ghidra GUI after the daemon launched.
    if hasattr(ctx, "run_on_swing"):
        try:
            from ghidra.framework.main import AppInfo
            from ghidra_rpc.server.context import GuiContext
            active = AppInfo.getActiveProject()
            if active is not None:
                if not GuiContext._project_matches(active, ctx.session):
                    locator = active.getProjectLocator()
                    active_name = str(locator.getName())
                    expected_name = ctx.session.project_gpr.stem
                    warning = (
                        f"Active Ghidra project '{active_name}' does not match "
                        f"expected project '{expected_name}'. The programs listed "
                        f"below are from the wrong project. Open '{expected_name}' "
                        f"in Ghidra's Project window and retry."
                    )
                project = active
        except Exception:
            pass

    if project is None:
        return {"programs": programs, "count": 0}

    try:
        project_data = project.getProjectData()
        root = project_data.getRootFolder()

        def _walk(folder, prefix="/"):
            for df in folder.getFiles():
                path = prefix + str(df.getName())
                entry = {
                    "name": str(df.getName()),
                    "path": path,
                    "content_type": str(df.getContentType()) if hasattr(df, "getContentType") else None,
                }
                # Check whether this program is currently loaded in the daemon
                with ctx._programs_lock:
                    entry["loaded"] = path in ctx.programs
                programs.append(entry)
            for sub_folder in folder.getFolders():
                _walk(sub_folder, prefix + str(sub_folder.getName()) + "/")

        _walk(root)
    except Exception as exc:
        raise RuntimeError(f"Failed to enumerate project folder: {exc}") from exc

    result = {"programs": programs, "count": len(programs)}
    if warning:
        result["warning"] = warning
    return result


def _handle_list_functions(ctx, args: dict) -> dict:
    """List all functions in a binary, with optional pagination and range filter.

    Extra args:
        address_min -- only return functions at or above this address
        address_max -- only return functions at or below this address
        with_body   -- if true, include body_min, body_max, body_size per function
    """
    from ghidra_rpc.server.context import _iter_functions_in_range

    binary = args.get("binary", "")
    pi = ctx.get_program(binary)

    include_externals = args.get("include_externals", False)
    offset = int(args.get("offset", 0))
    limit = args.get("limit", None)
    if limit is not None:
        limit = int(limit)

    address_min_str = args.get("address_min", "")
    address_max_str = args.get("address_max", "")
    with_body       = bool(args.get("with_body", False))

    functions = []
    for func in _iter_functions_in_range(pi.program, address_min_str, address_max_str):
        if not include_externals and (func.isExternal() or func.isThunk()):
            continue

        entry = func.getEntryPoint()
        item = {
            "name":      str(func.getName()),
            "address":   str(entry),
            "signature": str(func.getSignature()),
        }
        if with_body:
            body = func.getBody()
            item["body_min"]  = str(body.getMinAddress())
            item["body_max"]  = str(body.getMaxAddress())
            item["body_size"] = int(body.getNumAddresses())

        functions.append(item)

    total = len(functions)
    page = functions[offset:] if offset else functions
    if limit is not None:
        page = page[:limit]

    return {
        "functions": page,
        "count":     len(page),
        "total":     total,
        "offset":    offset,
    }


def _handle_list_imports(ctx, args: dict) -> dict:
    """List imported symbols."""
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)
    st = pi.program.getSymbolTable()

    imports = []
    for sym in st.getExternalSymbols():
        imports.append({
            "name": str(sym.getName()),
            "address": str(sym.getAddress()),
            "library": str(sym.getParentNamespace()),
        })
    return {"imports": imports, "count": len(imports)}


def _handle_list_exports(ctx, args: dict) -> dict:
    """List exported symbols."""
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)
    st = pi.program.getSymbolTable()

    exports = []
    for sym in st.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            exports.append({
                "name": str(sym.getName()),
                "address": str(sym.getAddress()),
            })
    return {"exports": exports, "count": len(exports)}


def _handle_binary_metadata(ctx, args: dict) -> dict:
    """Get metadata about a binary (architecture, format, etc.)."""
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)
    prog = pi.program

    language = prog.getLanguage()
    compiler_spec = prog.getCompilerSpec()

    return {
        "name": pi.name,
        "arch": str(language.getProcessor()),
        "bits": language.getLanguageDescription().getSize(),
        "endian": str(language.getLanguageDescription().getEndian()),
        "format": str(prog.getExecutableFormat()),
        "compiler": str(compiler_spec.getCompilerSpecID()),
        "base_address": str(prog.getImageBase()),
        "num_functions": prog.getFunctionManager().getFunctionCount(),
    }


def _handle_save(ctx, args: dict) -> dict:
    """Save a program (or all programs) to the project database on disk."""
    binary = args.get("binary", "")

    if binary:
        pi = ctx.get_program(binary)
        ctx.save_program(pi)
        return {"saved": [pi.name]}
    else:
        # Save all loaded programs
        saved = []
        with ctx._programs_lock:
            programs_to_save = list(ctx.programs.values())
        for pi in programs_to_save:
            ctx.save_program(pi)
            saved.append(pi.name)
        return {"saved": saved}


# Register all handlers
register_handler("load", _handle_load)
register_handler("list_binaries", _handle_list_binaries)
register_handler("list_project_programs", _handle_list_project_programs)
register_handler("functions", _handle_list_functions)
register_handler("imports", _handle_list_imports)
register_handler("exports", _handle_list_exports)
register_handler("metadata", _handle_binary_metadata)
register_handler("save", _handle_save)


def _handle_relocations(ctx, args: dict) -> dict:
    """List relocation table entries for a binary.

    Args (in ``args`` dict):
        binary  -- program name / key
        address -- optional: filter relocations at this specific address
        limit   -- max results (default 200, max 10000)

    Returns a dict with:
        relocations -- list of dicts:
                         address    -- relocation address
                         type       -- relocation type (integer)
                         symbol     -- associated symbol name (if any)
                         bytes      -- original bytes at the address (hex)
                         status     -- relocation status string
        count       -- number returned
        total       -- total relocations (may be > count if truncated)

    Important for understanding PIC/PIE code, distinguishing data
    pointers from code pointers, and import address table analysis.
    """
    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    limit       = int(args.get("limit", 200))
    if limit > 10000:
        limit = 10000

    pi = ctx.get_program(binary)
    reloc_table = pi.program.getRelocationTable()

    relocations = []
    total = 0

    if address_str:
        from ghidra_rpc.server.context import _parse_address
        addr = _parse_address(pi.program, address_str)
        relocs = reloc_table.getRelocations(addr)
        for r in relocs:
            total += 1
            if len(relocations) < limit:
                relocations.append(_format_relocation(r))
    else:
        reloc_iter = reloc_table.getRelocations()
        for r in reloc_iter:
            total += 1
            if len(relocations) < limit:
                relocations.append(_format_relocation(r))

    return {
        "relocations": relocations,
        "count":       len(relocations),
        "total":       total,
    }


def _format_relocation(r) -> dict:
    """Format a single Relocation object into a dict."""
    # Symbol name — may be None on some Ghidra versions
    sym_name = None
    try:
        sym_name = str(r.getSymbolName()) if r.getSymbolName() else None
    except Exception:
        pass

    # Original bytes — may be None
    orig_bytes = None
    try:
        b = r.getBytes()
        if b is not None:
            orig_bytes = bytes(x & 0xFF for x in b).hex()
    except Exception:
        pass

    # Status
    status = None
    try:
        status = str(r.getStatus())
    except Exception:
        pass

    return {
        "address": str(r.getAddress()),
        "type":    int(r.getType()),
        "symbol":  sym_name,
        "bytes":   orig_bytes,
        "status":  status,
    }


register_handler("relocations", _handle_relocations)


def _handle_list_calling_conventions(ctx, args: dict) -> dict:
    """List all calling conventions available for the current architecture.

    Returns the names of all calling conventions defined by the program's
    compiler spec (e.g. ``__cdecl``, ``__stdcall``, ``__fastcall``,
    ``__thiscall``, AAPCS, …).  Needed before ``set-calling-convention``
    to know which names are valid.

    Args (in ``args`` dict):
        binary -- program name / key

    Returns a dict with:
        conventions -- list of convention name strings
        default     -- the program's default calling convention name
        count       -- number of conventions
    """
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)
    compiler_spec = pi.program.getCompilerSpec()

    conventions = []
    for cc in compiler_spec.getCallingConventions():
        conventions.append(str(cc.getName()))

    default_cc = str(compiler_spec.getDefaultCallingConvention().getName())

    return {
        "conventions": conventions,
        "default":     default_cc,
        "count":       len(conventions),
    }


register_handler("list_calling_conventions", _handle_list_calling_conventions)
