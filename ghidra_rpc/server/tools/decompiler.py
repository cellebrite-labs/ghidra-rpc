"""Decompiler tools: decompile functions to pseudo-C."""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler


def _find_function(pi, name_or_address: str):
    """Resolve a function by name or hex address. Raises ValueError if not found or ambiguous."""
    prog = pi.program
    fm = prog.getFunctionManager()
    af = prog.getAddressFactory()

    # Try as address first
    if name_or_address.startswith("0x") or name_or_address.startswith("0X"):
        addr_str = name_or_address[2:]
        try:
            addr = af.getAddress(addr_str)
            if addr:
                func = fm.getFunctionAt(addr)
                if func:
                    return func
                # Maybe it's inside a function
                func = fm.getFunctionContaining(addr)
                if func:
                    return func
        except Exception:
            pass

    # Try as exact name
    name_lower = name_or_address.lower()
    exact_matches = []
    partial_matches = []

    for func in fm.getFunctions(True):
        func_name = str(func.getName())
        if func_name.lower() == name_lower:
            exact_matches.append(func)
        elif name_lower in func_name.lower():
            partial_matches.append(func)

    if len(exact_matches) == 1:
        return exact_matches[0]
    elif len(exact_matches) > 1:
        suggestions = [f"{f.getName()} @ 0x{f.getEntryPoint()}" for f in exact_matches]
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Matches: {suggestions}"
        )

    if len(partial_matches) == 1:
        return partial_matches[0]
    elif len(partial_matches) > 1:
        suggestions = [f"{f.getName()} @ 0x{f.getEntryPoint()}" for f in partial_matches[:10]]
        raise ValueError(
            f"Ambiguous function name '{name_or_address}'. Partial matches: {suggestions}"
        )

    raise ValueError(f"Function '{name_or_address}' not found. If '{name_or_address} is an address, pass it with a 0x prefix")


def _handle_decompile(ctx, args: dict) -> dict:
    """Decompile a function and return its pseudo-C code."""
    binary = args.get("binary", "")
    func_name = args.get("func", "")
    timeout = args.get("timeout", 60)

    if not func_name:
        raise ValueError("Missing required argument: func")

    pi = ctx.get_program(binary)
    func = _find_function(pi, func_name)

    from ghidra.util.task import TaskMonitor

    with pi.decompiler_pool.acquire() as decompiler:
        result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)

    error_msg = result.getErrorMessage()
    if error_msg and error_msg.strip():
        return {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "c_code": None,
            "error": error_msg,
        }

    decompiled = result.getDecompiledFunction()
    c_code = str(decompiled.getC()) if decompiled else ""

    return {
        "name": str(func.getName()),
        "address": str(func.getEntryPoint()),
        "signature": str(decompiled.getSignature()) if decompiled else str(func.getSignature()),
        "c_code": c_code,
    }


def _handle_search_decompiled(ctx, args: dict) -> dict:
    """Regex-search the decompiled C of many functions in one RPC call.

    Avoids the "enumerate with `symbols`, `decompile` each, grep the C
    client-side" pattern (one round-trip per function) for tasks like
    "which function builds this UUID / calls this callee / touches this
    struct field".

    Args (in ``args`` dict):
        binary        -- program name / key
        pattern       -- regex to search for, applied per source line
        class_filter  -- optional: only search functions whose fully
                          qualified name (namespace path, e.g.
                          "com::example::Foo::bar") contains this substring
                          (case-insensitive)
        ignore_case   -- case-insensitive pattern match (default True)
        limit         -- max matching functions to return (default 50)
        max_functions -- safety cap on functions actually decompiled
                          (default 5000); stops the sweep early on very
                          large programs (e.g. 50k+-function DEX files)
        timeout       -- per-function decompiler timeout in seconds (default 60)

    Returns a dict with:
        matches             -- list of {function, address, matching_lines}
                                where matching_lines is a list of
                                {line, text}
        count               -- number of functions with at least one match
        functions_searched  -- number of functions actually decompiled
        functions_total     -- number of functions matching class_filter
                                (before the limit/max_functions cutoff)
        truncated           -- True if the sweep stopped before covering
                                every candidate function (limit or
                                max_functions reached)
    """
    import re

    from ghidra.util.task import TaskMonitor

    binary        = args.get("binary", "")
    pattern_str   = args.get("pattern", "")
    class_filter  = args.get("class_filter", "")
    ignore_case   = bool(args.get("ignore_case", True))
    limit         = int(args.get("limit", 50))
    max_functions = int(args.get("max_functions", 5000))
    timeout       = int(args.get("timeout", 60))

    if not binary:
        raise ValueError("Missing required argument: binary")
    if not pattern_str:
        raise ValueError("Missing required argument: pattern")

    try:
        regex = re.compile(pattern_str, re.IGNORECASE if ignore_case else 0)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")

    pi = ctx.get_program(binary)
    fm = pi.program.getFunctionManager()
    class_filter_lower = class_filter.lower() if class_filter else None

    candidates = []
    for func in fm.getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        qualified_name = str(func.getSymbol().getName(True))
        if class_filter_lower and class_filter_lower not in qualified_name.lower():
            continue
        candidates.append((func, qualified_name))

    total = len(candidates)
    matches = []
    functions_searched = 0
    truncated = False

    for func, qualified_name in candidates:
        if functions_searched >= max_functions or len(matches) >= limit:
            truncated = True
            break
        functions_searched += 1

        try:
            with pi.decompiler_pool.acquire() as decompiler:
                result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)
            decompiled = result.getDecompiledFunction()
            if decompiled is None:
                continue
            c_code = str(decompiled.getC())
        except Exception:
            continue

        matching_lines = [
            {"line": i, "text": line.strip()}
            for i, line in enumerate(c_code.splitlines(), start=1)
            if regex.search(line)
        ]
        if matching_lines:
            matches.append({
                "function": qualified_name,
                "address": str(func.getEntryPoint()),
                "matching_lines": matching_lines,
            })

    return {
        "matches": matches,
        "count": len(matches),
        "functions_searched": functions_searched,
        "functions_total": total,
        "truncated": truncated,
    }


register_handler("decompile", _handle_decompile)
register_handler("search_decompiled", _handle_search_decompiled)
