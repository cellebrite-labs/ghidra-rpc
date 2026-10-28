"""Version Tracking tools: compare binaries, match functions, bulk decompile."""

from __future__ import annotations

import logging
import time

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler

logger = logging.getLogger("ghidra-rpc.vt")


# ---------------------------------------------------------------------------
# Helpers: temporarily release daemon's program handles for VT
# ---------------------------------------------------------------------------

def _open_vt_programs(ctx, binary1: str, binary2: str, consumer: str):
    """Temporarily close daemon's program handles and open fresh ones for VT.

    VTSessionDB requires writable access to the destination program, which
    conflicts with the daemon's exclusive write lock via GhidraProject.
    This helper saves and closes the daemon's references, then opens
    fresh writable references with a VT-specific consumer.

    Returns (src_prog, dst_prog, src_name, dst_name, src_key, dst_key).
    Caller MUST call _restore_daemon_programs() in a finally block.
    """
    from ghidra.util.task import TaskMonitor

    pi_src = ctx.get_program(binary1)
    pi_dst = ctx.get_program(binary2)

    # Save before closing
    ctx.save_program(pi_src)
    ctx.save_program(pi_dst)

    src_name = pi_src.name
    dst_name = pi_dst.name

    # Find keys in ctx.programs
    src_key = dst_key = None
    with ctx._programs_lock:
        for k, v in ctx.programs.items():
            if v is pi_src:
                src_key = k
            if v is pi_dst:
                dst_key = k

    # Dispose decompiler pools before closing
    pi_src.decompiler_pool.dispose()
    pi_dst.decompiler_pool.dispose()

    # Close daemon's references
    ctx.project.close(pi_src.program)
    ctx.project.close(pi_dst.program)
    with ctx._programs_lock:
        if src_key:
            del ctx.programs[src_key]
        if dst_key:
            del ctx.programs[dst_key]

    # Open fresh references via DomainFile for VT
    root = ctx.project.getProjectData().getRootFolder()
    src_df = root.getFile(src_name)
    dst_df = root.getFile(dst_name)
    if src_df is None or dst_df is None:
        _restore_daemon_programs(ctx, src_name, dst_name, src_key, dst_key)
        raise RuntimeError("Could not find program DomainFiles in project")

    src_prog = src_df.getDomainObject(consumer, False, False, TaskMonitor.DUMMY)
    dst_prog = dst_df.getDomainObject(consumer, False, False, TaskMonitor.DUMMY)

    return src_prog, dst_prog, src_name, dst_name, src_key, dst_key


def _restore_daemon_programs(ctx, src_name, dst_name, src_key, dst_key):
    """Re-open programs in the daemon context after VT is done."""
    from ghidra.program.flatapi import FlatProgramAPI

    from ghidra_rpc.server.context import (
        DecompilerPool,
        ProgramInfo,
        _setup_decompiler,
    )

    for name, key in [(src_name, src_key), (dst_name, dst_key)]:
        if not key:
            continue
        try:
            program = ctx.project.openProgram("/", name, False)
            ctx._take_ownership(program)
            flat_api = FlatProgramAPI(program)
            pi = ProgramInfo(
                name=name,
                program=program,
                flat_api=flat_api,
                decompiler_pool=DecompilerPool(
                    lambda p=program: _setup_decompiler(p), size=2
                ),
                metadata=dict(program.getMetadata()),
                analysis_complete=True,
                file_path=None,
                load_time=time.time(),
            )
            with ctx._programs_lock:
                ctx.programs[key] = pi
            logger.debug("Restored daemon program: %s -> %s", name, key)
        except Exception:
            logger.error("Failed to restore program %s", name, exc_info=True)


# ---------------------------------------------------------------------------
# version_track: run Version Tracking correlators between two loaded binaries
# ---------------------------------------------------------------------------

_CORRELATOR_FACTORIES = [
    "ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.ExactMatchMnemonicsProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.ExactDataMatchProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.DuplicateFunctionMatchProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.FunctionReferenceProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.CombinedFunctionAndDataReferenceProgramCorrelatorFactory",
]


def _handle_version_track(ctx, args: dict) -> dict:
    """Run Version Tracking correlators between two loaded binaries.

    Uses Ghidra's built-in correlators (exact bytes, exact instructions,
    exact mnemonics, symbol name, reference, duplicate function, BSim) to
    find matching functions/data between a source and destination binary.

    Temporarily closes and reopens the daemon's program handles to avoid
    exclusive-lock conflicts with VTSessionDB.

    Returns matched pairs with similarity scores and lists of unmatched
    functions in each binary.
    """
    from ghidra.feature.vt.api.db import VTSessionDB
    from ghidra.feature.vt.api.main import VTAssociationType

    binary1 = args.get("source", args.get("binary1", ""))
    binary2 = args.get("destination", args.get("binary2", ""))
    limit = int(args.get("limit", 500))
    include_data = bool(args.get("include_data", False))
    min_similarity = float(args.get("min_similarity", 0.0))
    changed_only = bool(args.get("changed_only", False))

    if not binary1 or not binary2:
        raise ValueError(
            "Missing required arguments: source (binary1) and destination (binary2)"
        )

    consumer = "ghidra-rpc-vt"
    src_prog, dst_prog, src_name, dst_name, src_key, dst_key = \
        _open_vt_programs(ctx, binary1, binary2, consumer)

    session_name = f"ghidra-rpc-vt-{src_name}-vs-{dst_name}"
    vt_session = VTSessionDB.createVTSession(
        session_name, src_prog, dst_prog, consumer
    )

    try:
        src_addr_set = src_prog.getMemory().getLoadedAndInitializedAddressSet()
        dst_addr_set = dst_prog.getMemory().getLoadedAndInitializedAddressSet()

        # Run each correlator manually
        correlators_run = []
        for factory_class in _CORRELATOR_FACTORIES:
            ok = _run_single_correlator(
                vt_session, src_prog, dst_prog,
                src_addr_set, dst_addr_set, factory_class,
            )
            if ok:
                correlators_run.append(factory_class.rsplit(".", 1)[-1])

        # Run BSim if available
        bsim_ran = _run_bsim_correlator(vt_session, src_prog, dst_prog)
        if bsim_ran:
            correlators_run.append("BSimProgramCorrelatorFactory")

        # Collect matches from all match sets
        matched = []
        matched_src_addrs = set()
        matched_dst_addrs = set()

        for match_set in vt_session.getMatchSets():
            correlator_info = match_set.getProgramCorrelatorInfo()
            correlator_name = str(correlator_info.getName()) if correlator_info else "unknown"
            for match in match_set.getMatches():
                assoc = match.getAssociation()
                assoc_type = assoc.getType()

                if assoc_type == VTAssociationType.DATA and not include_data:
                    continue

                similarity = match.getSimilarityScore().getScore()
                confidence = match.getConfidenceScore().getScore()

                if similarity < min_similarity:
                    continue

                src_addr = _fmt_address(match.getSourceAddress())
                dst_addr = _fmt_address(match.getDestinationAddress())

                src_func_name = _get_function_name_at(src_prog, match.getSourceAddress())
                dst_func_name = _get_function_name_at(dst_prog, match.getDestinationAddress())

                entry = {
                    "source_name": src_func_name,
                    "source_address": src_addr,
                    "destination_name": dst_func_name,
                    "destination_address": dst_addr,
                    "similarity": round(similarity, 4),
                    "confidence": round(confidence, 4),
                    "type": str(assoc_type),
                    "status": str(assoc.getStatus()),
                    "correlator": correlator_name,
                }
                matched.append(entry)
                matched_src_addrs.add(src_addr)
                matched_dst_addrs.add(dst_addr)

        # Deduplicate: per source address, keep only the single best-scoring
        # destination.  Many-to-many correlators (e.g. DuplicateFunctionMatch)
        # can produce N entries for every stub function, exhausting the limit
        # budget before better BSim/reference matches are emitted.  Keying on
        # source address bounds the result count to the number of unique source
        # functions and ensures important low-similarity BSim matches survive.
        seen: dict = {}
        for entry in matched:
            key = entry["source_address"]
            prev = seen.get(key)
            if (
                prev is None
                or entry["similarity"] > prev["similarity"]
                or (
                    entry["similarity"] == prev["similarity"]
                    and entry["confidence"] > prev["confidence"]
                )
            ):
                seen[key] = entry
        matched = sorted(seen.values(), key=lambda x: -x["similarity"])

        # Rebuild matched address sets from deduplicated results
        matched_src_addrs = {e["source_address"] for e in matched}
        matched_dst_addrs = {e["destination_address"] for e in matched}

        # Compute change stats against the full pre-limit, post-dedup set so
        # summary counts are accurate even when --limit truncates the output.
        total_matched = len(matched)
        changed_count = sum(1 for e in matched if e["similarity"] < 1.0)
        identical_count = total_matched - changed_count

        # Apply --changed-only filter before limit
        if changed_only:
            matched = [e for e in matched if e["similarity"] < 1.0]

        if limit and len(matched) > limit:
            matched = matched[:limit]

        # Get unmatched functions
        unmatched_source = _get_unmatched_functions(src_prog, matched_src_addrs)
        unmatched_dest = _get_unmatched_functions(dst_prog, matched_dst_addrs)

        return {
            "matched": matched,
            "unmatched_source": unmatched_source,
            "unmatched_destination": unmatched_dest,
            "summary": {
                "source_functions_total": total_matched + len(unmatched_source),
                "source_functions_matched": total_matched,
                "source_functions_unmatched": len(unmatched_source),
                "changed_functions": changed_count,
                "identical_functions": identical_count,
                "destination_functions_unmatched": len(unmatched_dest),
                "bsim_used": bsim_ran,
                "correlators_run": correlators_run,
            },
        }
    finally:
        vt_session.release(consumer)
        src_prog.release(consumer)
        dst_prog.release(consumer)
        _restore_daemon_programs(ctx, src_name, dst_name, src_key, dst_key)


def _run_single_correlator(
    vt_session, src_prog, dst_prog, src_addr_set, dst_addr_set,
    factory_class_name: str,
) -> bool:
    """Run one correlator factory. Returns True on success."""
    from ghidra.util.task import TaskMonitor

    try:
        parts = factory_class_name.rsplit(".", 1)
        mod = __import__(parts[0], fromlist=[parts[1]])
        cls = getattr(mod, parts[1])
        factory = cls()

        options = factory.createDefaultOptions()
        correlator = factory.createCorrelator(
            src_prog, src_addr_set, dst_prog, dst_addr_set, options
        )

        txn = vt_session.startTransaction(f"correlator-{factory.getName()}")
        try:
            correlator.correlate(vt_session, TaskMonitor.DUMMY)
            vt_session.endTransaction(txn, True)
        except Exception:
            vt_session.endTransaction(txn, False)
            raise

        logger.info("Correlator %s completed", factory.getName())
        return True
    except Exception as e:
        logger.debug("Correlator %s failed: %s", factory_class_name, e)
        return False


def _run_bsim_correlator(vt_session, src_prog, dst_prog) -> bool:
    """Run BSim correlator on the VT session. Returns True if successful."""
    try:
        from ghidra.feature.vt.api import BSimProgramCorrelatorFactory
        from ghidra.util.task import TaskMonitor

        factory = BSimProgramCorrelatorFactory()
        options = factory.createDefaultOptions()

        src_addr_set = src_prog.getMemory().getLoadedAndInitializedAddressSet()
        dst_addr_set = dst_prog.getMemory().getLoadedAndInitializedAddressSet()

        correlator = factory.createCorrelator(
            src_prog, src_addr_set, dst_prog, dst_addr_set, options
        )

        txn = vt_session.startTransaction("BSim correlator")
        try:
            correlator.correlate(vt_session, TaskMonitor.DUMMY)
            vt_session.endTransaction(txn, True)
        except Exception:
            vt_session.endTransaction(txn, False)
            raise

        logger.info("BSim correlator completed successfully")
        return True
    except ImportError:
        logger.info("BSim correlator not available (VersionTrackingBSim not loaded)")
        return False
    except Exception as e:
        logger.warning("BSim correlator failed: %s", e)
        return False


def _get_function_name_at(program, addr) -> str:
    """Get the function name at a given address, or '(none)' if no function."""
    fm = program.getFunctionManager()
    func = fm.getFunctionAt(addr)
    if func is None:
        func = fm.getFunctionContaining(addr)
    return str(func.getName()) if func else "(none)"


def _get_unmatched_functions(program, matched_addrs: set) -> list[dict]:
    """Get functions not in the matched address set."""
    fm = program.getFunctionManager()
    unmatched = []
    for func in fm.getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        addr_str = _fmt_address(func.getEntryPoint())
        if addr_str not in matched_addrs:
            unmatched.append({
                "name": str(func.getName()),
                "address": addr_str,
            })
    return unmatched


# ---------------------------------------------------------------------------
# match_function: find the best match for a specific function in another binary
# ---------------------------------------------------------------------------

def _handle_match_function(ctx, args: dict) -> dict:
    """Find matching functions for a specific function in another binary.

    Uses BSim (if available), exact-instruction, and other correlators to
    find candidate matches for a single function from source_binary in
    target_binary.
    """
    from ghidra.feature.vt.api.db import VTSessionDB
    from ghidra.util.task import TaskMonitor

    source_binary = args.get("source_binary", "")
    func_name = args.get("func", "")
    target_binary = args.get("target_binary", "")
    threshold = float(args.get("threshold", 0.0))

    if not source_binary or not func_name or not target_binary:
        raise ValueError(
            "Missing required arguments: source_binary, func, target_binary"
        )

    # Resolve the source function using the daemon's reference (for name lookup)
    from ghidra_rpc.server.tools.decompiler import _find_function
    pi_src_daemon = ctx.get_program(source_binary)
    src_func = _find_function(pi_src_daemon, func_name)
    src_func_name = str(src_func.getName())
    src_addr_str = _fmt_address(src_func.getEntryPoint())

    # Temporarily close and reopen for VT
    consumer = "ghidra-rpc-match"
    src_prog, dst_prog, src_name, dst_name, src_key, dst_key = \
        _open_vt_programs(ctx, source_binary, target_binary, consumer)

    session_name = f"ghidra-rpc-match-{func_name}"
    vt_session = VTSessionDB.createVTSession(
        session_name, src_prog, dst_prog, consumer
    )

    try:
        src_addr_set = src_prog.getMemory().getLoadedAndInitializedAddressSet()
        dst_addr_set = dst_prog.getMemory().getLoadedAndInitializedAddressSet()

        # Run correlators and collect candidates
        candidates = []

        for factory_class in _CORRELATOR_FACTORIES:
            _run_correlator_and_collect(
                vt_session, src_prog, dst_prog, src_addr_set, dst_addr_set,
                src_addr_str, candidates, factory_class,
            )

        # Try BSim
        try:
            from ghidra.feature.vt.api import BSimProgramCorrelatorFactory
            _run_correlator_and_collect(
                vt_session, src_prog, dst_prog, src_addr_set, dst_addr_set,
                src_addr_str, candidates,
                None,
                factory_instance=BSimProgramCorrelatorFactory(),
            )
        except ImportError:
            pass

        # Deduplicate by destination address, keep highest similarity
        by_dst = {}
        for c in candidates:
            key = c["address"]
            if key not in by_dst or c["similarity"] > by_dst[key]["similarity"]:
                by_dst[key] = c

        result_candidates = sorted(by_dst.values(), key=lambda x: -x["similarity"])

        if threshold > 0:
            result_candidates = [c for c in result_candidates if c["similarity"] >= threshold]

        return {
            "source": {
                "name": src_func_name,
                "address": src_addr_str,
            },
            "candidates": result_candidates,
            "count": len(result_candidates),
        }
    finally:
        vt_session.release(consumer)
        src_prog.release(consumer)
        dst_prog.release(consumer)
        _restore_daemon_programs(ctx, src_name, dst_name, src_key, dst_key)


def _run_correlator_and_collect(
    vt_session, src_prog, dst_prog, src_addr_set, dst_addr_set,
    src_addr_str, candidates, factory_class_name, *, factory_instance=None,
):
    """Run a single correlator and collect matches for the source address."""
    from ghidra.util.task import TaskMonitor

    try:
        if factory_instance is None:
            parts = factory_class_name.rsplit(".", 1)
            mod = __import__(parts[0], fromlist=[parts[1]])
            cls = getattr(mod, parts[1])
            factory_instance = cls()

        options = factory_instance.createDefaultOptions()
        correlator = factory_instance.createCorrelator(
            src_prog, src_addr_set, dst_prog, dst_addr_set, options
        )

        txn = vt_session.startTransaction(f"correlator-{factory_instance.getName()}")
        try:
            match_set = correlator.correlate(vt_session, TaskMonitor.DUMMY)
            vt_session.endTransaction(txn, True)
        except Exception:
            vt_session.endTransaction(txn, False)
            raise

        correlator_name = str(factory_instance.getName())
        for match in match_set.getMatches():
            if _fmt_address(match.getSourceAddress()) == src_addr_str:
                dst_addr = match.getDestinationAddress()
                dst_func_name = _get_function_name_at(dst_prog, dst_addr)
                similarity = match.getSimilarityScore().getScore()
                confidence = match.getConfidenceScore().getScore()
                candidates.append({
                    "name": dst_func_name,
                    "address": _fmt_address(dst_addr),
                    "similarity": round(similarity, 4),
                    "confidence": round(confidence, 4),
                    "correlator": correlator_name,
                })
    except Exception as e:
        logger.debug("Correlator %s failed: %s",
                     factory_class_name or factory_instance, e)


# ---------------------------------------------------------------------------
# decompile_all: bulk decompile all functions in a binary
# ---------------------------------------------------------------------------

def _handle_decompile_all(ctx, args: dict) -> dict:
    """Decompile all functions in a binary and return their pseudo-C code.

    Returns a list of {name, address, signature, c_code} dicts, one per
    function.  Skips external and thunk functions.
    """
    from ghidra.util.task import TaskMonitor

    binary = args.get("binary", "")
    timeout = int(args.get("timeout", 60))
    limit = args.get("limit")
    if limit is not None:
        limit = int(limit)
    offset = int(args.get("offset", 0))

    if not binary:
        raise ValueError("Missing required argument: binary")

    pi = ctx.get_program(binary)
    fm = pi.program.getFunctionManager()

    # Collect non-external, non-thunk functions
    all_funcs = []
    for func in fm.getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        all_funcs.append(func)

    total = len(all_funcs)

    # Apply offset/limit
    funcs_to_decompile = all_funcs[offset:]
    if limit is not None:
        funcs_to_decompile = funcs_to_decompile[:limit]

    results = []
    errors = 0

    for func in funcs_to_decompile:
        try:
            with pi.decompiler_pool.acquire() as decompiler:
                result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)

            error_msg = result.getErrorMessage()
            if error_msg and error_msg.strip():
                results.append({
                    "name": str(func.getName()),
                    "address": _fmt_address(func.getEntryPoint()),
                    "signature": str(func.getSignature()),
                    "c_code": None,
                    "error": str(error_msg),
                })
                errors += 1
                continue

            decompiled = result.getDecompiledFunction()
            c_code = str(decompiled.getC()) if decompiled else ""

            results.append({
                "name": str(func.getName()),
                "address": _fmt_address(func.getEntryPoint()),
                "signature": str(decompiled.getSignature()) if decompiled else str(func.getSignature()),
                "c_code": c_code,
            })
        except Exception as e:
            results.append({
                "name": str(func.getName()),
                "address": _fmt_address(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "c_code": None,
                "error": str(e),
            })
            errors += 1

    return {
        "functions": results,
        "count": len(results),
        "total": total,
        "offset": offset,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# function_diff: decompile two functions and produce a unified diff
# ---------------------------------------------------------------------------

def _handle_function_diff(ctx, args: dict) -> dict:
    """Diff two functions from two binaries.

    Supports two modes:
    - "decompile" (default): decompile to pseudo-C, normalise auto-generated
      variable/address names, then unified diff.  Best for semantic analysis.
    - "disassembly": extract instruction mnemonics+operands, normalise
      absolute addresses in branch/call targets and data references, then
      unified diff.  Best for byte-level or obfuscated-code analysis.
    """
    import difflib
    import re

    binary1 = args.get("binary1", "")
    func1 = args.get("func1", "")
    binary2 = args.get("binary2", "")
    func2 = args.get("func2", "")
    timeout = int(args.get("timeout", 60))
    mode = args.get("mode", "decompile")

    if mode not in ("decompile", "disassembly"):
        raise ValueError(
            f"Invalid mode '{mode}'. Use 'decompile' or 'disassembly'."
        )

    if not binary1 or not func1 or not binary2 or not func2:
        raise ValueError(
            "Missing required arguments: binary1, func1, binary2, func2"
        )

    from ghidra_rpc.server.tools.decompiler import _find_function

    pi1 = ctx.get_program(binary1)
    pi2 = ctx.get_program(binary2)

    f1 = _find_function(pi1, func1)
    f2 = _find_function(pi2, func2)

    if mode == "decompile":
        code1, code2 = _diff_decompile(pi1, f1, pi2, f2, timeout)
        normalise = _normalise_decompiled
    else:
        code1 = _disassemble_function(pi1, f1)
        code2 = _disassemble_function(pi2, f2)
        normalise = _normalise_disassembly

    norm1 = normalise(code1)
    norm2 = normalise(code2)

    lines1 = norm1.splitlines(keepends=True)
    lines2 = norm2.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        lines1, lines2,
        fromfile=f"{binary1}::{func1}",
        tofile=f"{binary2}::{func2}",
        lineterm="",
    ))

    is_identical = len(diff) == 0

    return {
        "binary1": binary1,
        "func1": str(f1.getName()),
        "func1_address": _fmt_address(f1.getEntryPoint()),
        "binary2": binary2,
        "func2": str(f2.getName()),
        "func2_address": _fmt_address(f2.getEntryPoint()),
        "mode": mode,
        "is_identical": is_identical,
        "diff": "\n".join(diff) if diff else "(functions are identical after normalisation)",
        "raw_code1": code1,
        "raw_code2": code2,
    }


def _diff_decompile(pi1, f1, pi2, f2, timeout: int):
    """Decompile both functions and return (code1, code2)."""
    from ghidra.util.task import TaskMonitor

    def _decompile(pi, func):
        with pi.decompiler_pool.acquire() as decomp:
            result = decomp.decompileFunction(func, timeout, TaskMonitor.DUMMY)
        error_msg = result.getErrorMessage()
        if error_msg and error_msg.strip():
            raise RuntimeError(
                f"Decompilation failed for {func.getName()}: {error_msg}"
            )
        df = result.getDecompiledFunction()
        return str(df.getC()) if df else ""

    return _decompile(pi1, f1), _decompile(pi2, f2)


def _disassemble_function(pi, func) -> str:
    """Disassemble all instructions in a function's body.

    Returns a multi-line string of ``MNEMONIC  OPERANDS`` lines (no
    addresses, no raw bytes — those change between versions and are noise).
    """
    listing = pi.program.getListing()
    body = func.getBody()
    lines = []
    for instr in listing.getInstructions(body, True):
        mnemonic = str(instr.getMnemonicString())
        ops = []
        for op_idx in range(instr.getNumOperands()):
            try:
                ops.append(str(instr.getDefaultOperandRepresentation(op_idx)))
            except Exception:
                pass
        operands = ", ".join(ops)
        lines.append(f"{mnemonic:<8} {operands}" if operands else mnemonic)
    return "\n".join(lines)


def _normalise_decompiled(code: str) -> str:
    """Normalise auto-generated names in decompiled pseudo-C.

    Replaces Ghidra's auto-generated identifiers so that pure relocation
    differences (functions or data that moved in memory between builds)
    don't produce false-positive diff lines.  User-assigned names are
    preserved.
    """
    import re
    code = re.sub(r'\blocal_[0-9a-fA-F]+\b', 'local_X', code)
    code = re.sub(r'\bparam_[0-9]+\b', 'param_X', code)
    code = re.sub(r'\b[a-zA-Z]Var[0-9]+\b', 'xVarN', code)
    # Auto-named functions/data/labels embed the address in their name and
    # differ between builds even when the code is semantically identical.
    code = re.sub(r'\bFUN_[0-9a-fA-F]+\b', 'FUN_ADDR', code)
    code = re.sub(r'\bDAT_[0-9a-fA-F]+\b', 'DAT_ADDR', code)
    code = re.sub(r'\bLAB_[0-9a-fA-F]+\b', 'LAB_ADDR', code)
    code = re.sub(r'\b0x[0-9a-fA-F]{6,}\b', '0xADDR', code)
    return code


def _normalise_disassembly(code: str) -> str:
    """Normalise absolute addresses in disassembly output.

    Replaces absolute hex addresses (branch/call targets, data references)
    with a placeholder so that address-layout differences between two
    builds don't create false-positive diff lines.
    """
    import re
    # Replace 0xHEX and bare hex tokens >= 6 digits that look like addresses.
    # Keep small immediates (e.g. 0x1, 0xff) intact — they're constants.
    code = re.sub(r'\b0x[0-9a-fA-F]{6,}\b', '0xADDR', code)
    code = re.sub(r'\b[0-9a-fA-F]{6,}\b', 'ADDR', code)
    return code


register_handler("version_track", _handle_version_track)
register_handler("match_function", _handle_match_function)
register_handler("decompile_all", _handle_decompile_all)
register_handler("function_diff", _handle_function_diff)
