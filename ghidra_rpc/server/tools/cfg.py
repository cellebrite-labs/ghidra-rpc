"""Control-flow graph and P-code tools.

Provides commands for inspecting function-level control flow and
Ghidra's intermediate representation:
  basic_blocks — basic block decomposition of a function (CFG)
  pcode        — raw or high (SSA) P-code for a function
"""

from __future__ import annotations

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.decompiler import _find_function


def _handle_basic_blocks(ctx, args: dict) -> dict:
    """Return the basic blocks (control-flow graph) of a function.

    Uses Ghidra's ``BasicBlockModel`` to decompose the function body into
    basic blocks without requiring a full decompilation pass.  This is
    faster and works even for functions the decompiler struggles with.

    Each block reports its entry address, address range, instruction count,
    and successor edges (with edge type: normal / conditional / unconditional
    / call / etc.).

    Args (in ``args`` dict):
        binary -- program name / key
        func   -- function name or hex address
        limit  -- max blocks to return (default 500, max 5000)

    Returns a dict with:
        name       -- function name
        address    -- function entry point
        blocks     -- list of basic block dicts:
                        start        -- block start address
                        end          -- block end address (inclusive, last byte)
                        size         -- byte size
                        instructions -- number of instructions in block
                        successors   -- list of {address, type} edges
                        predecessors -- list of predecessor start addresses
        num_blocks -- total basic blocks in function
        edges      -- total edge count
    """
    binary    = args.get("binary", "")
    func_name = args.get("func", "")
    limit     = min(int(args.get("limit", 500)), 5000)

    if not func_name:
        raise ValueError("Missing required argument: func")

    pi = ctx.get_program(binary)
    func = _find_function(pi, func_name)
    body = func.getBody()

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    model = BasicBlockModel(pi.program, True)  # True = follow calls is irrelevant for basic blocks

    # Iterate blocks within the function body
    block_iter = model.getCodeBlocksContaining(body, TaskMonitor.DUMMY)

    blocks = []
    total_edges = 0

    while block_iter.hasNext():
        cb = block_iter.next()
        start = cb.getMinAddress()
        end = cb.getMaxAddress()

        # Count instructions in this block
        listing = pi.program.getListing()
        instr_count = 0
        instr = listing.getInstructionAt(start)
        while instr is not None and body.contains(instr.getAddress()) and \
              instr.getAddress().compareTo(end) <= 0:
            instr_count += 1
            instr = instr.getNext()

        # Successor edges
        successors = []
        dest_iter = cb.getDestinations(TaskMonitor.DUMMY)
        while dest_iter.hasNext():
            ref = dest_iter.next()
            dest_block = ref.getDestinationBlock()
            flow_type = ref.getFlowType()
            edge = {
                "address": _fmt_address(dest_block.getMinAddress()),
                "type":    str(flow_type),
            }
            successors.append(edge)
            total_edges += 1

        # Predecessor addresses
        predecessors = []
        src_iter = cb.getSources(TaskMonitor.DUMMY)
        while src_iter.hasNext():
            ref = src_iter.next()
            src_block = ref.getSourceBlock()
            predecessors.append(_fmt_address(src_block.getMinAddress()))

        blocks.append({
            "start":        _fmt_address(start),
            "end":          _fmt_address(end),
            "size":         int(cb.getNumAddresses()),
            "instructions": instr_count,
            "successors":   successors,
            "predecessors": predecessors,
        })

        if len(blocks) >= limit:
            break

    return {
        "name":       str(func.getName()),
        "address":    _fmt_address(func.getEntryPoint()),
        "blocks":     blocks,
        "num_blocks": len(blocks),
        "edges":      total_edges,
    }


def _handle_pcode(ctx, args: dict) -> dict:
    """Return P-code (Ghidra's intermediate representation) for a function.

    Two modes:
    - **Raw P-code** (default): listing-level P-code from each instruction.
      Fast, no decompiler needed. Good for tracing individual instruction
      semantics.
    - **High P-code** (``high=True``): SSA-form P-code from the decompiler.
      Requires a decompilation pass. Shows optimized data flow with resolved
      variable names. Ideal for precise taint analysis and data-flow tracing.

    Args (in ``args`` dict):
        binary  -- program name / key
        func    -- function name or hex address
        high    -- if True, return high (SSA) P-code from the decompiler
        timeout -- decompiler timeout in seconds (only for high P-code, default 60)
        limit   -- max P-code ops to return (default 1000, max 10000)

    Returns a dict with:
        name    -- function name
        address -- function entry point
        mode    -- "raw" or "high"
        ops     -- list of P-code operation dicts:
                     For raw: {address, seq, opcode, output, inputs}
                     For high: {seq, opcode, output, inputs}
                   where output and each input is {name, size, [address]}
                   or null for void
        count   -- number of ops returned
        truncated -- whether output was truncated by limit
    """
    binary    = args.get("binary", "")
    func_name = args.get("func", "")
    high      = bool(args.get("high", False))
    timeout   = int(args.get("timeout", 60))
    limit     = min(int(args.get("limit", 1000)), 10000)

    if not func_name:
        raise ValueError("Missing required argument: func")

    pi = ctx.get_program(binary)
    func = _find_function(pi, func_name)

    if high:
        return _get_high_pcode(pi, func, timeout, limit)
    else:
        return _get_raw_pcode(pi, func, limit)


def _format_varnode(vn) -> dict | None:
    """Format a Varnode as a serializable dict."""
    if vn is None:
        return None
    result = {
        "space": str(vn.getAddress().getAddressSpace().getName()),
        "offset": _fmt_address(vn.getAddress()),
        "size": vn.getSize(),
    }
    return result


def _format_high_varnode(vn) -> dict | None:
    """Format a high-level Varnode (from High P-code) with variable name."""
    if vn is None:
        return None
    result = {
        "offset": _fmt_address(vn.getAddress()),
        "size":   vn.getSize(),
    }
    high = vn.getHigh()
    if high is not None:
        result["name"] = str(high.getName())
        try:
            result["data_type"] = str(high.getDataType().getName())
        except Exception:
            pass
    return result


def _get_raw_pcode(pi, func, limit: int) -> dict:
    """Get raw (listing-level) P-code for all instructions in the function."""
    body = func.getBody()
    listing = pi.program.getListing()

    ops = []
    truncated = False

    for instr in listing.getInstructions(body, True):
        pcode_ops = instr.getPcode()
        for i, op in enumerate(pcode_ops):
            if len(ops) >= limit:
                truncated = True
                break
            entry = {
                "address": _fmt_address(instr.getAddress()),
                "seq":     i,
                "opcode":  str(op.getMnemonic()),
                "output":  _format_varnode(op.getOutput()),
                "inputs":  [_format_varnode(inp) for inp in op.getInputs()],
            }
            ops.append(entry)
        if truncated:
            break

    return {
        "name":      str(func.getName()),
        "address":   _fmt_address(func.getEntryPoint()),
        "mode":      "raw",
        "ops":       ops,
        "count":     len(ops),
        "truncated": truncated,
    }


def _get_high_pcode(pi, func, timeout: int, limit: int) -> dict:
    """Get high (SSA) P-code from the decompiler."""
    from ghidra.util.task import TaskMonitor

    with pi.decompiler_pool.acquire() as decompiler:
        result = decompiler.decompileFunction(func, timeout, TaskMonitor.DUMMY)

    err = result.getErrorMessage()
    if err and str(err).strip():
        raise RuntimeError(
            f"Decompilation failed for '{func.getName()}': {err}"
        )

    high_func = result.getHighFunction()
    if high_func is None:
        raise RuntimeError(
            f"Could not obtain high function for '{func.getName()}'"
        )

    ops = []
    truncated = False
    seq = 0

    pcode_iter = high_func.getPcodeOps()
    while pcode_iter.hasNext():
        op = pcode_iter.next()
        if len(ops) >= limit:
            truncated = True
            break
        entry = {
            "seq":    seq,
            "opcode": str(op.getMnemonic()),
            "output": _format_high_varnode(op.getOutput()),
            "inputs": [_format_high_varnode(inp) for inp in op.getInputs()],
        }
        # Include the address of the corresponding machine instruction
        try:
            entry["address"] = _fmt_address(op.getSeqnum().getTarget())
        except Exception:
            pass
        ops.append(entry)
        seq += 1

    return {
        "name":      str(func.getName()),
        "address":   _fmt_address(func.getEntryPoint()),
        "mode":      "high",
        "ops":       ops,
        "count":     len(ops),
        "truncated": truncated,
    }


register_handler("basic_blocks", _handle_basic_blocks)
register_handler("pcode", _handle_pcode)
