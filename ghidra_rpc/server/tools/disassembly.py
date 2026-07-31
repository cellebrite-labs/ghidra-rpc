"""Disassembly and assembly tools.

Disassembly: raw instruction listing for an address range.
Assembly: assemble instruction text at an address using Ghidra's SLEIGH assembler.
"""

from __future__ import annotations

from ghidra_rpc.server.main import register_handler

_DEFAULT_COUNT = 20
_MAX_COUNT = 1000


def _handle_disassemble(ctx, args: dict) -> dict:
    """Return an assembly listing for a range of instructions.

    Args (in ``args`` dict):
        binary       -- program name / key
        address      -- start address (hex, e.g. ``0x101159`` or ``101159``)
        count        -- number of instructions to list (default 20, max 1000)
        verbose_list -- if true, include detailed instructions list array in output (default false)

    Returns a dict with:
        address      -- canonical start address
        count        -- number of instructions returned
        listing      -- formatted human-readable assembly listing string
        instructions -- (optional, only when verbose_list is true) list of dicts, one per instruction:
                          address   -- instruction address
                          bytes     -- hex bytes (e.g. ``"4889e5"``)
                          mnemonic  -- opcode mnemonic (e.g. ``"MOV"``)
                          operands  -- operand string  (e.g. ``"RBP,RSP"``)
                          length    -- byte length of instruction
                          comment   -- EOL comment if set, else null
    """
    from ghidra_rpc.server.context import _parse_address

    binary       = args.get("binary", "")
    address_str  = args.get("address", "")
    count        = int(args.get("count", _DEFAULT_COUNT))
    verbose_list = bool(args.get("verbose_list", False))

    if not address_str:
        raise ValueError("Missing required argument: address")
    if count < 1:
        raise ValueError("count must be >= 1")
    if count > _MAX_COUNT:
        raise ValueError(f"count must be <= {_MAX_COUNT} (requested {count})")

    pi      = ctx.get_program(binary)
    addr    = _parse_address(pi.program, address_str)
    listing = pi.program.getListing()

    # Start at the instruction at addr; fall back to the next one if addr is
    # mid-instruction or points to data.  Track whether we actually started
    # at the requested address so we can warn the caller.
    instr        = listing.getInstructionAt(addr)
    actual_start = None  # set when we fall back to a different address
    if instr is None:
        instr = listing.getInstructionAfter(addr)
        if instr is not None:
            fallback_addr = str(instr.getAddress())
            if fallback_addr != str(addr):
                actual_start = fallback_addr
    if instr is None:
        # Give a more helpful message when the address is in a data section.
        data = listing.getDataAt(addr)
        if data is None:
            data = listing.getDataContaining(addr)
        if data is not None:
            dt_name = str(data.getDataType().getName())
            raise ValueError(
                f"Address {address_str} is in a data section "
                f"(type: {dt_name}), not executable code. "
                f"Use 'read-bytes' to inspect raw bytes at this address."
            )
        raise ValueError(
            f"No instruction found at or after {address_str}. "
            f"The address may be in an unmapped region or a data section."
        )

    try:
        from ghidra.program.model.listing import CommentType
        _eol = CommentType.EOL
    except Exception:
        _eol = None  # fall back gracefully; comment will be None

    instructions = []
    for _ in range(count):
        if instr is None:
            break

        # Raw bytes
        raw = bytes(b & 0xFF for b in instr.getBytes())

        # Operands: join all operand representations with ", "
        # Resolve equates (named scalar constants) for each operand index.
        ops = []
        equate_table = pi.program.getEquateTable()
        for op_idx in range(instr.getNumOperands()):
            try:
                op_repr = str(instr.getDefaultOperandRepresentation(op_idx))
                # Check for equates applied to this operand.
                eqs = list(equate_table.getEquates(instr.getAddress(), op_idx))
                if eqs:
                    op_repr = str(eqs[0].getName())
                ops.append(op_repr)
            except Exception:
                pass
        operand_str = ",".join(ops)

        # EOL comment (new API: getComment(CommentType))
        comment = None
        if _eol is not None:
            try:
                c = instr.getComment(_eol)
                if c:
                    comment = str(c)
            except Exception:
                pass

        instructions.append({
            "address":  str(instr.getAddress()),
            "bytes":    raw.hex(),
            "mnemonic": str(instr.getMnemonicString()),
            "operands": operand_str,
            "length":   instr.getLength(),
            "comment":  comment,
        })

        instr = instr.getNext()

    result = {
        "address": str(addr),
        "count":   len(instructions),
        "listing": _format_listing(instructions),
    }
    if verbose_list:
        result["instructions"] = instructions
    if actual_start:
        result["warning"] = (
            f"No instruction at {address_str}; disassembly started from the "
            f"next available instruction at {actual_start}."
        )
    return result


def _format_listing(instructions: list) -> str:
    """Format instructions as a human-readable assembly listing.

    Example::

        00101159  55                PUSH    RBP
        0010115a  4889e5            MOV     RBP,RSP
        0010115d  53                PUSH    RBX
    """
    if not instructions:
        return ""

    # Determine column widths from actual data
    max_bytes_len = max(len(i["bytes"]) for i in instructions)
    max_bytes_len = max(max_bytes_len, 2)  # at least 1 byte column
    # Display bytes as space-separated pairs: "48 89 e5" (3 bytes → 8 chars)
    bytes_col = max(max_bytes_len // 2 * 3 - 1, 8)

    lines = []
    for i in instructions:
        addr    = i["address"]
        raw     = i["bytes"]
        mnem    = i["mnemonic"]
        ops     = i["operands"]
        comment = i["comment"]

        # Format bytes as space-separated hex pairs
        hex_pairs = " ".join(raw[j:j+2] for j in range(0, len(raw), 2))
        hex_col   = hex_pairs.ljust(bytes_col)

        instr_str = f"{mnem:<8} {ops}" if ops else mnem
        line = f"{addr}  {hex_col}  {instr_str}"
        if comment:
            line += f"  ; {comment}"
        lines.append(line)

    return "\n".join(lines)


register_handler("disassemble", _handle_disassemble)


def _handle_assemble(ctx, args: dict) -> dict:
    """Assemble instruction text at an address using Ghidra's SLEIGH assembler.

    Args (in ``args`` dict):
        binary       -- program name / key
        address      -- hex address where assembly starts
        instructions -- list of instruction strings (e.g. ["MOV EAX, 0", "NOP", "RET"])

    Returns a dict with:
        address      -- canonical start address
        bytes_written -- total bytes written
        hex          -- hex string of assembled bytes
        instructions -- list of resulting instructions (same format as disassemble)
    """
    from ghidra_rpc.server.context import _parse_address
    from ghidra_rpc.server.tools.modifications import (
        _maybe_swing,
        ghidra_transaction,
    )

    binary       = args.get("binary", "")
    address_str  = args.get("address", "")
    instr_lines  = args.get("instructions", [])

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not instr_lines:
        raise ValueError("Missing required argument: instructions (list of asm strings)")
    if not isinstance(instr_lines, (list, tuple)):
        raise ValueError("'instructions' must be a list of strings")

    pi = ctx.get_program(binary)
    addr = _parse_address(pi.program, address_str)

    def do_assemble():
        from ghidra.app.plugin.assembler import Assemblers

        asm = Assemblers.getAssembler(pi.program)

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: assemble {len(instr_lines)} instr @ {addr}"
        ):
            # assemble() takes Address and varargs of String lines.
            # It returns an InstructionBlock; errors raise
            # AssemblySyntaxException or AssemblySemanticException.
            try:
                result_block = asm.assemble(addr, *instr_lines)
            except Exception as e:
                error_msg = str(e)
                # Surface assembly errors clearly
                raise ValueError(
                    f"Assembly failed at {addr}: {error_msg}"
                ) from e

        # Read back the assembled instructions
        listing = pi.program.getListing()
        instructions = []
        current = listing.getInstructionAt(addr)
        total_bytes = 0
        all_hex = []

        for _ in range(len(instr_lines) + 10):  # generous limit
            if current is None:
                break
            # Stop if we've moved past the assembled region
            if instructions and total_bytes > 0:
                # Check if this instruction was part of our assembly
                pass

            raw = bytes(b & 0xFF for b in current.getBytes())
            all_hex.append(raw.hex())

            ops = []
            for op_idx in range(current.getNumOperands()):
                try:
                    ops.append(str(current.getDefaultOperandRepresentation(op_idx)))
                except Exception:
                    pass

            instructions.append({
                "address":  str(current.getAddress()),
                "bytes":    raw.hex(),
                "mnemonic": str(current.getMnemonicString()),
                "operands": ",".join(ops),
                "length":   current.getLength(),
            })
            total_bytes += current.getLength()
            current = current.getNext()

            # Once we've got at least as many instructions as we assembled, stop
            if len(instructions) >= len(instr_lines):
                break

        pi.decompiler_pool.invalidate_all()

        return {
            "address":       str(addr),
            "bytes_written": total_bytes,
            "hex":           "".join(all_hex),
            "instructions":  instructions,
        }

    result = _maybe_swing(ctx, do_assemble)
    ctx.save_program(pi)
    return result


register_handler("assemble", _handle_assemble)
