"""Processor context tools: read and write ISA register values at addresses.

Used to fix Ghidra mis-classification of instruction streams, e.g. setting
TMode=1 on ARM Thumb regions that were not identified as Thumb during
auto-analysis.

Key use-case (ARM firmware):
    get-processor-context binary 0x03288100 --register TMode
    set-processor-context binary 0x03288100 TMode 1 --end 0x032883ff

After setting the context, re-disassemble the range and re-create the
function at the correct (even) entry address.
"""

from __future__ import annotations

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler


def _handle_get_processor_context(ctx, args: dict) -> dict:
    """Return ISA context register values at an address.

    Without ``--register``, returns all context registers with non-default
    values (or all registers that are tracked by the program context).
    With ``--register REG``, returns only that register.

    Args (in ``args`` dict):
        binary   -- program name / key
        address  -- hex address to inspect
        register -- optional: restrict output to a single register name

    Returns a dict with:
        address   -- canonical address
        registers -- {register_name: integer_value_or_null}
    """
    binary          = args.get("binary", "")
    address_str     = args.get("address", "")
    register_filter = args.get("register", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    from ghidra_rpc.server.context import _parse_address

    pi   = ctx.get_program(binary)
    addr = _parse_address(pi.program, address_str)

    language        = pi.program.getLanguage()
    program_context = pi.program.getProgramContext()

    def _reg_int(reg, addr):
        """Return integer value of reg at addr, or None if unset.

        ProgramContext.getValue() returns java.math.BigInteger (or None when
        unset).  BigInteger is a Java object; JPype does not expose __int__,
        so use int(str(val)) for reliable conversion.

        Fallback: context registers for auto-analyzed code (e.g. TMode set by
        the ARM disassembler) live in defaultRegisterValueMap, which getValue()
        does NOT read.  getDisassemblyContext() combines both maps.
        """
        try:
            val = program_context.getValue(reg, addr, False)
            if val is not None:
                return int(str(val))
            # Fallback: try the combined disassembly context (both maps).
            ctx_rv = program_context.getDisassemblyContext(addr)
            if ctx_rv is None:
                return None
            sub_rv = ctx_rv.getRegisterValue(reg)
            if sub_rv is None or not sub_rv.hasValue():
                return None
            return int(str(sub_rv.getUnsignedValue()))
        except Exception:
            return None

    if register_filter:
        # Try exact match, then case-insensitive match.
        reg = language.getRegister(register_filter)
        if reg is None:
            for r in program_context.getRegisters():
                if str(r.getName()).lower() == register_filter.lower():
                    reg = r
                    break
        if reg is None:
            available = sorted(str(r.getName()) for r in program_context.getRegisters())
            raise ValueError(
                f"Unknown register '{register_filter}'. "
                f"Available context registers: {available}"
            )
        registers = {str(reg.getName()): _reg_int(reg, addr)}
    else:
        registers = {}
        for reg in program_context.getRegisters():
            val = _reg_int(reg, addr)
            registers[str(reg.getName())] = val

    return {
        "address":   _fmt_address(addr),
        "registers": registers,
    }


def _handle_set_processor_context(ctx, args: dict) -> dict:
    """Set an ISA context register value over an address range.

    This is the primary fix for ARM Thumb mis-classification: after
    clearing a data range, call ``set-processor-context`` with
    ``TMode 1`` before re-disassembling so the SLEIGH disassembler
    decodes the bytes as Thumb-2 rather than ARM.

    Args (in ``args`` dict):
        binary   -- program name / key
        address  -- start address (hex)
        register -- context register name (e.g. ``TMode``)
        value    -- integer value (0 or 1 for TMode)
        end      -- optional end address (inclusive); defaults to ``address``

    Returns a dict with:
        address  -- start address
        end      -- end address
        register -- register name
        value    -- the value that was requested
        verified -- whether read-back at the start address matches
    """
    binary        = args.get("binary", "")
    address_str   = args.get("address", "")
    end_str       = args.get("end", "")
    register_name = args.get("register", "")
    value         = args.get("value")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not register_name:
        raise ValueError("Missing required argument: register")
    if value is None:
        raise ValueError("Missing required argument: value")

    pi = ctx.get_program(binary)

    def do_set():
        from ghidra_rpc.server.context import _parse_address
        from ghidra_rpc.server.tools.modifications import ghidra_transaction

        addr     = _parse_address(pi.program, address_str)
        end_addr = _parse_address(pi.program, end_str) if end_str else addr

        language = pi.program.getLanguage()
        reg      = language.getRegister(register_name)
        if reg is None:
            program_context = pi.program.getProgramContext()
            for r in program_context.getRegisters():
                if str(r.getName()).lower() == register_name.lower():
                    reg = r
                    break
        if reg is None:
            program_context = pi.program.getProgramContext()
            available = sorted(str(r.getName()) for r in program_context.getRegisters())
            raise ValueError(
                f"Unknown register '{register_name}'. "
                f"Available context registers: {available}"
            )

        int_value       = int(value)
        program_context = pi.program.getProgramContext()

        from java.math import BigInteger  # type: ignore
        bi_val = BigInteger.valueOf(int_value)

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: set {register_name}={int_value} @ {addr}-{end_addr}",
        ):
            program_context.setValue(reg, addr, end_addr, bi_val)
            # Flush the processor-context write cache *inside* the transaction
            # and read back *before* endTransaction calls invalidateRegisterStores()
            # which clears registerValueMap.  Any getValue() after endTransaction
            # returns null even if the DB was written, because the store is gone.
            program_context.flushProcessorContextWriteCache()
            actual = None
            try:
                val_back = program_context.getValue(reg, addr, False)
                # BigInteger is a Java object; JPype does not expose __int__,
                # so use int(str(...)) for reliable conversion.
                actual = int(str(val_back)) if val_back is not None else None
            except Exception:
                pass

        return {
            "address":  _fmt_address(addr),
            "end":      _fmt_address(end_addr),
            "register": register_name,
            "value":    int_value,
            "verified": actual == int_value,
        }

    from ghidra_rpc.server.tools.modifications import _maybe_swing
    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


register_handler("get_processor_context", _handle_get_processor_context)
register_handler("set_processor_context", _handle_set_processor_context)
