"""C++ reverse-engineering helpers: vtable listing (and, later, RTTI).

These build on the pointer-reading primitive in ``memory.py`` and the address
resolution in ``xrefs.py`` to turn the mechanical parts of C++ analysis
(walking a vtable, resolving slots to methods) into single commands.
"""

from __future__ import annotations

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.memory import resolve_target_name
from ghidra_rpc.server.tools.xrefs import _resolve_address

# Hard cap on auto-terminated vtable walks (defensive; real vtables are small).
_VTABLE_HARD_CAP = 4096


def _has_vtable_symbol(symbol_table, addr) -> bool:
    """True if any symbol at *addr* looks like a vftable/vtable boundary."""
    for sym in symbol_table.getSymbols(addr):
        name = str(sym.getName()).lower()
        if "vftable" in name or "vtable" in name:
            return True
    return False


def _handle_list_vtable(ctx, args: dict) -> dict:
    """List the slots of a C++ virtual function table.

    Reads pointer-sized slots starting at the vtable address and resolves each
    to its target function/symbol.  This mechanises the vtable walk that would
    otherwise be done by hand with ``read-bytes`` + struct-unpack.

    Termination (belt-and-suspenders, since a reliable ``vftable`` boundary
    symbol may not exist):
      1. If ``count`` is given, read exactly that many slots
         (``stopped_reason: "count"``).
      2. Otherwise stop at the next slot that carries a ``vftable``/``vtable``
         symbol (``"next_vtable_symbol"``) — the authoritative boundary.
      3. Otherwise stop at the first slot whose value is not a function pointer
         (``"non_function_pointer"``) or is unreadable (``"unreadable"``).
      4. Otherwise stop at a hard cap (``"cap"``).

    Args (in ``args`` dict):
        binary       -- program name / key
        address      -- vtable address (hex) OR a symbol name (e.g. a
                        ``...::vftable`` label)
        count        -- optional fixed slot count (overrides auto-termination)
        pointer_size -- override pointer width in bytes; default = program's

    Returns a dict with:
        vtable_address, symbol, count, pointer_size, stopped_reason
        slots -- list of {index, offset, slot_address, target_address,
                 target_name, target_kind}
    """
    binary   = args.get("binary", "")
    target   = args.get("address", args.get("symbol", ""))
    count    = args.get("count")
    ptr_size = args.get("pointer_size")

    if not target:
        raise ValueError("Missing required argument: address (or symbol)")

    pi      = ctx.get_program(binary)
    program = pi.program

    # Resolve the start: hex address, function, or (typically) a data symbol.
    start_addr = _resolve_address(pi, str(target))

    if ptr_size is None:
        ptr_size = int(program.getDefaultPointerSize())
    else:
        ptr_size = int(ptr_size)
        if ptr_size not in (1, 2, 4, 8):
            raise ValueError("pointer_size must be one of 1, 2, 4, 8")

    big_endian    = bool(program.getLanguage().isBigEndian())
    byteorder     = "big" if big_endian else "little"
    st            = program.getSymbolTable()
    fm            = program.getFunctionManager()
    memory        = program.getMemory()
    default_space = program.getAddressFactory().getDefaultAddressSpace()

    # The symbol sitting on the vtable head (informational).
    head_sym = st.getPrimarySymbol(start_addr)
    head_name = str(head_sym.getName()) if head_sym is not None else None

    auto = count is None
    max_slots = _VTABLE_HARD_CAP if auto else int(count)
    if not auto and int(count) < 1:
        raise ValueError("count must be >= 1")

    slots = []
    stopped_reason = "count" if not auto else "cap"
    for i in range(max_slots):
        slot_addr = start_addr.add(i * ptr_size)

        # Boundary: a vftable symbol on a later slot ends this table.
        if auto and i > 0 and _has_vtable_symbol(st, slot_addr):
            stopped_reason = "next_vtable_symbol"
            break

        try:
            raw = pi.flat_api.getBytes(slot_addr, ptr_size)
        except Exception:
            stopped_reason = "unreadable"
            break
        value = int.from_bytes(bytes(b & 0xFF for b in raw), byteorder)

        tgt = None
        if value != 0:
            try:
                cand = default_space.getAddress(value)
            except Exception:
                cand = None
            if cand is not None and memory.contains(cand):
                tgt = cand

        func = fm.getFunctionAt(tgt) if tgt is not None else None

        # Auto-terminate at the first slot that isn't a function pointer.
        if auto and func is None:
            stopped_reason = "non_function_pointer"
            break

        if func is not None:
            name, kind = str(func.getName()), "function"
        elif tgt is not None:
            name, kind = resolve_target_name(program, tgt)
        else:
            name, kind = None, None

        slots.append({
            "index":          i,
            "offset":         i * ptr_size,
            "slot_address":   _fmt_address(slot_addr),
            "target_address": _fmt_address(tgt) if tgt is not None else None,
            "target_name":    name,
            "target_kind":    kind,
        })

    return {
        "vtable_address": _fmt_address(start_addr),
        "symbol":         head_name,
        "count":          len(slots),
        "pointer_size":   ptr_size,
        "stopped_reason": stopped_reason,
        "slots":          slots,
    }


register_handler("list_vtable", _handle_list_vtable)
