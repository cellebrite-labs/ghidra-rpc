"""Data-type authoring and bulk range tools.

Provides commands for creating composite types and operating on address ranges:
  create_struct        — build a StructureDataType in the program's DTM
  clear_data_range     — clear all code/data units in a byte range
  apply_data_type_range — stamp a type repeatedly across a range
  list_labels          — enumerate symbols/labels in an address range
"""

from __future__ import annotations

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.modifications import (
    _maybe_swing,
    _resolve_data_type,
    ghidra_transaction,
)


# ── create-struct ─────────────────────────────────────────────────────────────

def _coerce_offset(value):
    """Coerce a field offset to int, accepting decimal or ``0x`` hex strings."""
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _handle_create_struct(ctx, args: dict) -> dict:
    """Create a named structure data type in the program's data type manager.

    ``fields`` is a list of ``{"type": "<type_str>", "name": "<field_name>"}``
    dicts.  All the same type expressions accepted by ``set-data-type`` are
    valid for field types (``int``, ``char *``, ``MyStruct``, …).

    Two layout modes:
    - **Sequential** (default): fields are packed end-to-end in list order.
    - **Explicit offsets**: if any field carries an ``"offset"`` (int, or a
      decimal/``0x`` hex string) the struct is laid out at those byte offsets
      and the gaps between fields are auto-padded with undefined bytes — no
      manual ``pad`` fields needed.  In this mode *every* field must have an
      offset, and overlapping fields are rejected.

    Dynamic-length types (``string``, ``unicode``) are not allowed as struct
    fields; use a pointer (``char *``) instead.

    The struct is placed in the root category.

    ``if_not_exists`` — if True and the name already exists, return the
    existing struct without error (idempotent / safe-for-scripts).

    ``or_replace`` — if True and the name already exists, delete it first
    then create a fresh struct with the provided fields.
    """
    binary        = args.get("binary", "")
    struct_name   = args.get("name", "")
    fields        = args.get("fields", [])
    if_not_exists = bool(args.get("if_not_exists", False))
    or_replace    = bool(args.get("or_replace", False))

    if not struct_name:
        raise ValueError("Missing required argument: name")
    if not fields and not if_not_exists:
        raise ValueError("At least one field is required")

    pi = ctx.get_program(binary)

    def _summarise(dt):
        """Return a field summary list from any StructureDataType.

        Uses ``getDefinedComponents()`` so auto-pad gaps (undefined filler in an
        explicit-offset layout) are omitted — only the real fields are reported.
        For a gap-free sequential struct this is identical to listing every
        component.
        """
        summary = []
        for comp in dt.getDefinedComponents():
            summary.append({
                "offset":    comp.getOffset(),
                "name":      str(comp.getFieldName() or ""),
                "data_type": str(comp.getDataType().getName()),
                "length":    comp.getLength(),
            })
        return summary

    def do_create():
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            StructureDataType,
        )
        from ghidra.util.task import TaskMonitor

        dtm = pi.program.getDataTypeManager()
        existing = dtm.getDataType(f"/{struct_name}")

        if existing is not None:
            if if_not_exists:
                # Return the existing struct unchanged — no writes needed.
                return {
                    "name":            str(existing.getName()),
                    "path":            str(existing.getPathName()),
                    "size":            existing.getLength(),
                    "fields":          _summarise(existing),
                    "already_existed": True,
                }
            elif or_replace:
                # Remove the old definition; fresh one will be created below.
                with ghidra_transaction(
                    pi.program, f"ghidra-rpc: remove old struct {struct_name}"
                ):
                    dtm.remove(existing, TaskMonitor.DUMMY)
            else:
                raise ValueError(
                    f"Data type '{struct_name}' already exists at "
                    f"'{existing.getPathName()}'. Use --if-not-exists to "
                    f"silently return the existing type, --or-replace to "
                    f"delete and recreate it, or choose a different name."
                )

        # Strategy for self-referential structs:
        # 1. Register an empty struct placeholder in the DTM first.
        # 2. Then add all fields to the DTM-managed (mutable) instance;
        #    self-referential pointer fields (e.g. "MyStruct *") resolve
        #    correctly because "MyStruct" is already present in the DTM.
        # Everything happens inside a single transaction, avoiding the
        # deadlock that a two-transaction approach (add empty / add fields)
        # would have caused.

        def _resolve_field(fld):
            """Resolve a field's type; return (fdt, flen, fname). Validates."""
            ftype = fld.get("type", "")
            fname = fld.get("name", "")
            if not ftype or not fname:
                raise ValueError(f"Each field must have 'type' and 'name': {fld}")
            fdt = _resolve_data_type(pi.program, ftype)
            flen = fdt.getLength()
            if flen <= 0:
                raise ValueError(
                    f"Field '{fname}' has type '{ftype}' which is "
                    f"dynamic-length and cannot be a struct field directly. "
                    f"Use a pointer ('{ftype} *') or a fixed-length alternative."
                )
            return fdt, flen, fname

        def _build_struct():
            # Register empty placeholder, get the mutable DTM-managed instance.
            placeholder = StructureDataType(CategoryPath.ROOT, struct_name, 0, dtm)
            resolved = dtm.addDataType(placeholder, DataTypeConflictHandler.REPLACE_HANDLER)

            # Add fields sequentially (packed end-to-end, no gaps).
            for fld in fields:
                fdt, flen, fname = _resolve_field(fld)
                resolved.add(fdt, flen, fname, "")
            return resolved

        def _validate_explicit():
            """Validate the explicit-offset layout WITHOUT touching the DTM.

            Runs before any transaction opens: a create that fails inside a
            transaction leaves the transaction machinery in a state that makes
            the *next* write command silently fail to commit, so all input that
            can be rejected (bad types, offsets, overlaps) must be rejected here.
            Self-referential pointer fields ("MyStruct *") can't be resolved
            until the placeholder exists — detect them by name and defer
            resolution to the apply step, using the pointer size for the overlap
            check now.  Returns ``(entries, total)``.
            """
            ptr_size = pi.program.getDefaultPointerSize()
            entries = []  # (offset, fname, flen, fdt_or_None, ftype)
            for fld in fields:
                if fld.get("offset") is None:
                    raise ValueError(
                        "In explicit-offset mode every field must have an "
                        f"'offset' (missing on: {fld})."
                    )
                try:
                    off = _coerce_offset(fld["offset"])
                except (ValueError, TypeError):
                    raise ValueError(
                        f"Invalid offset {fld['offset']!r} in field {fld}."
                    )
                if off < 0:
                    raise ValueError(
                        f"Field '{fld.get('name')}' has a negative offset {off}."
                    )
                ftype = fld.get("type", "")
                fname = fld.get("name", "")
                if not ftype or not fname:
                    raise ValueError(f"Each field must have 'type' and 'name': {fld}")

                # Pointer to the struct being defined -> resolve later.
                if ftype.rstrip().endswith("*") and \
                        ftype.rstrip().rstrip("*").strip() == struct_name:
                    entries.append((off, fname, ptr_size, None, ftype))
                else:
                    fdt, flen, _ = _resolve_field(fld)
                    entries.append((off, fname, flen, fdt, ftype))

            # Detect overlaps so a mistaken layout fails loudly rather than
            # silently clobbering an adjacent field.
            entries.sort(key=lambda e: e[0])
            for i in range(len(entries) - 1):
                end = entries[i][0] + entries[i][2]
                if end > entries[i + 1][0]:
                    raise ValueError(
                        f"Field '{entries[i][1]}' (offset {entries[i][0]}, "
                        f"size {entries[i][2]}) overlaps field "
                        f"'{entries[i + 1][1]}' at offset {entries[i + 1][0]}."
                    )
            total = max(off + flen for (off, _, flen, _, _) in entries)
            return entries, total

        def _apply_explicit(entries, total):
            """Build the struct from a pre-validated layout (inside a tx)."""
            placeholder = StructureDataType(CategoryPath.ROOT, struct_name, 0, dtm)
            resolved = dtm.addDataType(placeholder, DataTypeConflictHandler.REPLACE_HANDLER)

            # A freshly created empty Ghidra structure reports getLength()==1
            # but holds zero addressable bytes, so a single grow-by-delta can
            # come up one byte short.  Loop until it actually covers `total`.
            while resolved.getLength() < total:
                resolved.growStructure(total - resolved.getLength())
            for (off, fname, flen, fdt, ftype) in entries:
                if fdt is None:  # deferred self-referential pointer
                    fdt = _resolve_data_type(pi.program, ftype)
                    flen = fdt.getLength()
                resolved.replaceAtOffset(off, fdt, flen, fname, "")
            return resolved

        explicit = any(fld.get("offset") is not None for fld in fields)

        # Validate the explicit layout BEFORE opening a transaction so a bad
        # layout can't leave the transaction machinery wedged for the next
        # command.
        explicit_layout = _validate_explicit() if explicit else None

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: create struct {struct_name}"
        ):
            added = (_apply_explicit(*explicit_layout) if explicit
                     else _build_struct())

        return {
            "name":            str(added.getName()),
            "path":            str(added.getPathName()),
            "size":            added.getLength(),
            "fields":          _summarise(added),
            "already_existed": False,
        }

    result = _maybe_swing(ctx, do_create)
    ctx.save_program(pi)
    return result


# ── clear-data-range ──────────────────────────────────────────────────────────

def _handle_clear_data_range(ctx, args: dict) -> dict:
    """Clear all code/data units in an inclusive byte range [start, end].

    Resets the range to undefined bytes so that ``set-data-type`` or
    ``apply-data-type-range`` can stamp fresh types there.
    """
    binary    = args.get("binary", "")
    start_str = args.get("start", "")
    end_str   = args.get("end", "")

    if not start_str:
        raise ValueError("Missing required argument: start")
    if not end_str:
        raise ValueError("Missing required argument: end")

    pi = ctx.get_program(binary)

    def do_clear():
        from ghidra_rpc.server.context import _parse_address

        start_addr = _parse_address(pi.program, start_str)
        end_addr   = _parse_address(pi.program, end_str)

        if start_addr.compareTo(end_addr) > 0:
            raise ValueError(
                f"start ({start_str}) must be <= end ({end_str})"
            )

        listing = pi.program.getListing()
        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: clear data range {start_addr}-{end_addr}",
        ):
            # clearCodeUnits(start, end, clearContext) — end is inclusive.
            listing.clearCodeUnits(start_addr, end_addr, False)

        pi.decompiler_pool.invalidate_all()
        return {
            "start":   _fmt_address(start_addr),
            "end":     _fmt_address(end_addr),
            "cleared": True,
        }

    result = _maybe_swing(ctx, do_clear)
    ctx.save_program(pi)
    return result


# ── apply-data-type-range ─────────────────────────────────────────────────────

def _handle_apply_data_type_range(ctx, args: dict) -> dict:
    """Stamp a fixed-size data type repeatedly across an inclusive range [start, end].

    Without ``clear=True`` the handler tries to stamp the type at each position;
    addresses where existing data units conflict are skipped and reported in the
    ``errors`` list. Pass ``clear=True`` (CLI flag ``--clear``) to atomically
    clear the entire range before stamping — this is required when existing
    definitions overlap with the new type's boundaries.

    The range is *inclusive*: both ``start`` and ``end`` are inside the region.
    The type is applied at each address while ``addr + type_size - 1 <= end``.

    Example (23 × 8-byte struct ErrorEntry, clear-and-stamp in one call):
        apply-data-type-range binary 0x0040e4a8 0x0040e55f ErrorEntry --clear
    """
    binary    = args.get("binary", "")
    start_str = args.get("start", "")
    end_str   = args.get("end", "")
    type_str  = args.get("data_type", "")
    clear     = bool(args.get("clear", False))

    if not start_str:
        raise ValueError("Missing required argument: start")
    if not end_str:
        raise ValueError("Missing required argument: end")
    if not type_str:
        raise ValueError("Missing required argument: data_type")

    pi = ctx.get_program(binary)

    def do_apply():
        from ghidra_rpc.server.context import _parse_address

        start_addr = _parse_address(pi.program, start_str)
        end_addr   = _parse_address(pi.program, end_str)

        if start_addr.compareTo(end_addr) > 0:
            raise ValueError(
                f"start ({start_str}) must be <= end ({end_str})"
            )

        dt     = _resolve_data_type(pi.program, type_str)
        dt_len = dt.getLength()

        if dt_len <= 0:
            raise ValueError(
                f"Data type '{type_str}' has dynamic or zero length ({dt_len}). "
                f"Only fixed-size types can be applied across a range. "
                f"Use a pointer or a fixed-size array instead."
            )

        listing = pi.program.getListing()
        applied = 0
        errors  = []

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: apply {type_str}[*] {start_addr}-{end_addr}",
        ):
            # Optionally clear the range first (removes all conflicting units).
            if clear:
                listing.clearCodeUnits(start_addr, end_addr, False)

            addr = start_addr
            while True:
                # Check that the full type instance fits within the range.
                try:
                    last_byte = addr.add(dt_len - 1)
                except Exception:
                    break
                if last_byte.compareTo(end_addr) > 0:
                    break

                try:
                    listing.createData(addr, dt)
                    applied += 1
                except Exception as e:
                    # Record the failure but continue to the next position so
                    # that a single bad address does not stop the whole range.
                    errors.append({"address": _fmt_address(addr), "error": str(e)})

                try:
                    addr = addr.add(dt_len)
                except Exception:
                    break

        pi.decompiler_pool.invalidate_all()

        result = {
            "start":         _fmt_address(start_addr),
            "end":           _fmt_address(end_addr),
            "data_type":     str(dt.getName()),
            "type_size":     dt_len,
            "applied_count": applied,
            "cleared":       clear,
        }
        if errors:
            result["errors"] = errors
        return result

    result = _maybe_swing(ctx, do_apply)
    ctx.save_program(pi)
    return result


# ── list-labels ───────────────────────────────────────────────────────────────

def _handle_list_labels(ctx, args: dict) -> dict:
    """List all symbols/labels at an address or within an address range.

    If ``end`` is not provided, returns all symbols at the single address
    ``address``.  If ``end`` is provided, returns the primary symbol at each
    labeled address in [address, end] (inclusive), up to ``limit`` results.

    The ``source`` field indicates where the symbol came from:
      USER_DEFINED — set explicitly by the user
      ANALYSIS     — created by auto-analysis (e.g. DAT_, FUN_, off_…)
      DEFAULT      — Ghidra's fallback name, not stored
      IMPORTED     — from debug info or imports table
    """
    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    end_str     = args.get("end", "")
    limit       = int(args.get("limit", 100))

    if not address_str:
        raise ValueError("Missing required argument: address")

    pi = ctx.get_program(binary)

    def do_list():
        from ghidra_rpc.server.context import _parse_address

        addr    = _parse_address(pi.program, address_str)
        st      = pi.program.getSymbolTable()
        listing = pi.program.getListing()

        labels = []

        def _data_type_at(a):
            """Return (type_name, length) for the data unit at address a, or (None, None)."""
            data = listing.getDataAt(a)
            if data is None:
                return None, None
            try:
                return str(data.getDataType().getName()), data.getLength()
            except Exception:
                return None, None

        if end_str:
            # Range query — iterate primary symbols across [addr, end_addr].
            from ghidra.program.model.address import AddressSet

            end_addr = _parse_address(pi.program, end_str)
            if addr.compareTo(end_addr) > 0:
                raise ValueError(
                    f"address ({address_str}) must be <= end ({end_str})"
                )
            addr_set = AddressSet(addr, end_addr)
            sym_iter = st.getPrimarySymbolIterator(addr_set, True)

            total = 0
            for sym in sym_iter:
                total += 1
                if len(labels) < limit:
                    dt_name, dt_len = _data_type_at(sym.getAddress())
                    labels.append({
                        "address":     _fmt_address(sym.getAddress()),
                        "name":        str(sym.getName()),
                        "type":        str(sym.getSymbolType()),
                        "source":      str(sym.getSource()),
                        "is_primary":  True,
                        "data_type":   dt_name,
                        "data_length": dt_len,
                    })
            return {"labels": labels, "count": len(labels), "total": total}
        else:
            # Single address — all symbols (including secondary).
            syms = list(st.getSymbols(addr))
            dt_name, dt_len = _data_type_at(addr)
            for sym in syms[:limit]:
                labels.append({
                    "address":     _fmt_address(sym.getAddress()),
                    "name":        str(sym.getName()),
                    "type":        str(sym.getSymbolType()),
                    "source":      str(sym.getSource()),
                    "is_primary":  bool(sym.isPrimary()),
                    "data_type":   dt_name,
                    "data_length": dt_len,
                })
            return {"labels": labels, "count": len(labels), "total": len(syms)}

    return _maybe_swing(ctx, do_list)


# ── create-enum ──────────────────────────────────────────────────────────────

def _handle_create_enum(ctx, args: dict) -> dict:
    """Create a named enum data type in the program's data type manager.

    ``values`` is a list of ``{"name": "<name>", "value": <int>}`` dicts.

    ``size`` — byte size of the enum (1, 2, 4, or 8; default 4).

    ``if_not_exists`` — if True and the name already exists, return the
    existing enum without error (idempotent / safe-for-scripts).

    ``or_replace`` — if True and the name already exists, delete it first
    then create a fresh enum with the provided values.
    """
    binary        = args.get("binary", "")
    enum_name     = args.get("name", "")
    values        = args.get("values", [])   # [{"name": str, "value": int}, ...]
    size          = int(args.get("size", 4))
    if_not_exists = bool(args.get("if_not_exists", False))
    or_replace    = bool(args.get("or_replace", False))

    if not enum_name:
        raise ValueError("Missing required argument: name")
    if size not in (1, 2, 4, 8):
        raise ValueError(f"Invalid enum size {size}. Must be 1, 2, 4, or 8.")
    if not values and not if_not_exists:
        raise ValueError("At least one value is required")

    pi = ctx.get_program(binary)

    def _summarise(dt):
        summary = []
        for n in dt.getNames():
            v = int(dt.getValue(str(n)))
            summary.append({"name": str(n), "value": v})
        return summary

    def do_create():
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            EnumDataType,
        )
        from ghidra.util.task import TaskMonitor

        dtm      = pi.program.getDataTypeManager()
        existing = dtm.getDataType(f"/{enum_name}")

        if existing is not None:
            if if_not_exists:
                return {
                    "name":            str(existing.getName()),
                    "path":            str(existing.getPathName()),
                    "size":            existing.getLength(),
                    "values":          _summarise(existing),
                    "already_existed": True,
                }
            elif or_replace:
                with ghidra_transaction(
                    pi.program,
                    f"ghidra-rpc: remove old enum {enum_name}",
                ):
                    dtm.remove(existing, TaskMonitor.DUMMY)
            else:
                raise ValueError(
                    f"Data type '{enum_name}' already exists at "
                    f"'{existing.getPathName()}'. Use --if-not-exists to "
                    f"silently return the existing type, --or-replace to "
                    f"delete and recreate it, or choose a different name."
                )

        enum_dt = EnumDataType(CategoryPath.ROOT, enum_name, size, dtm)
        for entry in values:
            ename = entry.get("name", "")
            evalue = int(entry.get("value", 0))
            if not ename:
                raise ValueError(f"Each value entry must have 'name': {entry}")
            enum_dt.add(ename, evalue)

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: create enum {enum_name}"
        ):
            added = dtm.addDataType(enum_dt, DataTypeConflictHandler.DEFAULT_HANDLER)

        return {
            "name":            str(added.getName()),
            "path":            str(added.getPathName()),
            "size":            added.getLength(),
            "values":          _summarise(added),
            "already_existed": False,
        }

    result = _maybe_swing(ctx, do_create)
    ctx.save_program(pi)
    return result


# ── set-equate ────────────────────────────────────────────────────────────────

def _handle_set_equate(ctx, args: dict) -> dict:
    """Apply an equate (named scalar constant) to an instruction operand.

    Creates the equate in the program's EquateTable if it does not exist,
    then adds a reference from the instruction at ``address`` operand index
    ``operand_index`` (default 1, the immediate operand).

    If ``enum_path`` is provided (e.g. ``MyEnum``) the equate name must
    exactly match an entry name in that enum so Ghidra links the equate to
    the enum type.  Otherwise the equate is a bare named constant.
    """
    binary        = args.get("binary", "")
    address_str   = args.get("address", "")
    equate_name   = args.get("equate_name", "")
    equate_value  = int(args.get("value", 0))
    operand_index = int(args.get("operand_index", 1))
    enum_path     = args.get("enum_path", "")  # optional DTM path to link to

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not equate_name:
        raise ValueError("Missing required argument: equate_name")

    pi = ctx.get_program(binary)

    def do_set():
        from ghidra_rpc.server.context import _parse_address

        addr         = _parse_address(pi.program, address_str)
        equate_table = pi.program.getEquateTable()
        dtm          = pi.program.getDataTypeManager()

        # Resolve enum type for linking (if requested or auto-detectable).
        enum_uid = None
        if enum_path:
            # Caller explicitly named an enum; validate and extract UniversalID.
            enum_dt = dtm.getDataType(
                enum_path if enum_path.startswith("/") else f"/{enum_path}"
            )
            if enum_dt is None:
                raise ValueError(
                    f"Enum '{enum_path}' not found in the data type manager."
                )
            cname = str(enum_dt.getClass().getSimpleName())
            if "Enum" not in cname:
                raise ValueError(
                    f"'{enum_path}' is a {cname}, not an EnumDataType."
                )
            # Verify the enum contains an entry with this name.
            if equate_name not in [str(n) for n in enum_dt.getNames()]:
                raise ValueError(
                    f"Enum '{enum_path}' has no entry named '{equate_name}'."
                )
            try:
                enum_uid = enum_dt.getUniversalID()
            except Exception:
                enum_uid = None  # fall back to bare equate if UID is unavailable
        else:
            # Auto-detect: if an enum in the DTM has an entry with this exact
            # name and value, link to it (mirrors Ghidra GUI behaviour).
            from java.util import ArrayList  # type: ignore
            hits = ArrayList()
            dtm.findDataTypes(equate_name, hits)
            for i in range(hits.size()):
                candidate = hits.get(i)
                if "Enum" not in str(candidate.getClass().getSimpleName()):
                    continue
                # Check if the enum has an entry whose name == equate_name
                # AND whose value == equate_value.
                names = [str(n) for n in candidate.getNames()]
                if equate_name in names:
                    try:
                        if int(candidate.getValue(equate_name)) == equate_value:
                            enum_uid = candidate.getUniversalID()
                            break
                    except Exception:
                        pass

        # Re-use an existing equate with the same name+value, else create.
        equate = equate_table.getEquate(equate_name)
        if equate is None:
            with ghidra_transaction(
                pi.program,
                f"ghidra-rpc: create equate {equate_name}={equate_value}",
            ):
                # Try the 3-arg form (enum-linked) first; fall back to 2-arg.
                if enum_uid is not None:
                    try:
                        equate = equate_table.createEquate(
                            equate_name, equate_value, enum_uid
                        )
                    except Exception:
                        equate = equate_table.createEquate(equate_name, equate_value)
                else:
                    equate = equate_table.createEquate(equate_name, equate_value)
        elif equate.getValue() != equate_value:
            raise ValueError(
                f"Equate '{equate_name}' already exists with value "
                f"{equate.getValue()}, not {equate_value}. "
                f"Choose a different name or use the matching value."
            )

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: set equate {equate_name} @ {addr}[{operand_index}]",
        ):
            equate.addReference(addr, operand_index)

        pi.decompiler_pool.invalidate_all()
        return {
            "address":        _fmt_address(addr),
            "operand_index":  operand_index,
            "equate_name":    equate_name,
            "value":          equate_value,
            "enum_linked":    enum_uid is not None,
            "verified":       True,
        }

    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


# ── list-equates ─────────────────────────────────────────────────────

def _handle_list_equates(ctx, args: dict) -> dict:
    """List equates in a program or at a specific address.

    Without ``address``: returns all equates defined in the program's equate
    table, up to ``limit`` results.

    With ``address``: returns only equates applied at that instruction address
    (across all operand indices).
    """
    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    limit       = int(args.get("limit", 200))

    pi = ctx.get_program(binary)

    def do_list():
        equate_table = pi.program.getEquateTable()
        equates = []
        total   = 0

        if address_str:
            from ghidra_rpc.server.context import _parse_address
            addr = _parse_address(pi.program, address_str)
            seen: set[str] = set()
            # EquateTable.getEquates(Address, int) — query each operand slot.
            for op_idx in range(8):
                for eq in equate_table.getEquates(addr, op_idx):
                    name = str(eq.getName())
                    key  = f"{name}:{op_idx}"
                    if key not in seen:
                        seen.add(key)
                        total += 1
                        if len(equates) < limit:
                            equates.append({
                                "name":          name,
                                "value":         int(eq.getValue()),
                                "operand_index": op_idx,
                                "address":       _fmt_address(addr),
                            })
        else:
            # All equates in the program.
            for eq in equate_table.getEquates():
                total += 1
                if len(equates) < limit:
                    equates.append({
                        "name":  str(eq.getName()),
                        "value": int(eq.getValue()),
                    })

        return {"equates": equates, "count": len(equates), "total": total}

    return _maybe_swing(ctx, do_list)


# ── list-data-types ───────────────────────────────────────────────────

def _handle_list_data_types(ctx, args: dict) -> dict:
    """Enumerate data types in the program's DataTypeManager.

    Returns names, paths, sizes, and categories of every type in the DTM,
    filtered by ``category`` and/or a name substring ``query``.

    ``category`` values: ``struct``, ``enum``, ``union``, ``typedef``,
    ``pointer``, ``array``, or ``all`` (default).
    """
    binary   = args.get("binary", "")
    category = args.get("category", "all").lower()
    query    = args.get("query", "").lower()
    limit    = int(args.get("limit", 200))

    valid_categories = {"all", "struct", "enum", "union", "typedef",
                        "pointer", "array", "other"}
    if category not in valid_categories:
        raise ValueError(
            f"Invalid category '{category}'. "
            f"Use one of: {sorted(valid_categories)}"
        )

    pi = ctx.get_program(binary)

    def _classify(dt) -> str:
        """Return a simple category string from the Java class name."""
        try:
            cname = str(dt.getClass().getSimpleName())
        except Exception:
            return "other"
        if "Structure" in cname:
            return "struct"
        if "Enum" in cname:
            return "enum"
        if "Union" in cname:
            return "union"
        if "Typedef" in cname:
            return "typedef"
        if "Pointer" in cname:
            return "pointer"
        if "Array" in cname:
            return "array"
        return "other"

    def do_list():
        dtm    = pi.program.getDataTypeManager()
        result = []
        total  = 0

        for dt in dtm.getAllDataTypes():
            name   = str(dt.getName())
            cat    = _classify(dt)

            if category != "all" and cat != category:
                continue
            if query and query not in name.lower():
                continue

            total += 1
            if len(result) < limit:
                result.append({
                    "name":     name,
                    "path":     str(dt.getPathName()),
                    "category": cat,
                    "size":     dt.getLength(),
                })

        return {"data_types": result, "count": len(result), "total": total}

    return _maybe_swing(ctx, do_list)


# ── modify-enum ───────────────────────────────────────────────────────

def _handle_modify_enum(ctx, args: dict) -> dict:
    """Add or remove individual entries from an existing enum.

    ``add``    — list of ``{"name": str, "value": int}`` entries to add.
    ``remove`` — list of entry *names* (strings) to remove.

    Both lists may be provided in the same call; removals are applied before
    additions so that renaming an entry is safe (remove old, add new).
    """
    binary    = args.get("binary", "")
    enum_name = args.get("name", "")
    add       = args.get("add", [])    # [{"name": str, "value": int}, ...]
    remove    = args.get("remove", []) # [str, ...]

    if not enum_name:
        raise ValueError("Missing required argument: name")
    if not add and not remove:
        raise ValueError("At least one 'add' or 'remove' entry is required")

    pi = ctx.get_program(binary)

    def _summarise(dt):
        summary = []
        for n in dt.getNames():
            summary.append({"name": str(n), "value": int(dt.getValue(str(n)))})
        return summary

    def do_modify():
        dtm      = pi.program.getDataTypeManager()
        enum_dt  = dtm.getDataType(f"/{enum_name}")

        if enum_dt is None:
            # Fall back to a substring search.
            from java.util import ArrayList  # type: ignore
            hits = ArrayList()
            dtm.findDataTypes(enum_name, hits)
            for i in range(hits.size()):
                candidate = hits.get(i)
                if str(candidate.getName()) == enum_name:
                    enum_dt = candidate
                    break

        if enum_dt is None:
            raise ValueError(
                f"Enum '{enum_name}' not found in the data type manager. "
                f"Use list-data-types to see what types exist."
            )

        cname = str(enum_dt.getClass().getSimpleName())
        if "Enum" not in cname:
            raise ValueError(
                f"'{enum_name}' is a {cname}, not an EnumDataType. "
                f"modify-enum only works with enum types."
            )

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: modify enum {enum_name}"
        ):
            # Removals first (safe if value changes are combined with rename).
            for entry_name in remove:
                try:
                    enum_dt.remove(str(entry_name))
                except Exception as e:
                    raise ValueError(
                        f"Cannot remove '{entry_name}' from '{enum_name}': {e}"
                    ) from None
            for entry in add:
                ename  = entry.get("name", "")
                evalue = int(entry.get("value", 0))
                if not ename:
                    raise ValueError(f"Each add entry must have 'name': {entry}")
                enum_dt.add(ename, evalue)

        return {
            "name":   str(enum_dt.getName()),
            "path":   str(enum_dt.getPathName()),
            "size":   enum_dt.getLength(),
            "values": _summarise(enum_dt),
        }

    result = _maybe_swing(ctx, do_modify)
    ctx.save_program(pi)
    return result


# ── create-union ─────────────────────────────────────────────────────────────

def _handle_create_union(ctx, args: dict) -> dict:
    """Create a named union data type in the program's data type manager.

    ``fields`` is a list of ``{"type": "<type_str>", "name": "<field_name>"}``
    dicts.  Same type expressions as ``create-struct``.

    Unlike structs, all union fields share offset 0 and the union's size
    equals the largest member. No offset tracking is needed.

    ``if_not_exists`` — return existing union without error (idempotent).
    ``or_replace`` — delete existing union and recreate.
    """
    binary        = args.get("binary", "")
    union_name    = args.get("name", "")
    fields        = args.get("fields", [])
    if_not_exists = bool(args.get("if_not_exists", False))
    or_replace    = bool(args.get("or_replace", False))

    if not union_name:
        raise ValueError("Missing required argument: name")
    if not fields and not if_not_exists:
        raise ValueError("At least one field is required")

    pi = ctx.get_program(binary)

    def _summarise(dt):
        summary = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            summary.append({
                "offset":    comp.getOffset(),
                "name":      str(comp.getFieldName() or ""),
                "data_type": str(comp.getDataType().getName()),
                "length":    comp.getLength(),
            })
        return summary

    def do_create():
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            UnionDataType,
        )
        from ghidra.util.task import TaskMonitor

        dtm = pi.program.getDataTypeManager()
        existing = dtm.getDataType(f"/{union_name}")

        if existing is not None:
            if if_not_exists:
                return {
                    "name":            str(existing.getName()),
                    "path":            str(existing.getPathName()),
                    "size":            existing.getLength(),
                    "fields":          _summarise(existing),
                    "already_existed": True,
                }
            elif or_replace:
                with ghidra_transaction(
                    pi.program, f"ghidra-rpc: remove old union {union_name}"
                ):
                    dtm.remove(existing, TaskMonitor.DUMMY)
            else:
                raise ValueError(
                    f"Data type '{union_name}' already exists at "
                    f"'{existing.getPathName()}'. Use --if-not-exists to "
                    f"silently return the existing type, --or-replace to "
                    f"delete and recreate it, or choose a different name."
                )

        def _build_union():
            placeholder = UnionDataType(CategoryPath.ROOT, union_name, dtm)
            resolved = dtm.addDataType(
                placeholder, DataTypeConflictHandler.REPLACE_HANDLER
            )
            for fld in fields:
                ftype = fld.get("type", "")
                fname = fld.get("name", "")
                if not ftype or not fname:
                    raise ValueError(
                        f"Each field must have 'type' and 'name': {fld}"
                    )
                fdt = _resolve_data_type(pi.program, ftype)
                flen = fdt.getLength()
                if flen <= 0:
                    raise ValueError(
                        f"Field '{fname}' has type '{ftype}' which is "
                        f"dynamic-length and cannot be a union field. "
                        f"Use a pointer ('{ftype} *') or fixed-length alternative."
                    )
                resolved.add(fdt, flen, fname, "")
            return resolved

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: create union {union_name}"
        ):
            added = _build_union()

        return {
            "name":            str(added.getName()),
            "path":            str(added.getPathName()),
            "size":            added.getLength(),
            "fields":          _summarise(added),
            "already_existed": False,
        }

    result = _maybe_swing(ctx, do_create)
    ctx.save_program(pi)
    return result


# ── modify-struct ────────────────────────────────────────────────────────────

def _handle_modify_struct(ctx, args: dict) -> dict:
    """Retype or rename a field in an existing struct.

    Identifies the target field by either ``field_offset`` (byte offset) or
    ``field_name``. At least one of these is required.

    Optional mutations:
        new_type    -- new data type for the field (type expression string)
        new_name    -- new name for the field
        new_comment -- new comment for the field

    Uses ``Structure.replaceAtOffset()`` which handles size changes and
    gap management correctly.

    Args (in ``args`` dict):
        binary       -- program name / key
        struct_name  -- name or path of the struct type
        field_offset -- byte offset of the field to modify (int)
        field_name   -- name of the field to modify (alternative to offset)
        new_type     -- new data type expression for the field
        new_name     -- new name for the field
        new_comment  -- new comment for the field

    Returns a dict with struct summary after modification.
    """
    binary       = args.get("binary", "")
    struct_name  = args.get("struct_name", "")
    field_offset = args.get("field_offset")  # int or None
    field_name   = args.get("field_name", "")
    new_type     = args.get("new_type", "")
    new_name     = args.get("new_name", "")
    new_comment  = args.get("new_comment", "")

    if not struct_name:
        raise ValueError("Missing required argument: struct_name")
    if field_offset is None and not field_name:
        raise ValueError(
            "At least one of field_offset or field_name is required "
            "to identify the target field."
        )
    if not new_type and not new_name and not new_comment:
        raise ValueError(
            "At least one mutation is required: new_type, new_name, or new_comment"
        )

    pi = ctx.get_program(binary)

    def _summarise(dt):
        summary = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            summary.append({
                "offset":    comp.getOffset(),
                "name":      str(comp.getFieldName() or ""),
                "data_type": str(comp.getDataType().getName()),
                "length":    comp.getLength(),
                "comment":   str(comp.getComment() or ""),
            })
        return summary

    def do_modify():
        dtm = pi.program.getDataTypeManager()
        struct_dt = dtm.getDataType(
            struct_name if struct_name.startswith("/") else f"/{struct_name}"
        )
        if struct_dt is None:
            # Fall back to name search
            from java.util import ArrayList
            hits = ArrayList()
            dtm.findDataTypes(struct_name, hits)
            for i in range(hits.size()):
                candidate = hits.get(i)
                if str(candidate.getName()) == struct_name:
                    struct_dt = candidate
                    break

        if struct_dt is None:
            raise ValueError(
                f"Struct '{struct_name}' not found in the data type manager."
            )

        cname = str(struct_dt.getClass().getSimpleName())
        if "Structure" not in cname:
            raise ValueError(
                f"'{struct_name}' is a {cname}, not a StructureDataType."
            )

        # Find the target field
        target_comp = None
        if field_offset is not None:
            target_comp = struct_dt.getComponentAt(int(field_offset))
            if target_comp is None:
                raise ValueError(
                    f"No field at offset {field_offset} in '{struct_name}'. "
                    f"Valid offsets: "
                    f"{[struct_dt.getComponent(i).getOffset() for i in range(struct_dt.getNumComponents())]}"
                )
        elif field_name:
            for i in range(struct_dt.getNumComponents()):
                comp = struct_dt.getComponent(i)
                if str(comp.getFieldName() or "") == field_name:
                    target_comp = comp
                    break
            if target_comp is None:
                raise ValueError(
                    f"No field named '{field_name}' in '{struct_name}'. "
                    f"Fields: "
                    f"{[str(struct_dt.getComponent(i).getFieldName() or '') for i in range(struct_dt.getNumComponents())]}"
                )

        offset = target_comp.getOffset()
        old_name = str(target_comp.getFieldName() or "")
        old_type = str(target_comp.getDataType().getName())

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: modify struct {struct_name} field @ offset {offset}",
        ):
            if new_type:
                fdt = _resolve_data_type(pi.program, new_type)
                flen = fdt.getLength()
                if flen <= 0:
                    raise ValueError(
                        f"Type '{new_type}' is dynamic-length and cannot "
                        f"be a struct field. Use a pointer or fixed-length type."
                    )
                # replaceAtOffset handles size changes and gap management
                struct_dt.replaceAtOffset(
                    offset, fdt, flen,
                    new_name or old_name,
                    new_comment or str(target_comp.getComment() or ""),
                )
            else:
                # Name and/or comment change only
                if new_name:
                    target_comp.setFieldName(new_name)
                if new_comment:
                    target_comp.setComment(new_comment)

        return {
            "name":     str(struct_dt.getName()),
            "path":     str(struct_dt.getPathName()),
            "size":     struct_dt.getLength(),
            "fields":   _summarise(struct_dt),
            "modified_field": {
                "offset":   offset,
                "old_name": old_name,
                "old_type": old_type,
                "new_name": new_name or old_name,
                "new_type": new_type or old_type,
            },
        }

    result = _maybe_swing(ctx, do_modify)
    ctx.save_program(pi)
    return result


# ── register ──────────────────────────────────────────────────────────────────

register_handler("create_struct",          _handle_create_struct)
register_handler("create_union",           _handle_create_union)
register_handler("create_enum",            _handle_create_enum)
register_handler("modify_enum",            _handle_modify_enum)
register_handler("modify_struct",          _handle_modify_struct)
register_handler("set_equate",             _handle_set_equate)
register_handler("list_equates",           _handle_list_equates)
register_handler("list_data_types",        _handle_list_data_types)
register_handler("clear_data_range",       _handle_clear_data_range)
register_handler("apply_data_type_range",  _handle_apply_data_type_range)
register_handler("list_labels",            _handle_list_labels)
