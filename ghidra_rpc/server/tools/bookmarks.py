"""Bookmark tools: read and write Ghidra analysis bookmarks.

Bookmarks are first-class annotations in Ghidra with a type (Note, Warning,
Error, Info, Analysis), a category (free-form string), and a comment.
"""

from __future__ import annotations

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.modifications import (
    _maybe_swing,
    ghidra_transaction,
)

# Valid bookmark types in Ghidra
_VALID_TYPES = {"Note", "Warning", "Error", "Info", "Analysis"}


def _handle_set_bookmark(ctx, args: dict) -> dict:
    """Create or update a bookmark at an address.

    Args (in ``args`` dict):
        binary   -- program name / key
        address  -- hex address string
        type     -- bookmark type: Note, Warning, Error, Info, Analysis
                    (default: Note)
        category -- free-form category string (e.g. "vuln-research",
                    "crypto", "needs-review")
        comment  -- bookmark comment text

    Returns a dict with:
        address  -- canonical address
        type     -- bookmark type
        category -- bookmark category
        comment  -- bookmark comment
        action   -- "created" or "updated"
    """
    from ghidra_rpc.server.context import _parse_address

    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    bm_type     = args.get("type", "Note")
    category    = args.get("category", "")
    comment     = args.get("comment", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not comment and not category:
        raise ValueError("At least one of 'comment' or 'category' is required")

    # Normalize type: case-insensitive match
    bm_type_norm = None
    for vt in _VALID_TYPES:
        if bm_type.lower() == vt.lower():
            bm_type_norm = vt
            break
    if bm_type_norm is None:
        raise ValueError(
            f"Invalid bookmark type '{bm_type}'. "
            f"Valid types: {sorted(_VALID_TYPES)}"
        )

    pi = ctx.get_program(binary)

    def do_set():
        addr = _parse_address(pi.program, address_str)
        bm_mgr = pi.program.getBookmarkManager()

        # Check if a bookmark of this type already exists at the address
        existing = bm_mgr.getBookmark(addr, bm_type_norm, category)
        action = "updated" if existing is not None else "created"

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: set bookmark {bm_type_norm} @ {addr}",
        ):
            bm_mgr.setBookmark(addr, bm_type_norm, category, comment)

        return {
            "address":  _fmt_address(addr),
            "type":     bm_type_norm,
            "category": category,
            "comment":  comment,
            "action":   action,
        }

    result = _maybe_swing(ctx, do_set)
    ctx.save_program(pi)
    return result


def _handle_list_bookmarks(ctx, args: dict) -> dict:
    """List bookmarks in a program.

    Args (in ``args`` dict):
        binary   -- program name / key
        type     -- optional: filter by bookmark type (Note, Warning, etc.)
        category -- optional: filter by category (case-insensitive substring
                    match). Useful for separating user-created bookmarks
                    (e.g. a custom category like "BLE-Protocol") from
                    analysis-generated ones (typically category "Address
                    Table" under type "Analysis").
        address  -- optional: list only bookmarks at this address
        limit    -- max results (default 200)

    Returns a dict with:
        bookmarks -- list of dicts:
                       address  -- bookmark address
                       type     -- bookmark type string
                       category -- bookmark category
                       comment  -- bookmark comment
        count     -- number returned
        total     -- total matching (may be > count if truncated)
    """
    from ghidra_rpc.server.context import _parse_address

    binary       = args.get("binary", "")
    bm_type      = args.get("type", "")
    category_str = args.get("category", "")
    address_str  = args.get("address", "")
    limit        = int(args.get("limit", 200))
    category_lower = category_str.lower() if category_str else None

    # Validate type if provided
    if bm_type:
        bm_type_norm = None
        for vt in _VALID_TYPES:
            if bm_type.lower() == vt.lower():
                bm_type_norm = vt
                break
        if bm_type_norm is None:
            raise ValueError(
                f"Invalid bookmark type '{bm_type}'. "
                f"Valid types: {sorted(_VALID_TYPES)}"
            )
        bm_type = bm_type_norm

    pi = ctx.get_program(binary)

    def do_list():
        bm_mgr = pi.program.getBookmarkManager()

        if address_str:
            addr = _parse_address(pi.program, address_str)
            bm_iter = bm_mgr.getBookmarks(addr)
        elif bm_type:
            bm_iter = bm_mgr.getBookmarksIterator(bm_type)
        else:
            bm_iter = bm_mgr.getBookmarksIterator()

        bookmarks = []
        total = 0
        for bm in bm_iter:
            # getBookmarks(addr) isn't pre-filtered by type; the other two
            # iterators already are, so this check is a cheap no-op for them.
            if bm_type and str(bm.getTypeString()) != bm_type:
                continue
            bm_category = str(bm.getCategory())
            if category_lower is not None and category_lower not in bm_category.lower():
                continue
            total += 1
            if len(bookmarks) < limit:
                bookmarks.append({
                    "address":  _fmt_address(bm.getAddress()),
                    "type":     str(bm.getTypeString()),
                    "category": bm_category,
                    "comment":  str(bm.getComment()),
                })

        return {"bookmarks": bookmarks, "count": len(bookmarks), "total": total}

    return _maybe_swing(ctx, do_list)


def _handle_remove_bookmark(ctx, args: dict) -> dict:
    """Remove a bookmark at an address.

    Args (in ``args`` dict):
        binary   -- program name / key
        address  -- hex address string
        type     -- bookmark type to remove (default: Note)
        category -- bookmark category to remove (default: "", matches
                    the empty-category bookmark)

    Returns a dict with:
        address -- canonical address
        type    -- bookmark type
        removed -- True if a bookmark was found and removed
    """
    from ghidra_rpc.server.context import _parse_address

    binary      = args.get("binary", "")
    address_str = args.get("address", "")
    bm_type     = args.get("type", "Note")
    category    = args.get("category", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    # Normalize type
    bm_type_norm = None
    for vt in _VALID_TYPES:
        if bm_type.lower() == vt.lower():
            bm_type_norm = vt
            break
    if bm_type_norm is None:
        raise ValueError(
            f"Invalid bookmark type '{bm_type}'. "
            f"Valid types: {sorted(_VALID_TYPES)}"
        )

    pi = ctx.get_program(binary)

    def do_remove():
        addr = _parse_address(pi.program, address_str)
        bm_mgr = pi.program.getBookmarkManager()
        bm = bm_mgr.getBookmark(addr, bm_type_norm, category)

        if bm is None:
            return {
                "address": _fmt_address(addr),
                "type":    bm_type_norm,
                "removed": False,
            }

        with ghidra_transaction(
            pi.program,
            f"ghidra-rpc: remove bookmark {bm_type_norm} @ {addr}",
        ):
            bm_mgr.removeBookmark(bm)

        return {
            "address": _fmt_address(addr),
            "type":    bm_type_norm,
            "removed": True,
        }

    result = _maybe_swing(ctx, do_remove)
    ctx.save_program(pi)
    return result


register_handler("set_bookmark", _handle_set_bookmark)
register_handler("list_bookmarks", _handle_list_bookmarks)
register_handler("remove_bookmark", _handle_remove_bookmark)
