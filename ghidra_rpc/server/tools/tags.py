"""Function tag tools: tag functions for classification and tracking.

Provides commands for managing function tags:
  tag_function     — add a tag to a function
  untag_function   — remove a tag from a function
  list_tags        — list all defined tags with use counts
  functions_by_tag — list functions with a specific tag
"""

from __future__ import annotations

from ghidra_rpc.server.context import _fmt_address
from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.decompiler import _find_function
from ghidra_rpc.server.tools.modifications import (
    _maybe_swing,
    ghidra_transaction,
)


def _handle_tag_function(ctx, args: dict) -> dict:
    """Add a tag to a function.

    Tags are string labels for classifying functions (e.g. "crypto",
    "vuln-sink", "analyzed", "needs-review"). Visible in Ghidra's
    Function Tags window.

    Creates the tag if it doesn't already exist in the program's tag manager.

    Args (in ``args`` dict):
        binary -- program name / key
        target -- function name or address
        tag    -- tag string to apply

    Returns a dict with:
        address  -- function entry point
        name     -- function name
        tag      -- the tag that was added
        all_tags -- list of all tags on this function after the operation
    """
    binary = args.get("binary", "")
    target = args.get("target", "")
    tag    = args.get("tag", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not tag:
        raise ValueError("Missing required argument: tag")

    pi = ctx.get_program(binary)

    def do_tag():
        func = _find_function(pi, target)
        fm = pi.program.getFunctionManager()
        tag_mgr = fm.getFunctionTagManager()

        with ghidra_transaction(
            pi.program, f"ghidra-rpc: tag {func.getName()} with '{tag}'"
        ):
            # Get or create the tag
            tag_obj = tag_mgr.getFunctionTag(tag)
            if tag_obj is None:
                tag_obj = tag_mgr.createFunctionTag(tag, "")
            func.addTag(tag.strip())

        # Collect all tags after mutation
        all_tags = [str(t.getName()) for t in func.getTags()]

        return {
            "address":  _fmt_address(func.getEntryPoint()),
            "name":     str(func.getName()),
            "tag":      tag,
            "all_tags": sorted(all_tags),
        }

    result = _maybe_swing(ctx, do_tag)
    ctx.save_program(pi)
    return result


def _handle_untag_function(ctx, args: dict) -> dict:
    """Remove a tag from a function.

    Args (in ``args`` dict):
        binary -- program name / key
        target -- function name or address
        tag    -- tag string to remove

    Returns a dict with:
        address  -- function entry point
        name     -- function name
        tag      -- the tag that was removed
        removed  -- whether the tag was actually present
        all_tags -- list of remaining tags after the operation
    """
    binary = args.get("binary", "")
    target = args.get("target", "")
    tag    = args.get("tag", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not tag:
        raise ValueError("Missing required argument: tag")

    pi = ctx.get_program(binary)

    def do_untag():
        func = _find_function(pi, target)

        existing_tags = {str(t.getName()) for t in func.getTags()}
        removed = tag in existing_tags

        if removed:
            with ghidra_transaction(
                pi.program, f"ghidra-rpc: untag {func.getName()} '{tag}'"
            ):
                func.removeTag(tag)

        all_tags = [str(t.getName()) for t in func.getTags()]
        return {
            "address":  _fmt_address(func.getEntryPoint()),
            "name":     str(func.getName()),
            "tag":      tag,
            "removed":  removed,
            "all_tags": sorted(all_tags),
        }

    result = _maybe_swing(ctx, do_untag)
    if result["removed"]:
        ctx.save_program(pi)
    return result


def _handle_list_tags(ctx, args: dict) -> dict:
    """List all function tags defined in the program with use counts.

    Args (in ``args`` dict):
        binary -- program name / key

    Returns a dict with:
        tags  -- list of {name, count} dicts
        count -- number of distinct tags
    """
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)

    def do_list():
        fm = pi.program.getFunctionManager()
        tag_mgr = fm.getFunctionTagManager()

        # Count usage per tag by iterating all functions
        tag_counts: dict[str, int] = {}

        # First, get all defined tags
        for tag_obj in tag_mgr.getAllFunctionTags():
            tag_counts[str(tag_obj.getName())] = 0

        # Count how many functions use each tag
        for func in fm.getFunctions(True):
            for t in func.getTags():
                tname = str(t.getName())
                tag_counts[tname] = tag_counts.get(tname, 0) + 1

        tags = [{"name": name, "count": count}
                for name, count in sorted(tag_counts.items())]

        return {
            "tags":  tags,
            "count": len(tags),
        }

    return _maybe_swing(ctx, do_list)


def _handle_functions_by_tag(ctx, args: dict) -> dict:
    """List all functions with a specific tag.

    Args (in ``args`` dict):
        binary -- program name / key
        tag    -- tag name to search for
        limit  -- max results (default 200)

    Returns a dict with:
        tag       -- the queried tag
        functions -- list of {name, address, signature} dicts
        count     -- number of functions returned
        total     -- total matching functions
    """
    binary = args.get("binary", "")
    tag    = args.get("tag", "")
    limit  = int(args.get("limit", 200))

    if not tag:
        raise ValueError("Missing required argument: tag")

    pi = ctx.get_program(binary)

    def do_list():
        fm = pi.program.getFunctionManager()
        functions = []
        total = 0

        for func in fm.getFunctions(True):
            func_tags = {str(t.getName()) for t in func.getTags()}
            if tag in func_tags:
                total += 1
                if len(functions) < limit:
                    functions.append({
                        "name":      str(func.getName()),
                        "address":   _fmt_address(func.getEntryPoint()),
                        "signature": str(func.getSignature()),
                    })

        return {
            "tag":       tag,
            "functions": functions,
            "count":     len(functions),
            "total":     total,
        }

    return _maybe_swing(ctx, do_list)


register_handler("tag_function",     _handle_tag_function)
register_handler("untag_function",   _handle_untag_function)
register_handler("list_tags",        _handle_list_tags)
register_handler("functions_by_tag", _handle_functions_by_tag)
