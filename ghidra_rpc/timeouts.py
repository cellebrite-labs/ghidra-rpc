"""Decompile budgets shared by the daemon's handlers and the client.

The client derives how long to wait for a reply from these, so a handler
that changes how many decompiles it runs, or its default ``timeout``, must
change them here too.
"""

from __future__ import annotations

# Default for a handler's per-decompile ``timeout`` arg when it is absent.
DEFAULT_DECOMPILE_TIMEOUT = 60

# Daemon commands that run two full decompiles, each with the ``timeout`` arg:
# the snapshot an edit applies to plus the read-back that verifies it, or the
# two sides of a diff.
DOUBLE_DECOMPILE_COMMANDS = frozenset({
    "batch_edit_variables",
    "function_diff",
    "rename_variable",
    "retype_variable",
})
