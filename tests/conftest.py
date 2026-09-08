"""Shared test fixtures.

macOS caps an ``AF_UNIX`` socket's ``sun_path`` at 104 bytes where Linux
allows 108, and pytest's ``tmp_path`` on macOS is rooted under
``/private/var/folders/<random>/T/pytest-of-<user>/pytest-N/<test-name>0``,
which reaches roughly 120 bytes before a filename is even appended.  Any test
that binds a socket therefore needs a shorter root than ``tmp_path`` can give
it — see ``short_tmp_path`` below.

Only the test harness is affected: real endpoints are
``/tmp/ghidra-rpc-<hash>.sock``, 29 bytes.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def short_tmp_path():
    """A temp directory short enough to hold an ``AF_UNIX`` socket path.

    Use this in place of ``tmp_path`` in any test that binds a socket.

    On POSIX this goes straight to ``/tmp`` rather than
    ``tempfile.gettempdir()``, because on macOS the latter is exactly the long
    per-user ``/var/folders`` path that causes the problem.  Windows has no
    ``sun_path`` limit — its endpoint is a regular file holding host, port and
    token — so the platform temp directory is fine there.
    """
    base = Path(tempfile.gettempdir()) if os.name == "nt" else Path("/tmp")
    # resolve() matters, and mkdtemp does not do it while pytest's tmp_path
    # arrives already resolved.  The `ping` reply reports project_gpr verbatim
    # (server/main.py) whereas the session registry stores it resolved, so with
    # an unresolved root the two forms of the same path stop comparing equal —
    # /tmp is a symlink to /private/tmp on macOS, and %TEMP% can carry an 8.3
    # short name like C:\Users\RUNNER~1 on Windows.  Resolving keeps the path
    # short either way: /private/tmp/grpc-xxxxxxxx is ~26 bytes of the 104.
    path = Path(tempfile.mkdtemp(prefix="grpc-", dir=base)).resolve()
    try:
        yield path
    finally:
        # mkdtemp has none of tmp_path's retention machinery, and
        # transport.remove_endpoint() only unlinks the socket file — never the
        # directory transport.listen() created with parents=True.  Clean up
        # here or every run leaks a /tmp/grpc-* directory.
        shutil.rmtree(path, ignore_errors=True)
