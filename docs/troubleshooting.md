# Troubleshooting

## GHIDRA_INSTALL_DIR Not Set

**Symptom**: Daemon fails to start with "GHIDRA_INSTALL_DIR environment variable is not set"

**Fix**: Set the environment variable to your Ghidra installation:
```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.3
```
This must be set in the terminal where the daemon runs.

## JVM Out of Memory on Large Binaries

**Symptom**: Analysis hangs or crashes with Java heap space errors.

**Fix**: Increase JVM heap size before starting:
```bash
export _JAVA_OPTIONS="-Xmx8g"
ghidra-rpc start --project /tmp/project.gpr --headless
```
For very large binaries (>100MB), 8GB or more may be needed.

## Stale Socket File

**Symptom**: "Address already in use" or daemon won't start, but `status` shows not running.

**Fix**: Remove the stale socket file:
```bash
# Find the socket path
ghidra-rpc status --project /path/to/project.gpr
# Remove it
rm /tmp/ghidra-rpc-XXXXXXXX.sock
# Start again
ghidra-rpc start --project /path/to/project.gpr --headless
```

The daemon normally cleans up its socket on shutdown, but if it's killed (SIGKILL, power
loss), the socket file may remain.

On Windows the equivalent file is the endpoint descriptor recording the daemon's
loopback port and auth token, at
`%LOCALAPPDATA%\ghidra-rpc\ghidra-rpc-XXXXXXXX.sock`. `status` prints its path the
same way; delete it with `del` instead of `rm`. Unlike `/tmp`, that directory is not
cleared on reboot, so a descriptor left behind by a killed daemon persists — but you
normally do not need to remove it by hand: the next command finds the recorded port
dead and restarts the daemon, which rewrites the descriptor with a fresh port and
token.

## macOS Framework Python Issue

**Symptom**: GUI mode crashes immediately on macOS with AWT or Swing errors.

**Cause**: Ghidra's GUI needs macOS "framework Python" for proper Swing integration. The
daemon attempts to re-exec into framework Python automatically, but this can fail if:
- You're using a non-standard Python install
- The framework Python path doesn't exist

**Fix**: Try running with the system Python or a framework-aware install:
```bash
/usr/bin/python3 -m ghidra_rpc.cli start --project /tmp/project.gpr
```

Or use headless mode, which doesn't need framework Python:
```bash
ghidra-rpc start --project /tmp/project.gpr --headless
```

## GUI Restart Reports Timeout (or `ok: true` With Warning)

**Symptom**: `ghidra-rpc restart` in GUI mode returns a response with a `warning` field
instead of a clean `{"status": "restarted"}`, or (with an older version) exits with
`RestartTimeout`.

**Cause**: GUI startup (JVM boot → Ghidra window → project open) routinely takes 60–120 s
or more on a cold machine. The default poll timeout for headless mode (60 s) was too short.

**Behaviour since fix**: `restart` now defaults to **180 s** in GUI mode. If the socket
becomes responsive within that window you get `{"ok": true, "status": "restarted"}`. If
the daemon starts listening but has not yet responded to a ping within 180 s, you get:
```json
{"ok": true, "result": {"status": "started", "warning": "Daemon started but did not become fully responsive within 180 s …"}}
```
The daemon **is** running — simply retry your first command in a few seconds.

**Override the timeout** if your machine is especially slow:
```bash
ghidra-rpc restart --project /tmp/re.gpr --timeout 300
```

**If the response is `ok: false` with `RestartTimeout`** (socket file does not exist),
the background process failed to start. Check the log file whose path is printed in the
error message.

## GUI Not Appearing

**Symptom**: `ghidra-rpc start` without `--headless` seems to hang, no Ghidra window.

**Possible causes**:
1. **No display**: Running over SSH without X11 forwarding. Use `--headless` or set up X11.
2. **Wayland issues**: Some Wayland compositors don't work well with Java Swing. Try:
   ```bash
   export _JAVA_AWT_WM_NONREPARENTING=1
   ```
3. **Slow startup**: Ghidra's GUI can take 30-60 seconds to appear on first run. Check
   the daemon's stderr output for progress.

## Connection Timeout

**Symptom**: Commands hang for 2 minutes then fail.

**Cause**: The daemon is processing a heavy operation (large binary analysis, decompilation
of a very complex function).

**Fix**: Wait for the operation to complete. For initial analysis of large binaries, this
can take several minutes. You can check the daemon's stderr log for progress.

## "Binary not found" After Restart

**Symptom**: Commands that worked before fail with "Binary not found" after daemon restart.

**Cause**: In headless mode, binaries are re-imported into a new Ghidra project on restart.
The binary keys may differ.

**Fix**: Re-load the binary with `ghidra-rpc load <path>`. Use `ghidra-rpc list-binaries`
to see what's currently loaded, or `ghidra-rpc list-project-programs` to see what's
stored in the project.

## "Unexpected trailing text" on set-signature

**Symptom**: `set-signature` fails with "Unexpected trailing text" when you paste a C
prototype that ends with a semicolon.

**Fix**: ghidra-rpc now strips trailing semicolons automatically, so this should be
resolved. If you hit this on an older version, remove the trailing `;` from the
signature string.

## `list-binaries` Is Empty in GUI Mode

**Symptom**: `list-binaries` returns `{"binaries": []}` even though you imported a
binary.

**Cause**: In GUI mode, `list-binaries` shows programs open in a running Ghidra tool
(e.g. CodeBrowser). A program stored in the project but not opened in CodeBrowser
won't appear.

**Fix**: Use `ghidra-rpc list-project-programs` to see everything in the project repo.
Then open the program in CodeBrowser (double-click in Ghidra's Project window).

## `restart` Fails with "NoSession"

**Symptom**: `ghidra-rpc restart` fails with
`"No saved session for /path. Use 'ghidra-rpc start' first."`

**Cause**: `restart` needs a saved session (created by a previous `start`) to know
which mode (GUI / headless) to use.

**Fix**: Pass `--headless` to `restart` so it can create a fresh headless session
without requiring a prior start:
```bash
ghidra-rpc restart --project /tmp/re.gpr --headless
```

## Edits Not Visible After Reopening in Ghidra GUI

**Symptom**: You applied renames / comments via ghidra-rpc but they are not visible
when you open the project in the Ghidra GUI.

**Possible causes**:

1. **You opened the raw file instead of the project copy.** Ghidra can open a binary
   directly from disk (File → Open File) or from the Project window. Only the Project
   copy (e.g. `basic_code-501243`) contains the saved database changes. Always open
   from the Project window.

2. **You opened a different program name/version.** When ghidra-rpc imports a binary
   it appends a hash suffix (e.g. `basic_code-501243`). If you opened a program with
   a different name or suffix you will see different contents. Run
   `ghidra-rpc list-project-programs` to find the exact name.

3. **Two Ghidra instances on the same project.** Running a second Ghidra (not the one
   managed by ghidra-rpc) causes lock conflicts and can prevent saves. Stop the daemon
   before opening the project in a standalone Ghidra, or use the GUI managed by
   `ghidra-rpc start` (without `--headless`).

4. **The daemon crashed before saving.** On older versions, writes were committed to
   the in-memory database but not persisted to disk. The current version auto-saves
   after every write operation and on clean shutdown. If the daemon is killed with
   SIGKILL (e.g. `kill -9`), in-flight changes may be lost. Use `ghidra-rpc stop`
   for a clean shutdown.

**How to verify**: Run `ghidra-rpc functions <binary>` — if the renames are visible
there, the project database is up to date. If not, the changes were lost and need to
be reapplied.
