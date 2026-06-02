# Application Security Review Findings

Scanned commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## High: World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in the same WSL distro as a victim session.

**Controlled input:** `LxInitMessageCreateProcessUtilityVm` sent to `/run/WSL` interop socket.

**Attack path:** Interop socket is `chmod 0777` with no peer UID check; message forwarded to Windows `CreateProcess` as the victim's identity.

**Impact:** Cross-user escalation to Windows code execution as victim identity.

**Remediation:** Restrict interop socket permissions and authenticate peer credentials before forwarding process-creation messages.

## High: Elevated DrvFs mount selectable by unprivileged Linux control of interop/env

**Location:** `src/linux/init/drvfs.cpp`

**Attacker:** Local Linux process in a WSL2 distro with filesystem mount capability (default WSL root satisfies this).

**Controlled input:** `WSL_DRVFS_ELEVATED=1`, and/or `WSL_INTEROP` aimed at another session's world-writable interop socket under `/run/WSL/`.

**Attack path:** Windows host starts (or has previously started) an elevated WSL session, which creates the admin DrvFs Plan9/VirtioFS backend bound to an elevated Windows token. Attacker runs from a non-elevated WSL shell. Path A: Attacker sets `WSL_DRVFS_ELEVATED=1` before invoking `mount.drvfs`; `IsDrvfsElevated()` trusts that environment variable with no caller authentication. Path B: Attacker sets `WSL_INTEROP=/run/WSL/<elevated_session_pid>_interop` (socket is mode `0777`), connects, and sends `LxInitMessageQueryDrvfsElevated`; handler returns the elevated session's flag with no peer-credential check. `MountPlan9()` → `MountPlan9Share(..., Admin=true)` connects to the admin Plan9 port. The Windows-side admin Plan9 server services file operations with the stored elevated token.

**Impact:** Cross-boundary privilege escalation—a non-elevated WSL/Linux context gains Windows-administrator-equivalent filesystem access for paths served by the elevated DrvFs backend, bypassing the UAC elevation boundary for file ACLs.

**Remediation:** Do not trust `WSL_DRVFS_ELEVATED` from unprivileged callers. Authenticate interop socket peers before returning elevation status. Restrict interop socket permissions.
