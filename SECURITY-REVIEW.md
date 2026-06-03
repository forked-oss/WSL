# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-03

## Summary

**5** validated finding(s) at medium severity or above.

### 1. [HIGH] Unauthenticated interop UNIX socket allows arbitrary Windows process creation as session owner

**Location:** `src/linux/init/util.cpp`

**Attacker:** Any local Linux principal in the WSL VM (including a different Linux user in the same distro) with interop enabled

**Controlled input:** `LxInitMessageCreateProcessUtilityVm` payload (Windows executable path, argv, cwd, environment) sent to `/run/WSL/<pid>_interop`

**Attack path:** Interop sockets are `chmod 0777`; the accept loop has no `SO_PEERCRED` or UID check; `ConfigHandleInteropMessage` forwards `CreateProcessUtilityVm` to the session hvsocket; Windows `CreateProcessW` runs under the WSL session owner's token, not the connecting Linux UID.

**Impact:** Cross-user auth bypass: a low-privilege Linux user can launch arbitrary Windows binaries with the victim's Windows identity.

**Remediation:** Restrict socket permissions to the owning UID; validate peer credentials on accept; bind process creation to the authenticated Linux principal.

### 2. [HIGH] Guest-controlled Admin flag on virtiofs HV socket creates elevated Windows file shares

**Location:** `src/linux/init/drvfs.cpp`

**Attacker:** Any process inside the WSL utility VM that can open AF_VSOCK to the host

**Controlled input:** `LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE.Admin` boolean and Windows path (e.g. `C:\`)

**Attack path:** Guest sends `LxInitMessageAddVirtioFsDevice` with `Admin=true` over vsock port 50004 without authentication; host `AddVirtioFsShare` selects `m_adminDrvfsToken` when `Admin` is true without verifying caller elevation.

**Impact:** Bypass of elevated vs non-elevated DrvFs separation; access to Windows paths readable only with an elevated token from a non-elevated WSL session.

**Remediation:** Verify requesting process elevation on the host before honoring `Admin=true`; authenticate vsock virtiofs share requests.

### 3. [MEDIUM] WSL_DRVFS_ELEVATED environment variable bypasses DrvFs elevation query

**Location:** `src/linux/init/drvfs.cpp`

**Attacker:** Linux root (or any principal that can invoke `mount.drvfs`)

**Controlled input:** Environment variable `WSL_DRVFS_ELEVATED=1` before calling `mount.drvfs`

**Attack path:** `IsDrvfsElevated` returns true from `getenv` without querying interop/wslservice; `MountDrvfsEntry` mounts with the elevated virtiofs server tag.

**Impact:** Linux-side privilege escalation across the Windows elevation boundary in non-elevated WSL sessions.

**Remediation:** Honor `WSL_DRVFS_ELEVATED` only during trusted init boot paths, not in user-invoked mount helpers.

### 4. [MEDIUM] Unauthenticated LxInitMessageCreateLoginSession forces login -f for arbitrary users

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux user who can connect to the WSL init interop socket

**Controlled input:** `LX_INIT_CREATE_LOGIN_SESSION` username and UID fields

**Attack path:** Unauthenticated interop accept; handler only checks `BootInit` and `InitPid==getpid()`; `CreateLoginSession` runs `execl("/bin/login", "-f", Username)` without authenticating the connector.

**Impact:** Unauthenticated creation of login sessions for arbitrary users (including root) via `login -f`.

**Remediation:** Require peer credential validation; restrict `CreateLoginSession` to trusted session-leader callers.

### 5. [MEDIUM] Interop socket environment query leaks init/session environment to any connector

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux user in the VM

**Controlled input:** Environment variable name in `LxInitMessageQueryEnvironmentVariable`

**Attack path:** Unauthenticated handler calls `getenv` in init/session context and returns the value; `UtilGetEnvironmentVariable` may cache results via `setenv`.

**Impact:** Information disclosure of environment variables visible to init/session leader (paths, feature flags, potentially secrets).

**Remediation:** Authenticate interop clients; restrict environment queries to the owning session.
