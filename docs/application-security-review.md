# Application Security Review

Commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
Branch: `cursor/application-security-review-116d`

## Findings

### 1. [High] World-writable interop socket enables cross-user Windows process creation

- **Location:** `src/linux/init/util.cpp`
- **Attacker:** Local Linux user in the same WSL distro as a victim session
- **Controlled input:** `LxInitMessageCreateProcessUtilityVm` sent on the `/run/WSL` interop socket
- **Attack path:** Interop socket is created with mode `0777` and no peer UID check; messages are forwarded to Windows `CreateProcess` as the victim.
- **Impact:** Cross-user escalation to Windows code execution under the victim's identity.
- **Remediation:** Restrict socket permissions to the session owner, validate peer credentials, and reject cross-user interop clients.

### 2. [Medium] Non-elevated WSL processes can force elevated DrvFs mounts via WSL_DRVFS_ELEVATED

- **Location:** `src/linux/init/drvfs.cpp`
- **Attacker:** Local user with code execution in a non-elevated WSL2 distro on the same Windows account
- **Controlled input:** Environment variable `WSL_DRVFS_ELEVATED=1` before a drvfs mount
- **Attack path:** `IsDrvfsElevated` returns true from `getenv` before querying init via `LxInitMessageQueryDrvfsElevated`; `MountPlan9Share` then connects to the admin plan9 port when an elevated server is already running.
- **Impact:** Bypasses the documented elevated vs non-elevated DrvFs separation and grants elevated-token Windows file access from non-elevated Linux processes.
- **Remediation:** Ignore user-controlled `WSL_DRVFS_ELEVATED` after early boot; always query init/interop for elevation status at mount time.
