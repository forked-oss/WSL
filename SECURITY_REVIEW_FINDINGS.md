# Application Security Review Findings

Commit scanned: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## 1. Medium: Guest-controlled env var bypasses DrvFS elevation gate

- Severity: Medium
- Primary location: `src/linux/init/drvfs.cpp`
- Attacker: Any process inside the WSL guest that can set environment variables and invoke a DrvFS mount (typically root via `mount -t drvfs` / `mount.drvfs`). A guest process can also connect directly to the admin HV-socket port without using the environment variable.
- Controlled input: `WSL_DRVFS_ELEVATED=1` in the process environment, or a direct connection to `LX_INIT_UTILITY_VM_PLAN9_DRVFS_ADMIN_PORT` (50003).
- Attack path: If the host user previously started WSL from an elevated Windows context in the current utility-VM lifetime, `WslCoreVm::AddDrvFsShare(true, UserToken)` creates the elevated DrvFS Plan9 server on HV socket port 50003. The same user later runs WSL from a non-elevated Windows context. Guest code sets `WSL_DRVFS_ELEVATED=1` and runs `mount.drvfs` (`MountDrvfsEntry` passes an empty `Admin` optional, so `IsDrvfsElevated()` runs). `IsDrvfsElevated()` returns true from the environment variable before querying the interop server (`LxInitMessageQueryDrvfsElevated`), which would report non-elevation. `MountPlan9Share` connects to port 50003 instead of 50002, obtaining file access through the elevated Plan9 server. HV-socket ports have no client authentication. The variable is documented in `config.cpp` for early boot when interop is unavailable, but it is honored for runtime `mount.drvfs` invocations that inherit caller environment.
- Impact: Privilege escalation within the Windows-user boundary: a non-elevated WSL session can read or write host files using the elevated DrvFS server token, bypassing the intended split between elevated and non-elevated DrvFS namespaces.
- Remediation: Restrict trust of `WSL_DRVFS_ELEVATED` to init-controlled early boot only; always use interop `QueryDrvfsElevated` for user-triggered mounts. Bind admin Plan9/HV-socket endpoints to a per-session secret issued only to elevated host sessions.
