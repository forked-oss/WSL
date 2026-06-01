# Application Security Review

**Branch:** `cursor/application-security-review-8f44`  
**Commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
**Reviewed:** 2026-06-01

## Findings

### [HIGH] World-writable interop Unix socket allows unauthenticated Windows process creation

| Field | Detail |
|-------|--------|
| **Location** | `src/linux/init/util.cpp` |
| **Attacker** | Any local Linux principal in the WSL VM that can connect to the interop Unix socket (secondary distro users, container workloads) |
| **Controlled input** | `LxInitMessageCreateProcessUtilityVm` payload: Windows executable path, argv, environment |
| **Attack path** | Interop socket is `chmod 0777`. Attacker connects and sends create-process messages. `init` forwards to `wslhost`, which calls `CreateProcess` on Windows as the WSL session owner without peer authentication. |
| **Impact** | Cross-boundary code execution on the Windows host as the WSL owner. |
| **Remediation** | Restrict socket to owning user (`0600`); authenticate clients with `SO_PEERCRED`; add session binding and message integrity checks. |

### [HIGH] World-accessible /dev/lxbus enables cross-user Linux→Windows CreateProcess

| Field | Detail |
|-------|--------|
| **Location** | `src/linux/init/config.cpp` |
| **Attacker** | Any Linux UID with access to `/dev/lxbus` (mode 0666) |
| **Controlled input** | `LX_INIT_CREATE_NT_PROCESS` message with arbitrary Windows executable path |
| **Attack path** | Attacker opens `/dev/lxbus`, connects, and sends create-process messages with paths not subject to `WslPathTranslate`. `wslhost` creates the process as the distro owner's Windows token. |
| **Impact** | Secondary Linux users execute arbitrary Windows programs as the distro owner. |
| **Remediation** | Remove world-writable lxbus; enforce per-UID authorization; validate executable paths. |
