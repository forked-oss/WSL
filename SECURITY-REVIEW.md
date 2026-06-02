# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-02

## Summary

**1** validated finding(s) at medium severity or above.

### 1. [HIGH] Unauthenticated cross-user access to WSL interop Unix socket enables arbitrary Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local unprivileged Linux user in the same WSL2 distro (different UID from session owner), with interop.enabled=true (default)

**Controlled input:** LxInitMessageCreateProcessUtilityVm payload: Windows executable path, command-line arguments, optional environment block, and guest vsock port

**Attack path:** Attacker connects to world-writable /run/WSL/*_interop socket without peer credential check; ConfigHandleInteropMessage forwards CreateProcessUtilityVm to Windows host which launches process as distro owner

**Impact:** Cross-UID privilege escalation to arbitrary non-elevated Windows code execution as the Windows user who owns the WSL installation

**Remediation:** Apply input validation and authorization at the trust boundary; use parameterized APIs and post-resolution permission checks where applicable.
