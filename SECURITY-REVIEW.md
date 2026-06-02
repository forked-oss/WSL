# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-02

## Summary

**3** validated finding(s) at medium severity or above.

### 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in same WSL distro as victim session

**Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket

**Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess

**Impact:** Cross-user escalation to Windows code execution as victim identity

**Remediation:** Apply input validation and authorization at the trust boundary; use parameterized APIs and post-resolution permission checks where applicable.

### 2. [MEDIUM] Unauthenticated systemd login-session creation via world-writable init interop socket

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux UID in a WSL2 distro with systemd boot enabled

**Controlled input:** LxInitMessageCreateLoginSession with attacker-chosen Username and Uid over /run/WSL/1_interop

**Attack path:** Init interop socket is chmod 0777 with no peer credential check; ConfigHandleInteropMessage accepts CreateLoginSession and runs login -f as root for any UID

**Impact:** Authentication bypass creating another user systemd login session without credentials in multi-user distros

**Remediation:** Apply input validation and authorization at the trust boundary; use parameterized APIs and post-resolution permission checks where applicable.

### 3. [MEDIUM] Unauthenticated elevated VirtIO-FS share creation over HV socket bypasses DrvFs elevation boundary

**Location:** `src/windows/service/exe/WslCoreVm.cpp`

**Attacker:** Local Linux process in WSL utility VM with mount capability

**Controlled input:** LxInitMessageAddVirtioFsDevice with Admin=true and attacker-chosen Windows path on vsock port 50004

**Attack path:** VirtioFsWorker accepts unauthenticated HV socket requests and AddVirtioFsShare uses m_adminDrvfsToken when Admin=true regardless of caller elevation

**Impact:** Non-elevated guest processes obtain host file access normally reserved for elevated DrvFs context

**Remediation:** Apply input validation and authorization at the trust boundary; use parameterized APIs and post-resolution permission checks where applicable.
