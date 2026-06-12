# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-11 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.

## [HIGH] World-writable interop socket enables cross-user Windows process creation

- **Location:** `src/linux/init/util.cpp`
- **Attacker:** Local Linux user
- **Controlled input:** LxInitMessageCreateProcessUtilityVm
- **Attack path:** chmod 0777 interop socket without peer UID check
- **Impact:** Cross-user Windows code execution

## [HIGH] Guest-controlled virtiofs Admin flag bypasses elevation [NEW]

- **Location:** `src/windows/service/exe/WslCoreVm.cpp`
- **Attacker:** Linux process in utility VM
- **Controlled input:** Admin=true on vsock port 50004
- **Attack path:** Guest-supplied Admin selects m_adminDrvfsToken
- **Impact:** Elevated Windows file access from non-elevated session

## [MEDIUM] World-writable interop socket forced login -f [NEW]

- **Location:** `src/linux/init/config.cpp`
- **Attacker:** Local Linux user with systemd boot
- **Controlled input:** CreateLoginSession message
- **Attack path:** No peer credential check; execl login -f arbitrary user
- **Impact:** Authentication bypass for session creation
