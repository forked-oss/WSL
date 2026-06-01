# Application Security Review Findings

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-01 (scheduled automation)

Validated medium, high, and critical issues with end-to-end attack paths.

## World-writable interop socket enables cross-user Windows process creation

- **Severity:** high
- **Location:** `src/linux/init/util.cpp`
- **Attacker:** Local Linux user in same distro
- **Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket
- **Attack path:** chmod 0777 and no peer UID check; forwards to Windows CreateProcess
- **Impact:** Cross-user Windows code execution as victim

## DrvFs mount impersonation via WSL_INTEROP hijacks elevated Windows file access **[NEW THIS SCAN]**

- **Severity:** medium
- **Location:** `src/linux/init/drvfs.cpp`
- **Attacker:** Local Linux user
- **Controlled input:** WSL_INTEROP to victim elevated session socket
- **Attack path:** IsDrvfsElevated queries victim session; mounts admin virtiofs backend
- **Impact:** Access elevated-only Windows paths

## WSLC registry credentials stored with machine-wide persistence readable by any local Windows user **[NEW THIS SCAN]**

- **Severity:** medium
- **Location:** `src/windows/wslc/services/WinCredStorage.cpp`
- **Attacker:** Any local Windows user
- **Controlled input:** CredEnumerate on wslc-credential/ prefix
- **Attack path:** CRED_PERSIST_LOCAL_MACHINE on CredWriteW
- **Impact:** Cross-user registry credential theft

