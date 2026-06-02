# Application Security Review Findings

Scanned commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

Validated medium, high, and critical issues with end-to-end attack paths.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in same WSL distro as victim session

**Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket

**Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess

**Impact:** Cross-user escalation to Windows code execution as victim identity

## 2. [MEDIUM] ListSessions COM API omits authorization leaking other users session metadata

**Location:** `src/windows/service/exe/WSLCSessionManager.cpp`

**Attacker:** Any authenticated Windows user who can invoke IWSLCSessionManager COM APIs

**Controlled input:** Unprivileged ListSessions COM call

**Attack path:** ListSessions enumerates all sessions without CheckTokenAccess while OpenSession enforces it

**Impact:** Cross-user disclosure of session IDs, creator PIDs, SIDs, and display names
