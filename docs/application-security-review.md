# Application Security Review

Automated security findings for **WSL**.

- **Generated:** 2026-06-25 02:30 UTC
- **Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
- **Active findings:** 3

## Summary

| Severity | Count |
|----------|------:|
| high | 1 |
| medium | 2 |

## Findings

### 1. World-writable interop socket enables cross-user Windows process creation

- **Severity:** high
- **Status:** active
- **Location:** src/linux/init/util.cpp
- **Commit:** 210b7640f7d1eb7da2cf4b4c47b6d1babd63b502
- **Detected (PST):** 2026-06-01T00:12:00-07:00
- **Attacker:** Local Linux user in same WSL distro as victim session
- **Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket
- **Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess
- **Impact:** Cross-user escalation to Windows code execution as victim identity

### 2. Unauthenticated interop socket allows reading victim relay environment variables including proxy credentials

- **Severity:** medium
- **Status:** active
- **Location:** src/linux/init/config.cpp
- **Commit:** 210b7640f7d1eb7da2cf4b4c47b6d1babd63b502
- **Detected (PST):** 2026-06-12T19:00:22-07:00
- **Reported:** https://github.com/forked-oss/WSL/pull/27
- **Attacker:** Local Linux user in same WSL2 VM with access to victim interop socket
- **Controlled input:** Victim interop socket path and arbitrary environment variable names such as HTTP_PROXY
- **Attack path:** LxInitMessageQueryEnvironmentVariable calls UtilGetEnvironmentVariable via getenv on relay process with no peer-credential check
- **Impact:** Information disclosure of session-scoped secrets including Windows-injected proxy URLs with embedded credentials

### 3. Unauthenticated login session creation for arbitrary users via interop socket when systemd boot is enabled

- **Severity:** medium
- **Status:** active
- **Location:** src/linux/init/config.cpp
- **Commit:** 210b7640f7d1eb7da2cf4b4c47b6d1babd63b502
- **Detected (PST):** 2026-06-13T19:25:43-07:00
- **Reported:** https://github.com/forked-oss/WSL/pull/28
- **Attacker:** Any local unprivileged user in WSL instance when boot systemd true in wsl.conf
- **Controlled input:** LX_INIT_CREATE_LOGIN_SESSION username and UID/GID over world-writable interop socket
- **Attack path:** Handler accepts CreateLoginSession without peer check and execl login -f to skip PAM activating user@Uid.service
- **Impact:** Unauthenticated activation of systemd login sessions for any user including root
