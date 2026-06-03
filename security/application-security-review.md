# Application Security Review

Repository: **WSL**
Scanned commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
Branch: `cursor/application-security-review-6a2c`

Validated medium-or-higher findings with end-to-end attack paths.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

- **Location:** `src/linux/init/util.cpp`
- **Attacker:** Local Linux user in same WSL distro as victim session
- **Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket
- **Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess
- **Impact:** Cross-user escalation to Windows code execution as victim identity
- **Remediation:** Restrict socket permissions; validate SO_PEERCRED on interop connections.
