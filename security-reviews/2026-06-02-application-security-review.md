# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-5025`

## Summary

This review documents **2** validated finding(s) at medium severity or above.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in the same WSL distro as a victim session, or any process that can connect to `/run/WSL/*_interop`

**Controlled input:** `LxInitMessageCreateProcessUtilityVm` with attacker-chosen Windows executable path and command line

**Attack path:** Interop socket is created with `chmod(..., 0777)`; `ConfigHandleInteropMessage` accepts connections without peer UID validation and forwards create-process messages to Windows `CreateProcessW`

**Impact:** Cross-user escalation to arbitrary Windows code execution as the victim WSL session owner

**Remediation:** Restrict interop socket permissions to the session owner (for example mode `0700`) and validate peer credentials on every connection.

## 2. [HIGH] Unauthenticated CreateLoginSession enables login as arbitrary Linux user

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux principal in the WSL VM when `boot.systemd=true` in `/etc/wsl.conf`

**Controlled input:** `LxInitMessageCreateLoginSession` with attacker-chosen `Username` (for example `root`)

**Attack path:** World-writable `/run/WSL/1_interop` accepts unauthenticated messages; the handler runs `login -f` without validating caller identity

**Impact:** Local privilege escalation to an arbitrary Linux account, including root, with a full login session and user runtime directories

**Remediation:** Require peer authentication for login-session creation and bind the interop socket to the init owner only.
