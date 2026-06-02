# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-0a64`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in same WSL distro

**Controlled input:** LxInitMessageCreateProcessUtilityVm on interop socket

**Attack path:** chmod 0777 socket without peer UID check; relayed to Windows CreateProcess

**Impact:** Windows code execution as WSL session owner

**Remediation:** Use SO_PEERCRED and restrict socket permissions

## 2. [MEDIUM] WSLC volume mount symlink TOCTOU when host bind source path does not exist

**Location:** `src/windows/wslcsession/WSLCContainer.cpp`

**Attacker:** Concurrent writer to mount parent directory

**Controlled input:** Non-existent HostPath at create time

**Attack path:** Unresolved path kept; symlink at mount time shares attacker target

**Impact:** Unintended host directory exposed to container

**Remediation:** Create and canonicalize mount path atomically before share

## 3. [MEDIUM] Unauthenticated interop socket can force login sessions for arbitrary local users

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any Linux UID with interop and BootInit

**Controlled input:** LxInitMessageCreateLoginSession username and uid

**Attack path:** CreateLoginSession runs login -f without connector authorization

**Impact:** Linux-local lateral movement via forced user sessions

**Remediation:** Authenticate interop clients to target account
