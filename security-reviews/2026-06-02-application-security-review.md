# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-1987`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in same WSL distro

**Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket

**Attack path:** Interop socket chmod 0777 with no peer UID check; forwarded to Windows CreateProcess

**Impact:** Windows code execution as victim identity

## 2. [MEDIUM] Unauthenticated init interop socket allows forced login -f for arbitrary Linux users on systemd distros

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux UID with boot.systemd=true

**Controlled input:** LX_INIT_CREATE_LOGIN_SESSION with victim Uid

**Attack path:** ConfigHandleInteropMessage calls CreateLoginSession with login -f without peer auth

**Impact:** Linux lateral movement via authenticated sessions

## 3. [MEDIUM] WSL container registry credentials stored with machine-wide persistence exposing secrets to other Windows users

**Location:** `src/windows/wslc/services/WinCredStorage.cpp`

**Attacker:** Another standard Windows user on same machine

**Controlled input:** wslc-credential/ targets via CredEnumerateW

**Attack path:** CredWriteW with CRED_PERSIST_LOCAL_MACHINE

**Impact:** Cross-user registry credential theft
