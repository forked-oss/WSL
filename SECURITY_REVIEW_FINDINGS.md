# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-02 (scheduled cron)
**Branch:** `cursor/application-security-review-bcf6`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in same WSL distro

**Controlled input:** LxInitMessageCreateProcessUtilityVm on 0777 interop socket

**Attack path:** No peer UID check; forwarded to Windows CreateProcess

**Impact:** Cross-user Windows code execution as victim identity

## 2. [MEDIUM] WSL_DRVFS_ELEVATED environment variable selects admin DrvFs token outside elevated mount namespace **[NEW this scan]**

**Location:** `src/linux/init/drvfs.cpp`

**Attacker:** Local Linux user with sudo after admin DrvFs initialized

**Controlled input:** WSL_DRVFS_ELEVATED=1 on mount

**Attack path:** IsDrvfsElevated trusts getenv before interop elevation query

**Impact:** Access elevated DrvFs files without elevated Windows session

## 3. [MEDIUM] Unauthenticated interop socket allows forced login sessions for arbitrary users **[NEW this scan]**

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux UID with systemd boot enabled

**Controlled input:** LxInitMessageCreateLoginSession with arbitrary Uid

**Attack path:** ConfigHandleInteropMessage runs login -f without peer check

**Impact:** Cross-user forced PAM/systemd session creation
