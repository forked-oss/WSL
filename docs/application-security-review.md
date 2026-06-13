# Application Security Review — WSL

**Scanned commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Review date:** 2026-06-12 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer triage; follow each project's security disclosure process before public discussion.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

- **Location:** `src/linux/init/util.cpp`
- **Attacker:** Local Linux user in same WSL distro as victim session
- **Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket
- **Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess
- **Impact:** Cross-user escalation to Windows code execution as victim identity

## 2. [HIGH] DrvFs elevated namespace bypass via guest-controlled Admin flag on virtiofs

- **Location:** `src/windows/service/exe/WslCoreVm.cpp`
- **Attacker:** Any process inside the WSL2 utility VM
- **Controlled input:** LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE.Admin=true and arbitrary Windows path
- **Attack path:** VirtioFsWorker passes guest Admin bit to AddVirtioFsShare which selects m_adminDrvfsToken without caller identity check
- **Impact:** Non-elevated Linux namespace gains elevated Windows-token file access bypassing DrvFs isolation

## 3. [HIGH] DrvFs elevation bypass via direct connection to admin Plan9 vsock port

- **Location:** `src/linux/init/drvfs.cpp`
- **Attacker:** Any guest VM process
- **Controlled input:** Vsock connect to LX_INIT_UTILITY_VM_PLAN9_DRVFS_ADMIN_PORT (50003)
- **Attack path:** Host exposes admin and user Plan9 servers on fixed vsock ports with no authentication on accept
- **Impact:** Elevated-token Windows file access without being in elevated Linux mount namespace

## 4. [MEDIUM] WSL_DRVFS_ELEVATED environment variable trusted for DrvFs elevation

- **Location:** `src/linux/init/drvfs.cpp`
- **Attacker:** Process controlling environment before DrvFs mount
- **Controlled input:** WSL_DRVFS_ELEVATED=1 environment variable
- **Attack path:** IsDrvfsElevated checks getenv before interop; attacker sets flag and triggers mount.drvfs with admin path
- **Impact:** Software elevation of DrvFs mounts without host validation of caller elevation

## 5. [MEDIUM] WSLC session IPC grants all elevated Windows admins access to every session

- **Location:** `src/windows/service/exe/WSLCSessionManager.cpp`
- **Attacker:** Windows principal with elevated administrator token on shared host
- **Controlled input:** WSLC session manager COM calls against other users sessions
- **Attack path:** CheckTokenAccess returns S_OK for any elevated token without per-session ACL
- **Impact:** Cross-user WSLC session enumeration and control on multi-user Windows hosts

## 6. [MEDIUM] Unauthenticated interop socket allows reading victim relay environment variables including proxy credentials

- **Location:** `src/linux/init/config.cpp`
- **Attacker:** Local Linux user in same WSL2 VM with access to victim interop socket
- **Controlled input:** Victim interop socket path and arbitrary environment variable names such as HTTP_PROXY
- **Attack path:** LxInitMessageQueryEnvironmentVariable calls UtilGetEnvironmentVariable via getenv on relay process with no peer-credential check
- **Impact:** Information disclosure of session-scoped secrets including Windows-injected proxy URLs with embedded credentials
