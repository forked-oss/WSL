# Application Security Review — WSL

Scanned commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
Detected: 2026-06-02T03:19:18-07:00

Validated medium, high, and critical findings with end-to-end attack paths.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in same WSL distro as victim session

**Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket

**Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess

**Impact:** Cross-user escalation to Windows code execution as victim identity

## 2. [HIGH] Unauthenticated interop IPC allows arbitrary login session creation via login -f

**Location:** `src/linux/init/util.cpp`

**Attacker:** Any local Linux user in a WSL2 distro with systemd enabled

**Controlled input:** LxInitMessageCreateLoginSession Username and Uid fields over world-writable interop socket

**Attack path:** Attacker connects to /run/WSL/1_interop (chmod 0777) and sends CreateLoginSession for root; init runs execl login -f without peer auth

**Impact:** Local privilege escalation via authenticated root systemd user session without password

## 3. [MEDIUM] WSL_DRVFS_ELEVATED=1 bypasses elevated-mount authorization gate

**Location:** `src/linux/init/drvfs.cpp`

**Attacker:** Local Linux process in utility VM after admin previously launched WSL elevated

**Controlled input:** WSL_DRVFS_ELEVATED=1 environment variable before drvfs mount

**Attack path:** IsDrvfsElevated returns true from env var without interop elevation check; MountPlan9Share uses admin port 50003

**Impact:** Non-elevated WSL processes access elevated DrvFs share and read/write host files with elevated-token ACL semantics
