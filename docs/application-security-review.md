# Application Security Review

Commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
Branch: `cursor/application-security-review-7b43`

## Findings

### 1. [High] World-writable interop socket enables cross-user Windows process creation

- **Location:** `src/linux/init/util.cpp`
- **Attacker:** Local Linux user in same WSL distro
- **Controlled input:** LxInitMessageCreateProcessUtilityVm on interop socket
- **Attack path:** Socket chmod 0777 without peer UID check
- **Impact:** Windows code execution as victim
- **Remediation:** Restrict socket permissions and validate peer UID

### 2. [Medium] DrvFs elevation bypass via WSL_DRVFS_ELEVATED environment variable

- **Location:** `src/linux/init/drvfs.cpp`
- **Attacker:** Linux process after elevated DrvFs started
- **Controlled input:** WSL_DRVFS_ELEVATED=1 before mount
- **Attack path:** IsDrvfsElevated trusts getenv without elevation check
- **Impact:** Elevated Windows file access from non-elevated session
- **Remediation:** Verify elevation via interop only

### 3. [Medium] wslc registry credentials stored as machine-visible Credential Manager entries

- **Location:** `src/windows/wslc/services/WinCredStorage.cpp`
- **Attacker:** Another local Windows user
- **Controlled input:** Credentials from wslc registry login
- **Attack path:** CredWrite with CRED_PERSIST_LOCAL_MACHINE
- **Impact:** Cross-user registry credential theft
- **Remediation:** Use CRED_PERSIST_ENTERPRISE or per-user DPAPI file backend
