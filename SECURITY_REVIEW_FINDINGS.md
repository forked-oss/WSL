# Application Security Review Findings

Commit scanned: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## 1. High: World-writable interop socket enables cross-user Windows process creation

- Severity: High
- Primary location: `src/linux/init/util.cpp`
- Attacker: Local Linux user in the same WSL distro as a victim session.
- Controlled input: `LxInitMessageCreateProcessUtilityVm` on `/run/WSL` interop socket.
- Attack path: Interop socket `chmod 0777` with no peer UID check; message forwarded to Windows `CreateProcess`.
- Impact: Cross-user escalation to Windows code execution as the victim identity.
- Remediation: Restrict socket permissions and validate peer credentials before relaying create-process requests.

## 2. Medium: Unauthenticated forced login via world-writable init interop socket

- Severity: Medium (High in multi-user WSL with `[boot] systemd=true`)
- Primary location: `src/linux/init/config.cpp`
- Attacker: Any local Linux principal in a running WSL distro.
- Controlled input: `LX_INIT_CREATE_LOGIN_SESSION` message `Username` field.
- Attack path: Init interop listener mode `0777`; `LxInitMessageCreateLoginSession` handled without peer credential check, calling `execl("/bin/login", "/bin/login", "-f", Username, nullptr)`.
- Impact: Passwordless login as arbitrary local account when systemd boot init is enabled.
- Remediation: Restrict socket permissions and authenticate peers before `CreateLoginSession`.
- Prerequisite: `[boot] systemd=true` in `/etc/wsl.conf`.

## 3. Medium: DrvFs elevation bypass via trusted WSL_DRVFS_ELEVATED environment variable

- Severity: Medium
- Primary location: `src/linux/init/drvfs.cpp`
- Attacker: Linux process with `mount -t drvfs` capability in the WSL mount namespace.
- Controlled input: `WSL_DRVFS_ELEVATED=1` environment variable before drvfs mount.
- Attack path: `IsDrvfsElevated()` returns true from env without host elevation query; mount uses admin Plan9 share when previously initialized in VM lifetime.
- Impact: Elevated Windows file access from a non-elevated WSL session.
- Remediation: Query host interop for authoritative elevation state instead of trusting guest env.
