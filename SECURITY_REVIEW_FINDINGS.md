# Application Security Review Findings

Commit scanned: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## 1. High: Unauthenticated interop socket hijacking enables arbitrary Windows process execution

- Severity: High
- Primary location: `src/linux/init/config.cpp`
- Attacker: Any local Linux process inside the WSL2 distro VM when interop is enabled (default).
- Controlled input: Target interop socket path (`/run/WSL/<pid>_interop`), optional `WSL_INTEROP` environment variable, and `LxInitMessageCreateProcessUtilityVm` payload (Windows executable path, argv, cwd, environment).
- Attack path: Interop endpoints are world-accessible (`chmod 0777`). Any process can connect to another session's interop unix socket. `ConfigHandleInteropMessage` relays `LxInitMessageCreateProcessUtilityVm` to Windows over the victim session's `InteropChannel` with no peer-credential or ownership check. Windows `wslhost.exe` calls `CreateProcess` using the victim session owner's token.
- Impact: Cross-trust-boundary execution from Linux VM to arbitrary Windows process as the hijacked session's Windows user; privilege escalation when targeting an elevated WSL session. Secondary impact via `LxInitMessageQueryDrvfsElevated` enabling elevated drvfs access.
- Remediation: Restrict interop socket permissions to the owning UID; validate peer credentials with `SO_PEERCRED` before relaying privileged messages.
