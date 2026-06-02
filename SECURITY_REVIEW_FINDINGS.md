# Application Security Review Findings

Commit scanned: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## 1. High: Unauthenticated interop Unix socket allows arbitrary Windows process creation

- Severity: High
- Primary location: `src/linux/init/util.cpp`
- Attacker: Any local Linux UID inside a running WSL2 utility-VM distro, including a secondary unprivileged Linux account in a multi-user distro.
- Controlled input: `LxInitMessageCreateProcessUtilityVm` message fields: Windows executable path, command line, working directory, environment, and vsock port for stdio.
- Attack path: Interop sockets are chmod `0777` under `/run/WSL/`; any connector can send `LxInitMessageCreateProcessUtilityVm`; `ConfigHandleInteropMessage` forwards to host hvsocket; `CreateProcessVmMode` runs `CreateProcessW` with attacker-supplied parameters under the WSL session Windows user token. No `SO_PEERCRED` or UID checks on accept.
- Impact: Cross-boundary arbitrary Windows command execution as the distro-owning Windows user from any local Linux account.
- Remediation: Restrict interop socket permissions to session owner; validate peer credentials on accept; scope create-process messages to authorized session descendants.

## 2. Medium: Unauthenticated interop socket allows passwordless login -f for arbitrary users on systemd distros

- Severity: Medium
- Primary location: `src/linux/init/config.cpp`
- Attacker: Any local Linux UID inside a WSL2 distro with BootInit/systemd enabled.
- Controlled input: `LxInitMessageCreateLoginSession` fields: `Username`, `Uid`, `Gid`.
- Attack path: Attacker connects to world-writable init interop socket at `/run/WSL/1_interop`; `ConfigHandleInteropMessage` accepts `LxInitMessageCreateLoginSession` when `BootInit` is true; `CreateLoginSession` runs `execl("/bin/login", "/bin/login", "-f", Username, nullptr)` without authenticating the connector.
- Impact: Passwordless Linux login sessions for arbitrary local accounts, activating that user's systemd user slice and associated user-level infrastructure.
- Remediation: Authenticate interop connections and restrict login-session creation to authorized session leaders.
