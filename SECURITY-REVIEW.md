# WSL Security Review

Commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## New findings (2026-07-01)

### Medium: Unauthenticated crash-dump injection via vsock port 50005

- **Location:** `src/windows/service/exe/WslCoreVm.cpp`
- **Attacker:** Any local Linux user in the WSL2 guest
- **Controlled input:** `LX_PROCESS_CRASH` metadata and arbitrary byte stream over vsock
- **Attack path:** Guest connects to `LX_INIT_UTILITY_VM_CRASH_DUMP_PORT` (50005) without authentication. Host impersonates the VM owner and writes attacker-controlled data to `%TEMP%\wsl-crashes\wsl-crash-*.dmp`.
- **Impact:** Disk exhaustion, planted crash dumps, and pollution of crash telemetry.
- **Remediation:** Authenticate vsock peers before accepting crash-dump streams; cap relay size.

### Medium: Unauthenticated non-elevated DrvFs access via Plan9 vsock port 50002

- **Location:** `src/linux/init/drvfs.cpp`
- **Attacker:** Any local Linux user in the WSL2 guest
- **Controlled input:** Direct vsock connection to port 50002 speaking Plan9/9P
- **Attack path:** Guest `UtilConnectVsock(50002)` mounts DrvFs without peer authentication. Host exposes the VM owner's Windows filesystem at medium integrity via `AllowSubPaths`.
- **Impact:** Cross-UID read/write of the owning Windows user's files in multi-user distros.
- **Remediation:** Bind DrvFs vsock endpoints to authenticated peers only.

### Medium: Unauthenticated init interop environment variable disclosure

- **Location:** `src/linux/init/config.cpp`
- **Attacker:** Any local Linux user in the WSL2 guest
- **Controlled input:** `LxInitMessageQueryEnvironmentVariable` requests against `/run/WSL/1_interop`
- **Attack path:** World-writable interop socket (`chmod 0777`) accepts unauthenticated queries. Init responds with values from its own environment (DISPLAY, WSLG paths, VM ID, etc.).
- **Impact:** Session topology and VM identity disclosure aiding follow-on attacks. Distinct from relay-process environment leak.
- **Remediation:** Authenticate interop peers or restrict socket permissions to the session owner.

### Medium: Machine-wide registry credential storage enables cross-user theft

- **Location:** `src/windows/wslc/services/WinCredStorage.cpp`
- **Attacker:** Another interactive Windows user on the same machine
- **Controlled input:** `wslc registry login` credentials stored with `CRED_PERSIST_LOCAL_MACHINE`
- **Attack path:** User A logs in to a container registry. Credentials persist machine-wide. User B enumerates `wslc-credential/*` via Credential Manager APIs and reuses the secrets.
- **Impact:** Cross-user theft of container-registry credentials on shared Windows hosts.
- **Remediation:** Use per-user persistence (`CRED_PERSIST_ENTERPRISE` / DPAPI file storage).

## Previously reported findings

| Severity | Title |
|----------|-------|
| High | World-writable interop socket enables cross-user Windows process creation |
| Medium | Unauthenticated interop socket allows reading victim relay environment variables |
| Medium | Unauthenticated login session creation for arbitrary users via interop socket |
| High | Unauthenticated elevated DrvFs access via fixed Plan9 admin vsock port |
| High | Unauthenticated virtiofs share management on vsock port 50004 |
| Medium | Unauthenticated localhost TCP relay via guest vsock listener |
