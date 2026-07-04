# Application Security Review Findings

Repository: [WSL](https://github.com/forked-oss/WSL)

Total active findings: 10

## World-writable interop socket enables cross-user Windows process creation

**Severity:** high

**Location:** src/linux/init/util.cpp

**Attacker:** Local Linux user in same WSL distro as victim session

**Controlled input:** LxInitMessageCreateProcessUtilityVm on /run/WSL interop socket

**Attack path:** Interop socket chmod 0777 with no peer UID check; message forwarded to Windows CreateProcess

**Impact:** Cross-user escalation to Windows code execution as victim identity

## Unauthenticated interop socket allows reading victim relay environment variables including proxy credentials

**Severity:** medium

**Location:** src/linux/init/config.cpp

**Attacker:** Local Linux user in same WSL2 VM with access to victim interop socket

**Controlled input:** Victim interop socket path and arbitrary environment variable names such as HTTP_PROXY

**Attack path:** LxInitMessageQueryEnvironmentVariable calls UtilGetEnvironmentVariable via getenv on relay process with no peer-credential check

**Impact:** Information disclosure of session-scoped secrets including Windows-injected proxy URLs with embedded credentials

## Unauthenticated login session creation for arbitrary users via interop socket when systemd boot is enabled

**Severity:** medium

**Location:** src/linux/init/config.cpp

**Attacker:** Any local unprivileged user in WSL instance when boot systemd true in wsl.conf

**Controlled input:** LX_INIT_CREATE_LOGIN_SESSION username and UID/GID over world-writable interop socket

**Attack path:** Handler accepts CreateLoginSession without peer check and execl login -f to skip PAM activating user@Uid.service

**Impact:** Unauthenticated activation of systemd login sessions for any user including root

## Unauthenticated elevated DrvFs access via fixed Plan9 admin vsock port bypassing IsDrvfsElevated

**Severity:** high

**Location:** src/linux/init/drvfs.cpp

**Attacker:** Local Linux user in the WSL2 VM

**Controlled input:** Direct vsock connection to LX_INIT_UTILITY_VM_PLAN9_DRVFS_ADMIN_PORT 50003

**Attack path:** IsDrvfsElevated gates mount.drvfs admin path but any guest process can UtilConnectVsock to fixed admin port 50003 and mount elevated DrvFs via 9p fd transport without peer authentication

**Impact:** Read and write Windows files available to elevated DrvFs share bypassing DrvFs elevation policy in multi-user instances

## Unauthenticated virtiofs share management on vsock port 50004 with guest-controlled Admin flag

**Severity:** high

**Location:** src/linux/init/drvfs.cpp

**Attacker:** Local Linux user in the WSL2 VM

**Controlled input:** LX_INIT_ADD_VIRTIOFS_SHARE_MESSAGE with Admin=true and attacker-chosen Windows path

**Attack path:** Guest connects to virtiofs vsock port without credentials; host WslCoreVm trusts guest Admin bit and impersonates m_adminDrvfsToken when Admin is true

**Impact:** Arbitrary Windows path exposure through virtiofs with elevated token bypassing DrvFs elevation policy

## Unauthenticated localhost TCP relay via guest vsock listener

**Severity:** medium

**Location:** src/linux/init/localhost.cpp

**Attacker:** Local Linux user in the same WSL2 guest

**Controlled input:** LxInitMessageStartSocketRelay with guest-supplied TCP port on 127.0.0.1

**Attack path:** localhost relay accepts vsock connections and connects to 127.0.0.1 attacker port with no peer authentication

**Impact:** Access to services bound only to localhost in another user session bypassing localhost isolation

## Unauthenticated crash-dump injection via vsock port 50005

**Severity:** medium

**Location:** src/windows/service/exe/WslCoreVm.cpp

**Attacker:** Any local Linux user in the WSL2 guest

**Controlled input:** LX_PROCESS_CRASH metadata and arbitrary byte stream over vsock

**Attack path:** Guest connects to LX_INIT_UTILITY_VM_CRASH_DUMP_PORT (50005) without authentication. Host impersonates the VM owner and writes attacker-controlled data to %TEMP%\wsl-crashes\wsl-crash-*.dmp.

**Impact:** Disk exhaustion, planted crash dumps, and pollution of crash telemetry.

## Unauthenticated non-elevated DrvFs access via Plan9 vsock port 50002

**Severity:** medium

**Location:** src/linux/init/drvfs.cpp

**Attacker:** Any local Linux user in the WSL2 guest

**Controlled input:** Direct vsock connection to port 50002 speaking Plan9/9P

**Attack path:** Guest UtilConnectVsock(50002) mounts DrvFs without peer authentication. Host exposes the VM owner's Windows filesystem at medium integrity via AllowSubPaths.

**Impact:** Cross-UID read/write of the owning Windows user's files in multi-user distros.

## Unauthenticated init interop environment variable disclosure

**Severity:** medium

**Location:** src/linux/init/config.cpp

**Attacker:** Any local Linux user in the WSL2 guest

**Controlled input:** LxInitMessageQueryEnvironmentVariable requests against /run/WSL/1_interop

**Attack path:** World-writable interop socket (chmod 0777) accepts unauthenticated queries. Init responds with values from its own environment (DISPLAY, WSLG paths, VM ID, etc.).

**Impact:** Session topology and VM identity disclosure aiding follow-on attacks. Distinct from relay-process environment leak.

## Machine-wide registry credential storage enables cross-user theft

**Severity:** medium

**Location:** src/windows/wslc/services/WinCredStorage.cpp

**Attacker:** Another interactive Windows user on the same machine

**Controlled input:** wslc registry login credentials stored with CRED_PERSIST_LOCAL_MACHINE

**Attack path:** User A logs in to a container registry. Credentials persist machine-wide. User B enumerates wslc-credential/* via Credential Manager APIs and reuses the secrets.

**Impact:** Cross-user theft of container-registry credentials on shared Windows hosts.
