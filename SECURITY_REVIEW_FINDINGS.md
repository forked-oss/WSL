# Application Security Review Findings

Scanned commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## High: Unauthenticated interop UNIX socket allows cross-user Windows process execution

**Location:** `src/linux/init/util.cpp`

**Attacker:** Local Linux user in the same WSL2 distro

**Controlled input:** LxInitMessageCreateProcessUtilityVm payload on world-writable /run/WSL/*_interop socket

**Attack path:** Interop socket chmod 0777 with no SO_PEERCRED check; ConfigHandleInteropMessage forwards to Windows CreateProcessVmMode as WSL owner's Windows token

**Impact:** Cross-user execution of arbitrary Windows binaries as the WSL owner's Windows identity

**Remediation:** Validate connecting Linux UID matches session owner; restrict interop socket permissions.

## Medium: Unauthenticated VirtioFS vsock RPC allows arbitrary Windows host path sharing

**Location:** `src/linux/init/drvfs.cpp`

**Attacker:** Local process in WSL2 utility VM with Linux root for mount step

**Controlled input:** LxInitMessageAddVirtioFsDevice with attacker-chosen Windows path and Admin=true

**Attack path:** Any caller opens AF_VSOCK to port 50004; WslCoreVm AddVirtioFsShare exports path under owner/admin Windows token without caller auth

**Impact:** Arbitrary host directory export readable/writable under elevated Windows ACL view

**Remediation:** Bind VirtioFS RPC to authenticated session owner before AddVirtioFsShare.
