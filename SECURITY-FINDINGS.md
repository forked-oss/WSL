# Application Security Review — WSL

**Scan commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`  
**Review date:** 2026-07-03 (PST)

No new findings this scan.

## Active findings inventory

| Severity | Location | Title |
|----------|----------|-------|
| high | src/linux/init/util.cpp | World-writable interop socket enables cross-user Windows process creation |
| medium | src/linux/init/config.cpp | Unauthenticated interop socket allows reading victim relay environment variables including proxy credentials |
| medium | src/linux/init/config.cpp | Unauthenticated login session creation for arbitrary users via interop socket when systemd boot is enabled |
| high | src/linux/init/drvfs.cpp | Unauthenticated elevated DrvFs access via fixed Plan9 admin vsock port bypassing IsDrvfsElevated |
| high | src/linux/init/drvfs.cpp | Unauthenticated virtiofs share management on vsock port 50004 with guest-controlled Admin flag |
| medium | src/linux/init/localhost.cpp | Unauthenticated localhost TCP relay via guest vsock listener |
| medium | src/windows/service/exe/WslCoreVm.cpp | Unauthenticated crash-dump injection via vsock port 50005 |
| medium | src/linux/init/drvfs.cpp | Unauthenticated non-elevated DrvFs access via Plan9 vsock port 50002 |
| medium | src/linux/init/config.cpp | Unauthenticated init interop environment variable disclosure |
| medium | src/windows/wslc/services/WinCredStorage.cpp | Machine-wide registry credential storage enables cross-user theft |

Findings tracked in automation memory (`WSL---flagged-vulnerabilities.json`).
