# Security Review — 2026-06-30

Commit scanned: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

**Findings:** 6 (no new findings in this scan)

## Known findings

- **High:** Unauthenticated elevated DrvFs access via fixed Plan9 admin vsock port bypassing IsDrvfsElevated
- **High:** Unauthenticated virtiofs share management on vsock port 50004 with guest-controlled Admin flag
- **High:** World-writable interop socket enables cross-user Windows process creation
- **Medium:** Unauthenticated interop socket allows reading victim relay environment variables including proxy credentials
- **Medium:** Unauthenticated localhost TCP relay via guest vsock listener
- **Medium:** Unauthenticated login session creation for arbitrary users via interop socket when systemd boot is enabled
