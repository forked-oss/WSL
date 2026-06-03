# Application Security Review — WSL

**Scan date:** 2026-06-02 (Pacific)
**Commit:** `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
**Branch:** `cursor/application-security-review-126f`

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer tracking; follow each project's security disclosure process before public discussion.

## 1. [HIGH] World-writable interop socket enables cross-user Windows process creation

- **Location:** `src/linux/init/util.cpp`
- **Impact:** Cross-user escalation to Windows code execution as victim identity

## 2. [MEDIUM] Unauthenticated interop IPC leaks session environment variables **(new this scan)**

- **Location:** `src/linux/init/config.cpp`
- **Impact:** Cross-user disclosure of secrets from victim WSL environment

## Remediation priorities

Address high-severity items first. Each finding should be verified on the scanned commit before patch design.
