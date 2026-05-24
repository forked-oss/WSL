# hardcoded-password

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Repository | WSL |
| Commit | 210b7640f7d1eb7da2cf4b4c47b6d1babd63b502 |
| File | /agent/repos/WSL/test/windows/wslc/e2e/WSLCE2ERegistryTests.cpp |
| Line | 29 |

## Summary

Pattern `password\s*=\s*["\x27][^"\x27]{8,}` matched in source.

## Status

True positive (heuristic pattern match — requires manual validation).
