# Application Security Review (2026-06-01)

Commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`

## Findings

### HIGH: World-writable interop socket enables cross-user Windows process creation

| Field | Detail |
|-------|--------|
| **Location** | `src/linux/init/util.cpp` |
| **Attacker** | Local Linux principal in the same WSL distro/VM as a victim WSL session |
| **Controlled input** | Messages on `/run/WSL/<pid>_interop` including `LxInitMessageCreateProcessUtilityVm` |
| **Attack path** | Interop socket is created with `chmod(..., 0777)` (`util.cpp:142`). Parent directory is mode `0777`. `config.cpp` accepts connections without `SO_PEERCRED`/UID validation and forwards create-process messages to the Windows host (`config.cpp:374-378`). Windows `interop.cpp` executes the supplied command line under the victim's Windows identity. |
| **Impact** | Cross-user escalation from Linux to arbitrary Windows process creation as the victim's Windows user |
| **Remediation** | Restrict socket permissions to the session owner, validate peer UID on accept, reject create-process from non-owner peers |
