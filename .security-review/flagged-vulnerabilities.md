# Application Security Review — WSL

Scanned commit: `210b7640f7d1eb7da2cf4b4c47b6d1babd63b502`
Detected: 2026-06-02T05:08:41-07:00

Validated medium, high, and critical findings with end-to-end attack paths.

## 1. [HIGH] Unauthenticated world-writable interop Unix socket allows arbitrary Windows process execution as the WSL session owner

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux UID in the WSL utility VM who can open Unix sockets under /run/WSL/

**Controlled input:** Crafted LxInitMessageCreateProcessUtilityVm message with attacker-chosen Windows ApplicationName and CommandLine sent over the interop Unix socket

**Attack path:** Interop sockets and /run/WSL are chmod 0777 with no SO_PEERCRED check; session leader or init accepts and ConfigHandleInteropMessage forwards CreateProcessUtilityVm to Windows CreateProcess under the session owner token

**Impact:** Arbitrary Windows command execution as WSL session owner; breaks Linux UID isolation at the Windows interop boundary

## 2. [MEDIUM] Unauthenticated interop socket allows credential-free login -f for arbitrary Linux users

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux UID that can connect to boot init world-writable interop socket at /run/WSL/1_interop

**Controlled input:** Crafted LxInitMessageCreateLoginSession message with attacker-chosen Username and Uid

**Attack path:** Boot init interop handler accepts CreateLoginSession from any socket peer and child runs execl /bin/login -f Username as root fork, skipping authentication

**Impact:** Authentication bypass establishing login sessions for arbitrary accounts including root without password

## 3. [MEDIUM] Interop socket allows reading victim session environment variables

**Location:** `src/linux/init/config.cpp`

**Attacker:** Any local Linux UID in the same WSL2 VM that can connect to a victim interop socket

**Controlled input:** LxInitMessageQueryEnvironmentVariable with arbitrary variable names

**Attack path:** World-writable interop socket with no peer authentication; handler calls UtilGetEnvironmentVariable on victim session and returns values to attacker

**Impact:** Cross-UID confidentiality breach of session environment secrets (cloud tokens, API keys, credentials in env)
