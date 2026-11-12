# FalconFlank — CrowdStrike Falcon Sensor 0day LPE

## Target
- **Binary:** CrowdStrike Falcon Sensor (CSFalconService)
- **Feature abused:** "Microsoft Office file malicious macro removal"
- **Privilege:** NT AUTHORITY\SYSTEM

## Vulnerability class
DLL side-loading via directory junction + TxF atomic overwrite during Falcon's macro-
remediation feature. Falcon launches PowerShell as SYSTEM and loads DLLs from an
attacker-redirected path.

## Technique chain

### Trigger — Falcon macro remediation
When Falcon detects a document with a malicious macro, it spawns a cleanup process that
loads PowerShell. The cleanup runs as SYSTEM.

### Redirect — junction + TxF atomic write (B1 + B7)
1. Create temp directory tree mirroring `WindowsPowerShell\v1.0\`
2. Write payload DLL as `bcrypt.dll` in the fake `v1.0\` directory
3. Set oplock (`FSCTL_REQUEST_OPLOCK` with `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`)
4. Delete original `v1.0` directory
5. Create NTFS junction on `WindowsPowerShell` → `\SystemRoot\System32\WindowsPowerShell`
   using `FSCTL_SET_REPARSE_POINT_EX`
6. Use Transacted NTFS to atomically overwrite `C:\Windows\System32\WindowsPowerShell\v1.0\bcrypt.dll`:
   ```cpp
   CreateFileTransacted(target, ..., hTransaction, ...)
   // write payload content
   CommitTransaction(hTransaction)
   ```

### Race-win — oplock (C1)
Oplock on the bait file fires when Falcon's SYSTEM process accesses it. In the callback,
the junction is swapped and the TxF write commits, placing the payload DLL before Falcon
loads it.

### Execution trigger — Task Scheduler COM
```cpp
ITaskService → Connect → GetFolder("\\") → GetTask("\\Microsoft\\Windows\\Application Experience\\MareBackup")
// trigger task that loads the planted bcrypt.dll
```

### IPC — named pipe synchronization
`\\?\pipe\FALCONFLANK` — payload DLL signals back to main PoC when execution achieved.

## Key techniques from source

### Embedded payload (doc.h)
`FlankerDll` — 1.4MB embedded DLL stored as byte array in `doc.h`
`rawData` — additional embedded data for the bait document

### NTFS reparse point manipulation
```cpp
FSCTL_SET_REPARSE_POINT_EX  // set junction
// Uses IO_REPARSE_TAG_MOUNT_POINT for directory junctions
```

### TxF (Transacted NTFS) — NEW PRIMITIVE
```cpp
CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL)
CreateFileTransacted(targetPath, GENERIC_WRITE, ..., hTransaction, NULL, NULL)
CommitTransaction(hTransaction)
```
TxF provides atomic file replacement — the payload either fully replaces the target or
doesn't exist at all. No partial-write window. This is superior to rename-in-place for
avoiding AV real-time scan of the intermediate state.

## Hunt generalization for other EDR
1. Identify any EDR remediation feature that spawns SYSTEM processes
2. Check if those processes load DLLs from user-writable or redirectable paths
3. Check if the remediation process uses PowerShell, cmd.exe, or other interpreters
   (all have DLL search-order attack surface)
4. Task Scheduler tasks that run as SYSTEM with user-triggerable conditions
5. Named pipe/event synchronization patterns reveal timing-sensitive chains
