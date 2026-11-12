# ShieldBreak — Defender CVE-2026-50656 Patch Bypass (CVE-2026-69414)

## Target
- **Binary:** MsMpEng.exe / MpClient.dll
- **Predecessor:** RoguePlanet (CVE-2026-50656)
- **Privilege:** NT AUTHORITY\SYSTEM

## What Microsoft patched (and missed)
Microsoft's patch for RoguePlanet blocked the specific race path. ShieldBreak demonstrates
that the underlying TOCTOU (scan-by-path, clean-by-path without identity pinning) was NOT
fixed — only the specific junction vector was mitigated.

## Technique chain (evolution from RoguePlanet)

### Privileged operation — same MpClient chain
Identical to RoguePlanet: `MpManagerOpen → MpScanStart → MpCleanOpen → MpCleanStart`.

### Redirect — object-manager symlink + shadow directory
ShieldBreak uses `NtCreateDirectoryObjectEx` with a shadow directory handle and
`NtCreateSymbolicLinkObject` to build a parallel object namespace that redirects Defender's
native-path resolution. This bypasses the junction-specific checks Microsoft added.

Key pattern from source:
```cpp
class ObjectDirMgr  // wraps NtCreateDirectoryObjectEx(shadow)
class ObjectSymlinkMgr  // wraps NtCreateSymbolicLinkObject
```

### Race-win — cfapi FETCH_DATA (DETERMINISTIC)
The critical evolution: ShieldBreak replaces RoguePlanet's probabilistic oplock with the
**Cloud Filter API** (`CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CF_CALLBACK_TYPE_FETCH_DATA`).

The attacker registers a sync root over the working directory and places the bait as a
**placeholder file**. When MsMpEng reads the placeholder, the attacker's callback fires
**inside the read** — fully deterministic. The callback serves different content per state:
```cpp
void CALLBACK CLBK(...) {
    DWORD* RNA = (DWORD*)CallbackInfo->CallbackContext;
    if (*RNA == 1) {
        // serve EICAR zip (for scan detection)
    } else {
        // serve payload DLL (for clean write)
    }
}
```
This state machine achieves 100% success rate — first serve the malware sample so Defender
detects it, then serve the DLL payload when Defender comes back to "clean".

### SYSTEM conversion — DLL plant via transacted write
Uses `CreateTransaction` / `CreateFileTransacted` / `CommitTransaction` to atomically
write the payload DLL, avoiding partial-write races.

## Key new technique: cfapi as universal TOCTOU oracle
**This is the most important primitive in the entire collection.** The cfapi FETCH_DATA
callback:
1. Fires inside the victim's read — no race window
2. Lets the attacker choose what bytes to serve each time
3. Can stall indefinitely via delayed `CfExecute(TRANSFER_DATA)`
4. Works against ANY SYSTEM process that reads a file in a user-writable location
5. Survives reparse-point mitigations (it's not a reparse point)

## idalib hunt queries
- `imports_query` for `CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CfExecute`
- Products that already use cfapi trust placeholders by design → they are pre-vulnerable
