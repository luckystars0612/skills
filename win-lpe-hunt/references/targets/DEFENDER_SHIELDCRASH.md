# ShieldCrash — Defender CVE-2026-69414 Patch Bypass (arbitrary file read as SYSTEM)

## Target
- **Binary:** MsMpEng.exe / MpClient.dll
- **Predecessor:** ShieldBreak (CVE-2026-69414)

## What Microsoft patched (and missed again)
Microsoft fixed several ShieldBreak vectors but missed a specific condition under which
the same scan→clean TOCTOU can be re-triggered. Third round of the same root cause.

## Technique chain
Identical to ShieldBreak with these variations:
- Same MpClient RPC chain for scan trigger
- Same cfapi FETCH_DATA for deterministic content serving
- Same object-manager symlink infrastructure
- **Adds:** `windefend.idl` RPC interface for direct Defender service communication
  (uses `Proc42_ServerMpUpdateEngineSignature` to coerce Defender into opening paths)
- **Adds:** `offreg.lib` for offline registry hive manipulation
- **Result demonstrated:** arbitrary file READ as SYSTEM (not write), reading protected
  files that standard users cannot access

## Key additional techniques from source

### RPC coercion via WinDefend IDL
```cpp
RPC_WSTR MS_WD_UUID = L"c503f532-443a-4c69-8300-ccd1fbdb3839";
// endpoint: ncalrpc "IMpService77BDAF73-B396-481F-9042-AD358843EC24"
Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, path, &errstat);
```
This coerces MsMpEng to open a path as SYSTEM — useful beyond just ShieldCrash.

### Offline registry manipulation
Uses `offreg.h` / `offreg.lib` (`OROpenHiveByHandle`, `ORGetValue`, `ORSetValue`,
`ORSaveHive`) to edit registry hives while they're not mounted.

## Lessons for patch-bypass hunting
1. Check if the patch is path-specific or root-cause (identity-pinning)
2. If path-specific → enumerate all paths the same primitive can reach
3. The chain RoguePlanet→ShieldBreak→ShieldCrash proves TOCTOU requires structural fix
   (impersonation + handle identity pinning), not per-path blocklisting
