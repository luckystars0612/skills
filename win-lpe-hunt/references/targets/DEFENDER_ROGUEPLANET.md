# RoguePlanet — Windows Defender Race Condition LPE (CVE-2026-50656)

## Target
- **Binary:** MsMpEng.exe / MpClient.dll (Windows Defender Antimalware Service)
- **Privilege:** NT AUTHORITY\SYSTEM
- **Entry point:** Low-priv user via MpClient.dll RPC exports

## Vulnerability class
TOCTOU race condition in Defender scan→clean pipeline. The clean operation runs as SYSTEM
on an attacker-controlled path without pinning the file identity between scan and clean.

## Technique chain

### Privileged operation (A1 — MpClient scan→clean)
```
MpManagerOpen → MpScanStart(MPSCAN_TYPE_RESOURCE, {scheme:"file", path:attacker_dir})
→ MpScanResult → MpThreatOpen(MPTHREAT_SOURCE_SCAN, MPTHREAT_TYPE_KNOWNBAD)
→ MpThreatEnumerate → MpCleanOpen → MpCleanStart(callback)
```
The PoC loads `MpClient.dll` directly from the Defender platform directory and drives the
full scan-to-clean chain programmatically. The clean runs as SYSTEM.

### Redirect (B1 — NTFS junction + ISO mount)
RoguePlanet uses `AttachVirtualDisk` to mount a crafted ISO containing the EICAR test
file. The scan target is set to a path inside a user-writable directory. Between scan and
clean, the directory is swapped via junction to redirect SYSTEM's write.

### Race-win (C1 — oplock)
The PoC places an oplock (`FSCTL_REQUEST_OPLOCK`) on the bait file. When MsMpEng opens
for clean, the oplock fires, giving the attacker a window to swap the junction target.
The race is probabilistic — "hit or miss" per the author.

### SYSTEM conversion (D — DLL plant)
The redirected SYSTEM write places attacker-controlled content into a SYSTEM DLL search
path. A scheduled task or service that loads the planted DLL completes the chain.

## Key APIs from source
- `AttachVirtualDisk` / `OpenVirtualDisk` — ISO mount (standard user on desktop SKU)
- `FSCTL_REQUEST_OPLOCK` — race-win timing primitive
- MpClient exports: `MpManagerOpen`, `MpScanStart`, `MpScanResult`, `MpThreatOpen`,
  `MpThreatEnumerate`, `MpCleanOpen`, `MpCleanStart`, `MpCleanControl`
- Task Scheduler COM (`ITaskService`) to trigger DLL load

## Limitations
- Windows Server: standard users cannot mount ISO → PoC fails (but bug exists)
- Race condition is non-deterministic with oplock alone

## What to hunt for in other AV
1. Find the user-callable scan/clean/remediate RPC chain
2. Check if the clean operation re-opens the file by path (not by handle)
3. Check if impersonation is used during the clean write
4. Check if the target path is re-validated after scan
