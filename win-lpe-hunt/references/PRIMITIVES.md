# Primitive toolkit — Windows LPE building blocks

Each primitive is a reusable Lego brick. A hypothesis = one PRIVILEGED OP + one REDIRECT
+ one RACE-WIN + one CONVERSION. Every entry lists: what it is, the API/artifact
signature to grep for in a binary (with the idalib query), and how it's abused.

Short names below map to `mcp__plugin_ida-pro-mcp_idalib__<name>`.

---

## A. PRIVILEGED OPERATIONS (the confused-deputy verb you trigger)

### A1. Defender remediation via MpClient.dll (user-callable scan→clean as SYSTEM)
A low-priv process `LoadLibrary`s the platform `MpClient.dll` and calls the RPC-backed
exports directly, commanding the SYSTEM Defender service to scan then "clean" any path:
```
MpManagerOpen → MpScanStart(MPSCAN_TYPE_RESOURCE, {scheme:"file", path}) → MpScanResult
→ MpThreatOpen(MPTHREAT_SOURCE_SCAN, MPTHREAT_TYPE_KNOWNBAD) → MpThreatEnumerate
→ MpCleanOpen → MpCleanStart(callback) [→ MpCleanControl]
```
The clean runs as SYSTEM and does delete/move/quarantine. **Adjacent verb hypothesis:**
quarantine **restore** writes attacker-controlled bytes back to the original
(attacker-influenced) path as SYSTEM — a cleaner write primitive than clean/delete.
idalib: `imports_query` for `Mp*` exports; `entity_query`/`func_query` on the AV service
binary for the RPC stubs behind them.

### A2. AV/EDR "remediate / rollback / restore" verbs (vendor-agnostic)
Any product exposing a user-reachable "clean this path", "restore from quarantine",
"rollback these changes" is the same confused deputy. Targets: Defender, MDE live
response, SentinelOne, CrowdStrike remediation (FalconFlank abused Office-macro removal),
Sophos, Trend, ESET, Bitdefender, Malwarebytes, Elastic Defend.
idalib: find the ALPC/RPC/COM entry, `trace_data_flow` from the request buffer to a file
API, check impersonation.

### A3. Sandbox / "open on my behalf" READ (confused-deputy read)
A sandbox or scanner opens a file for you that you can't open yourself (PrettyPrague used
Avast's sandbox to read `SAM`+`SYSTEM`). Generalizes to reading DPAPI masterkeys
(`%APPDATA%\Microsoft\Protect`), LSA secrets, scheduled-task creds, other users' hives.

### A4. Profile/logon service hive load (ProfSvc)
ProfSvc loads `UsrClass.dat`/`NTUSER.DAT` at logon as SYSTEM (LegacyHive). Any service
that `RegLoadKey`/`RegLoadAppKey`s a user-influenced hive path is a target.
idalib: `imports_query` `RegLoadKey`, `RegLoadAppKey`, `LoadUserProfile`.

### A5. Installer / MSI repair, updater manifest fetch, self-heal
`msiexec` repair/advertised-install and product self-heal run as SYSTEM and read source
files/manifests from redirectable locations. Updaters that run as SYSTEM and read a
manifest/URL/path from a user location are the same shape (Kaspersky-style).
idalib: strings for `.msi`, `msiexec`, `unattend`, `manifest`, update URLs; xref to file reads.

### A6. Kernel driver IOCTL that does a file/registry/memory op
Hand to `driver-analysis` for the dispatch table, then treat a dangerous IOCTL as the
privileged op. Watch for missing `ProbeForRead/Write`, missing requestor-mode checks,
file/reg ops built from user buffers.

---

## B. REDIRECT PRIMITIVES (make the privileged op land where you choose)

### B1. NTFS junction (mount-point reparse)
`DeviceIoControl(dir, FSCTL_SET_REPARSE_POINT, REPARSE_DATA_BUFFER→\??\target)`. Redirects
a directory. Cheapest; try first when the op opens a path inside a user-writable dir.
idalib: `find_regex` `FSCTL_SET_REPARSE_POINT` / `0x900A4` / `\\\\\?\?\\`.

### B2. Object-manager symlink + shadow directory + globalroot (native-path ops)
`NtCreateDirectoryObjectEx(..., ShadowDirectoryHandle, ...)` layers a fake dir over a
real `\BaseNamedObjects\...` subtree; `NtCreateSymbolicLinkObject` names a leaf → your
target. Bridge Win32→object-manager with a `\.\globalroot\BaseNamedObjects\...` path or
`\??\`. Use when the victim opens via native APIs / the object namespace (LegacyHive).

### B3. Registry indirection (poison a string the service expands)
Set a user-writable `REG_EXPAND_SZ` the SYSTEM service later expands into a file path —
LegacyHive used `HKCU\...\Explorer\User Shell Folders\Local AppData`. Sweep for other
HKCU strings a service consumes: `HKCU\Environment`, Folder Redirection, Shell Folders,
per-user codec/font paths, MSIX staging.
idalib: `xrefs_to` `RegQueryValueExW` then `trace_data_flow` to `ExpandEnvironmentStrings*`
and a file open.

### B4. DOS device (`DefineDosDevice DDD_RAW_TARGET_PATH`, `\??\`)
Creates a per-session device symlink; HardBreacher used it plus `NtCreateSymbolicLinkObject`
on a driver object to redirect the AV's write into System32.

### B5. Hardlink to a victim file
`CreateHardLink` a target file into a location the privileged op writes/sets-ACL on, to
edit a file you couldn't. Classic for "set ACL as SYSTEM on my hardlink → own the target".

### B6. Weak-DACL shared section (memory redirect)
A named section (`\BaseNamedObjects\{GUID}`) created with Everyone/NULL DACL whose data is
validated once but reused at runtime → cross-process OOB write (GreenSection/NVIDIA).
idalib: `list_globals` + `xrefs_to` the section name; check where mapped data is re-read.

---

## C. RACE-WIN PRIMITIVES (hold the TOCTOU window open)

### C1. Batch/filter oplock
`DeviceIoControl(file, FSCTL_REQUEST_BATCH_OPLOCK / FSCTL_REQUEST_FILTER_OPLOCK, overlapped)`;
the callback fires when the victim opens the file, giving you a window to swap a
symlink/junction. Probabilistic; MSNightmare's oplock PoCs are "hit or miss".

### C2. Cloud Filter (cfapi) FETCH_DATA oracle — DETERMINISTIC, prefer this
Register a sync root over your working dir and place the bait as a **placeholder**:
```
CfRegisterSyncRoot(dir, reg, policies{Hydration=FULL, Population=PARTIAL}, ...)
CfConnectSyncRoot(dir, {CF_CALLBACK_TYPE_FETCH_DATA→cb}, ..., &key)
```
When the SYSTEM process reads the placeholder, YOUR `cb` fires **inside its read** — you
choose the bytes (`CfExecute TRANSFER_DATA`) and can **stall arbitrarily**, turning a
flaky race into ~100% and letting you serve staged, multi-step content (ShieldBreak
served a ZIP then a DLL via a 2-state flag). **This is the highest-leverage skill: retrofit
it onto ANY SYSTEM file read, AV or not (MSI source, updater cache, log/config reload).**
idalib: `imports_query` `Cf*` to spot products that already use it (and thus trust
placeholders).

---

## D. SYSTEM CONVERSIONS (turn the primitive into code execution / SYSTEM)

- **Arbitrary write → DLL plant** in a SYSTEM DLL search path or a known phantom/missing DLL
  (`.wsp`, side-by-side, `KnownDlls` gaps, service dir).
- **Arbitrary delete → reload hijack**: delete a DLL/config a SYSTEM service reloads, or use
  the Installer "arbitrary delete → arbitrary folder create" rollback pattern, then plant.
- **Protected read → creds**: read `SAM`+`SYSTEM` → descramble bootkey from class names of
  `HKLM\SYSTEM\CCS\Control\Lsa\{JD,Skew1,GBG,Data}` → parse `SAM\Domains\Account\Users` →
  then a driverless local escalation: `LogonUserEx` → `TokenElevationTypeLimited` →
  `TokenLinkedToken` (full admin token) → set integrity → impersonate → `OpenSCManager` →
  create service → SYSTEM. Or read DPAPI/LSA secrets → lateral.
- **Hive load → COM hijack**: mount an attacker hive into `HKCU\Classes` (or HKU) so a
  SYSTEM/other-user process instantiates your CLSID/InprocServer32.
- **Weak section OOB → DWM/cross-session**: corrupt shared structures consumed by a
  higher-priv or cross-user process (dwm.exe, GPU service).
- **Pre-auth config → unlocked shell**: drop `unattend.xml` + `Recovery\WindowsRE\ReAgent.xml`
  on a writable recovery/ESP partition so WinRE spawns a shell on an unlocked BitLocker
  volume (GreatXML) — generalizes to OEM recovery / push-button-reset flows.

---

## E. The impersonation grep — fastest single check
For every privileged op you find, the bug usually IS the missing impersonation. In the
caller's decompilation confirm the presence/absence of, before the op:
`ImpersonateLoggedOnUser`, `RpcImpersonateClient`, `ImpersonateNamedPipeClient`,
`CoImpersonateClient`, `ImpersonateSecurityContext` — and a matching revert after. Absent
= redirectable. Also flag: no `FILE_FLAG_OPEN_REPARSE_POINT`, no `GetFinalPathNameByHandle`
re-check, path built from user input. idalib: `xrefs_to` those APIs to see which privileged
ops are (not) wrapped.
