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

### A7. RPC coercion of AV/service engine (force a SYSTEM process to open your path)
Call a service's RPC method that accepts a path argument, causing the SYSTEM process to
open/read/write at that path. ShieldCrash/SignDrop used Defender's
`Proc42_ServerMpUpdateEngineSignature` on `c503f532-443a-4c69-8300-ccd1fbdb3839` via
`ncalrpc` endpoint `IMpService77BDAF73-B396-481F-9042-AD358843EC24`. The coerced open
is the trigger — combine with B-class redirects so the open lands on your target.
**Generalizes to any service with an RPC method that opens a user-supplied path.**
idalib: `entity_query` for RPC server interface UUIDs; `trace_data_flow` from the
RPC stub's parameter buffer to `NtCreateFile`/`CreateFileW`; check if impersonation
is applied before the open.

### A8. AV process namespace hijack (DosDevice map poisoning)
Abuse per-logon-session DOS device maps to redirect an AV process's DLL resolution.
HardBreacher created entries in `\Sessions\0\DosDevices\<AuthenticationId>\KASPERSKY-<GUID>`
using `DefineDosDevice(DDD_RAW_TARGET_PATH)` to map Kaspersky DLL names to attacker
payloads, then spawned `avpui.exe` (with parent-spoofed `NtCreateUserProcess` +
`PS_ATTRIBUTE_PARENT_PROCESS`) which loaded the poisoned DLLs. **Key insight:** AV
self-protection (minifilters) blocks injection/file-write but NOT object-manager
namespace manipulation or DOS device creation.
idalib: `imports_query` `DefineDosDeviceW`; check if the target product's GUI/tray
process uses relative DLL paths or relies on DOS device resolution.

### A9. Disk exhaustion against update/install pipelines
Monitor a product's update directory (`ReadDirectoryChangesW`) and allocate all free
disk space (`NtCreateFile` with `AllocationSize = free_space, FILE_DELETE_ON_CLOSE`)
when the updater starts writing. BigDiskBuster blocked Defender signature updates
permanently. The update fails, the product rolls back, the attacker releases space and
waits for retry. Combine with `FILE_SHARE_READ` locks on engine binaries (`MRT.exe`)
to also prevent binary replacement.
idalib: N/A (no binary analysis needed — this is a logic/resource bug).

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

### B7. Transacted NTFS (TxF) atomic file replacement
```
CreateTransaction → CreateFileTransacted(target, GENERIC_WRITE, ..., hTx)
  → WriteFile → CommitTransaction(hTx)
```
Atomically replaces a file's contents — the payload either fully appears or doesn't exist
at all. FalconFlank used TxF to overwrite `bcrypt.dll` in System32 during an oplock window;
SignDrop used `DeleteFileTransacted` for atomic cleanup. **Advantages:** no partial-write
window for AV real-time scan to catch; no temp file left on disk if the chain fails.
idalib: `imports_query` `CreateFileTransacted`, `CommitTransaction`, `CreateTransaction`.

### B8. CLFS container path association (kernel file-create coercion)
CLFS log files (`.blf`) remember their associated container paths. If you create a log
with a container whose path is an object-manager symlink, then coerce a SYSTEM process to
open the `.blf`, CLFS re-creates the missing `.cnpf` authentication file **in the opener's
security context** at the symlinked path. SignDrop:
```
NtCreateFile(\CLFS\??\workdir\log.blf) → AddLogContainer(path=\BNO\Restricted\<GUID>)
// delete container + .cnpf, replace symlink to target
// coerce SYSTEM to open log.blf → CLFS creates .cnpf at target path AS SYSTEM
```
The created file inherits the DACL of the original container file (attacker-owned) →
attacker can write arbitrary content to the SYSTEM-created file.
idalib: `imports_query` `CreateLogFile`, `AddLogContainer`; in kernel drivers:
`ClfsMgmtRegisterManagedClient`, `ClfsCreateLogFile`.

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
- **SAM dump → SamiChangePasswordUser → LinkedToken → CreateService → SYSTEM**:
  PrettyPrague's full driverless chain. Read `SAM`+`SYSTEM` hives (via sandbox, arbitrary
  read, or backup privilege) → extract boot key from LSA class names → decrypt NTLM hashes
  → `SamiChangePasswordUser(oldHash→newHash)` (no cracking needed) → `LogonUserExW` →
  `TokenLinkedToken` for full admin → `ImpersonateLoggedOnUser` → `OpenSCManager` →
  `CreateServiceW` → SYSTEM. **Cleanup:** restore original password with same API.
- **UAC bypass via COM elevation moniker (CMSTPLUA)**:
  `ICMLuaUtil` `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` — create elevated COM object
  without UAC prompt. PrettyPrague used this as an alternative SYSTEM conversion path.
  Generalizes: any auto-elevating COM object with `ShellExec` method.
- **CLFS .cnpf arbitrary create → DLL plant**: SignDrop's conversion. The SYSTEM-created
  `.cnpf` file has attacker's DACL → write payload DLL content → trigger load via
  `osk.exe` (loads `hid.dll` from `Common Files\microsoft shared\ink\`). Other known
  phantom DLL targets: `version.dll`, `wer.dll`, `wbemcomn.dll` in various search paths.
- **AV namespace hijack → AV-trusted code execution**: HardBreacher's conversion. The
  AV's own GUI process loads the attacker's DLL because the DOS device map was poisoned.
  Since the load comes from the AV's own process, the AV's minifilter trusts it. This
  bypasses self-protection that would block external injection.

---

## E. AUXILIARY PRIMITIVES (tools used across multiple chains)

### E1. offreg.lib — offline registry hive manipulation
`OROpenHiveByHandle`, `OROpenKey`, `ORGetValue`, `ORSetValue`, `ORSaveHive`, `OREnumKey`.
Edit any `.dat` hive file without mounting it — no privilege required beyond file read/write.
Used by: LegacyHive (poison shell folders), PrettyPrague (SAM parsing), ShieldCrash
(offline hive edits). **Hunt pattern:** any time you can read/write a hive file, you can
edit its contents without `RegLoadKey` privilege.

### E2. NtCreateUserProcess with PS_ATTRIBUTE_PARENT_PROCESS (parent spoofing)
Create a process as a child of any process you can `OpenProcess(PROCESS_CREATE_PROCESS)`.
HardBreacher used this to spawn `avpui.exe` under `explorer.exe`, evading process-tree
heuristics. Also controls the initial DOS device map and environment of the child.

### E3. ISO/VHD mount as standard user (AttachVirtualDisk)
On desktop Windows SKUs, standard users can mount `.iso`/`.vhd` files via `virtdisk.lib`.
RoguePlanet used this to introduce files without writing to the filesystem. **Not available
on Windows Server** — PoCs relying on this need a Server-compatible fallback.

### E4. Named pipe / event synchronization
IPC between PoC stages: FalconFlank used `\\?\pipe\FALCONFLANK`, HardBreacher used
`Local\HardBreacher-SolidSnake-Sync-Event`. When the payload DLL runs in the AV's process
context, it signals back to the orchestrator. Pattern for any multi-stage chain.

---

## F. The impersonation grep — fastest single check
For every privileged op you find, the bug usually IS the missing impersonation. In the
caller's decompilation confirm the presence/absence of, before the op:
`ImpersonateLoggedOnUser`, `RpcImpersonateClient`, `ImpersonateNamedPipeClient`,
`CoImpersonateClient`, `ImpersonateSecurityContext` — and a matching revert after. Absent
= redirectable. Also flag: no `FILE_FLAG_OPEN_REPARSE_POINT`, no `GetFinalPathNameByHandle`
re-check, path built from user input. idalib: `xrefs_to` those APIs to see which privileged
ops are (not) wrapped.

---

## G. PATCH-BYPASS METHODOLOGY (from RoguePlanet → ShieldBreak → ShieldCrash)

The Defender trilogy demonstrates a systematic patch-bypass approach:

1. **Classify the patch:** Is it path-specific (blocks the exact vector) or root-cause
   (adds impersonation / handle-identity pinning)?
2. **If path-specific:** enumerate all alternative paths the same primitive can reach.
   ShieldBreak bypassed junction-specific checks by switching to object-manager symlinks.
3. **If mechanism-specific:** find a mechanism the patch doesn't cover. ShieldBreak
   replaced oplock (probabilistic) with cfapi FETCH_DATA (deterministic) — the patch
   didn't anticipate cfapi as a race-win source.
4. **If the fix adds validation:** check if the validation itself has a TOCTOU. The
   RoguePlanet patch re-validated the path but still by-name (not by-handle), so a
   second swap between validation and use still worked.
5. **Iterate:** each patch reveals what the vendor considers the attack surface. Anything
   NOT patched is implicitly assumed safe — test those assumptions.

### Patch-bypass hunt checklist
- [ ] Read the patch diff (if available) or reverse the patched binary
- [ ] List what the patch blocks vs. what the root cause is
- [ ] For each blocked mechanism, list alternatives from sections B and C
- [ ] Test each alternative against the patched binary
- [ ] If the patch adds a check: can you race the check itself?
