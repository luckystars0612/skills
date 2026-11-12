# Hypothesis engine — format, worked example, and a starter set

## Why multiple hypotheses
One target yields many candidate bugs. You enumerate the cross-product of
(privileged op × redirect × race-win × conversion), then **falsify aggressively**. A
killed hypothesis is a result: it documents coverage and stops re-treading. Aim for 5–8+
hypotheses on any non-trivial target; spawn a subagent per subsystem to draft, but YOU
rank and own the final list.

## The template (fill one per hypothesis)

```
### H<n>: <one-line name>
- Claim (falsifiable): Because <component> does <privileged op> on <user-influenced path>
  <without impersonation / following reparse / without re-checking final path>, a standard
  user can <redirect> + <race-win> to <primitive>, converted to SYSTEM via <conversion>.
- Privileged op:      <A1..A6 from PRIMITIVES.md + the exact function/export>
- Redirect:           <B1..B6>
- Race-win:           <C1/C2, or "none needed">
- Conversion:         <D>
- Evidence so far:    <idalib finding: function @ addr, decompiled line, import, data-flow;
                       mark VERIFIED (seen in binary) vs INFERRED (assumed)>
- Kill condition:     <the single observation that disproves it>
- Cheapest next test: <static: decompile fn X | dynamic: Procmon filter Y>
- Rank:               likelihood(H/M/L) × impact(SYSTEM/cross-user/other) × novelty
                      (shipped-bug / adjacent-verb / new)
- Status:             OPEN | KILLED(<why>) | CONFIRMED(<evidence>)
```

## Worked example (from ShieldBreak, reconstructed)

```
### H1: Defender clean redirected via cfapi placeholder → SYSTEM arbitrary write
- Claim: Because MsMpEng cleans a KNOWNBAD resource by path without pinning the file
  identity, a standard user can serve the bytes via a cfapi FETCH_DATA callback and
  redirect the SYSTEM clean/write to plant a DLL.
- Privileged op:  A1 MpClean (MpCleanOpen/MpCleanStart driven from MpClient.dll)
- Redirect:       B1 junction / placeholder path control
- Race-win:       C2 cfapi FETCH_DATA (deterministic; serve ZIP then DLL)
- Conversion:     D DLL plant in SYSTEM search path
- Evidence:       VERIFIED — MpClient export chain + CfRegisterSyncRoot/CfExecute in the
                  PoC; callback state machine serves 2 payloads.
- Kill condition: clean pins the file by handle/id at scan time and won't re-read content.
- Cheapest test:  Procmon: does the clean re-open the placeholder (FETCH_DATA fires) as SYSTEM?
- Rank:           H × SYSTEM × shipped-bug (this is CVE-2026-50656's bypass)
- Status:         CONFIRMED (author's PoC)
```

## Starter hypothesis set (derived; mostly OPEN/INFERRED — validate before believing)

Use these as seeds when the target is Defender/AV/an updater/a profile service. They are
the "new hypotheses" from the MSNightmare teardown; none are confirmed here.

```
### H-A: Defender quarantine RESTORE as arbitrary write (adjacent verb to the clean bug)
- A2 restore-from-quarantine × B1 junction × C2 cfapi × D DLL plant / delete-reload.
- Kill: restore impersonates the caller, or writes only to a fixed quarantine store.
- Cheapest test: Procmon MsMpEng on a restore call — path + token of the write.
- Rank: H × SYSTEM × adjacent-verb.

### H-B: cfapi FETCH_DATA oracle vs Windows Installer repair source read
- A5 msiexec repair × B1/placeholder × C2 cfapi × D write-to-SYSTEM-path.
- Kill: msiexec verifies source signature/hash before use, or copies before executing.
- Cheapest test: benign MSI + placeholder source; Procmon msiexec read as SYSTEM.
- Rank: H × SYSTEM × new (non-AV generalization of the best primitive).

### H-C: AV sandbox/scanner confused-deputy read of DPAPI/LSA, not just SAM
- A3 sandbox read × (no redirect needed) × D protected-read → creds → lateral.
- Kill: sandbox impersonates caller for the open, or restricts readable paths.
- Cheapest test: ask the sandbox to "scan"/open %APPDATA%\Microsoft\Protect and observe.
- Rank: M-H × cross-user/lateral × broadening.

### H-D: HKCU REG_EXPAND_SZ poisoning of a logon/profile service other than ProfSvc
- A4-style × B3 registry indirection × C1 oplock × D hive/COM or path-open.
- Candidates: Folder Redirection, Offline Files/CSC, MSIX staging, Storage Sense.
- Kill: the service expands the string under impersonation, or ACLs the value.
- Cheapest test: idalib xref RegQueryValueEx→ExpandEnvironmentStrings→file open per service.
- Rank: M-H × SYSTEM × family-expansion.

### H-E: cfapi retrofit onto a known flaky oplock LPE to make it 100%
- any A × existing B × swap C1→C2 × existing D.
- Kill: the victim pins the file handle so no re-read/hydration occurs.
- Rank: M × varies × reliability-multiplier (can make an unreportable race reportable).

### H-F: weak-DACL section OOB (GreenSection-class) → dwm.exe / cross-session
- A6/B6 weak section write × D OOB → higher-priv consumer.
- Kill: consumer re-validates the structure on reuse, or DACL is not writable.
- Cheapest test: idalib — find the section, xref consumers, check re-validation on reuse.
- Rank: M × cross-user × hard-but-real (MSNightmare left this undeveloped).

### H-G: self-protected AV process as a trusted writer (Kaspersky-class), generalized
- A2 × B4 DefineDosDevice/symlink × C1/C2 × D System32 write.
- Applies to any product whose GUI/helper/updater runs elevated and trusts its own
  usermode process by PID/path.
- Kill: the driver validates the write path server-side regardless of caller process.
- Rank: M × SYSTEM × vendor-specific.

### H-H: CLFS .cnpf creation coerced via any SYSTEM log opener (SignDrop-class)
- A7 RPC coercion (or any trigger that makes a SYSTEM process open a .blf) × B8 CLFS
  container path symlink × C1 oplock on bait file × D arbitrary file create w/ attacker
  DACL → DLL plant.
- The CLFS authentication mitigation (Mode 0 or 1) creates .cnpf files in the opener's
  context. If the opener is SYSTEM and the container path is an object-manager symlink,
  the .cnpf lands anywhere with the attacker's DACL.
- Beyond Defender: ANY service that opens CLFS logs is a target — Event Log, BITS,
  TxF recovery, SQL Server, custom services using CLFS for logging.
- Kill: CLFS validates container paths against symlinks; or the service never opens
  user-created .blf files; or CLFS auth Mode is 2+ on the target.
- Cheapest test: check reg `HKLM\SYSTEM\CCS\Services\CLFS\Authentication\Mode`; then
  enumerate SYSTEM services that call CreateLogFile/OpenLogFile.
- Rank: H × SYSTEM × family-expansion (SignDrop proved it vs Defender; generalize to
  all SYSTEM log-openers).

### H-I: TxF atomic overwrite during AV remediation window (FalconFlank-class)
- A2 AV remediation/cleanup verb × B7 TxF (CreateFileTransacted + CommitTransaction) ×
  C1 oplock (hold the remediation mid-op) × D DLL plant in System32/SxS.
- When an AV/EDR process remediates a file (deletes macro, strips PE, moves to
  quarantine), the target directory has a brief state where the original is gone and the
  replacement hasn't landed. TxF commits the payload atomically in that window.
- FalconFlank used this vs CrowdStrike's macro removal + junction to redirect into
  System32\WindowsPowerShell\v1.0\bcrypt.dll. The pattern applies to any remediation
  that re-creates/replaces a file.
- Kill: remediation holds an exclusive handle throughout (no window); or the target dir
  is ACL-protected against junction creation; or the replaced file is signature-verified.
- Cheapest test: Procmon the remediation process — look for CreateFile/DeleteFile gaps
  on the target path. If there's a gap, TxF can fill it.
- Rank: M-H × SYSTEM × vendor-specific (depends on remediation behavior).

### H-J: RPC path coercion against non-Defender SYSTEM services
- A7 RPC method accepting a path arg × B2 object-manager symlink × C2 cfapi or C1
  oplock × D depends on what the coerced open does (read → SAM chain, write → DLL plant).
- ShieldCrash/SignDrop proved that Defender's Proc42_ServerMpUpdateEngineSignature
  coerces MsMpEng to open a user-supplied path. Other SYSTEM services with similar
  RPC methods: BITS (IBackgroundCopyJob::SetNotifyInterface → path), WinRM, WSUS agent,
  Print Spooler (AddPrinterDriverEx), Certificate Services, Task Scheduler.
- Kill: RPC method impersonates before the open; or the path is validated server-side
  against an allowlist; or the method requires admin privilege to call.
- Cheapest test: RpcView to enumerate methods, then idalib trace_data_flow from the
  RPC stub's path parameter to NtCreateFile/CreateFileW. Check impersonation.
- Rank: H × SYSTEM × systematic (this is a repeatable search pattern across all services).

### H-K: AV namespace hijack via DefineDosDevice on GUI/tray processes (HardBreacher-class)
- A8 namespace hijack × B4 DefineDosDevice(DDD_RAW_TARGET_PATH) per-session map × no
  race needed (deterministic DLL load from poisoned path) × D AV-trusted code execution.
- HardBreacher proved this vs Kaspersky avpui.exe. The pattern: AV's user-mode GUI
  process loads DLLs through DOS device resolution. Attacker creates per-session DOS
  device entries shadowing DLL names → spawns the GUI process (or waits for auto-start)
  → loads attacker DLL. Self-protection minifilters do NOT block DOS device creation.
- Targets: any AV with a tray/GUI process — avpui.exe (Kaspersky), avgui.exe (AVG),
  NortonSecurity.exe, SEDService/SEPM (Symantec), SentinelAgent.exe UI, bdagent.exe
  (Bitdefender), ekrn.exe tray (ESET).
- Kill: the product's process uses fully absolute NT paths for all DLL loads (no device
  resolution); or the minifilter also monitors DOS device map changes; or the GUI process
  verifies DLL signatures before loading.
- Cheapest test: use NtCreateUserProcess to spawn the target GUI exe with parent-spoofed
  to explorer.exe, after setting up DefineDosDevice entries. Check Process Monitor for
  DLL loads from unexpected paths.
- Rank: H × SYSTEM (if GUI runs elevated) or M × user-context (if GUI runs as user but
  AV trusts it) × vendor-specific.

### H-L: Sandbox file read beyond SAM — DPAPI masterkeys, scheduled task creds, certificates
- A3 sandbox confused-deputy read × (no redirect — the read itself is the primitive) ×
  D credential extraction → lateral or local escalation.
- PrettyPrague read SAM+SYSTEM via Avast sandbox. The same read primitive can target:
  - `%APPDATA%\Microsoft\Protect\<SID>\` — DPAPI masterkeys
  - `%APPDATA%\Microsoft\Credentials\` — credential manager blobs
  - `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\` — machine private keys
  - `C:\Windows\System32\config\SECURITY` — LSA secrets (service passwords, autologon)
  - Other users' NTUSER.DAT / AppData (cross-user data theft)
- If the sandbox can read any of these, the chain is: extract → decrypt offline → reuse.
- Kill: sandbox restricts read paths to a whitelist; or sandbox doesn't open files as
  SYSTEM (uses caller's token).
- Cheapest test: submit a scan request targeting each sensitive path; check if the AV
  engine successfully opens and reads the file. Procmon filter on the AV PID.
- Rank: H × lateral/SYSTEM × broadening (PrettyPrague only demonstrated SAM; the same
  primitive reaches much more).

### H-M: Disk exhaustion DoS against AV signature delivery (BigDiskBuster-class)
- A9 disk exhaustion × (no redirect) × (no race — deterministic) × D DoS (permanent
  stale signatures, silent AV bypass).
- Any AV that writes signature/engine updates to the system volume without pre-reserving
  space is vulnerable. Monitor the update directory, exhaust disk on write start, release
  on rollback, loop. The machine runs permanently outdated signatures.
- Targets: every AV that downloads to ProgramData or Program Files on C:\ — Kaspersky,
  ESET, Bitdefender, Malwarebytes, Sophos, Trend Micro, Symantec.
- Also: lock engine binaries (FILE_SHARE_READ only) to prevent binary replacement.
- Kill: product uses a dedicated partition; or pre-allocates space before download; or
  downloads to a fixed-size container; or verifies final state matches expected size.
- Cheapest test: during an update, check the staging directory in Procmon — is it on
  the system volume? Can a standard user allocate all remaining space?
- Rank: M × DoS × family-expansion (BigDiskBuster proved vs Defender; trivial to port).

### H-N: WinRE/recovery partition injection after AV offline scan (GreatXML-class)
- Physical-access attack. After any AV triggers an offline scan that modifies WinRE
  boot config, the recovery partition may accept unattend.xml.
- GreatXML proved this after Defender Offline Scan. Other AV offline/rescue modes:
  Kaspersky Rescue Disk, ESET SysRescue, Bitdefender Rescue Environment, Avast
  WinPE scan — do they also leave WinRE in a more permissive state?
- Kill: WinRE doesn't process unattend.xml from the recovery root; or Secure Boot
  prevents modification of recovery partition files; or the AV restores original
  WinRE config after the offline scan completes.
- Cheapest test: initiate the AV's offline scan feature, then check if unattend.xml
  is processed on next WinRE boot (Shift+Restart).
- Rank: M × BitLocker-bypass (physical access) × family-expansion.

### H-O: Patch-bypass of any path-specific TOCTOU fix via mechanism swap
- Meta-hypothesis: when a vendor patches a TOCTOU by blocking the specific redirect
  mechanism (e.g., blocks junctions but not object-manager symlinks), swap the redirect
  to an unblocked mechanism from PRIMITIVES.md B1–B8.
- The Defender trilogy proves this works: RoguePlanet (junction+oplock) → ShieldBreak
  (obj-mgr symlink+cfapi) → ShieldCrash (same cfapi+different path).
- For ANY recently-patched TOCTOU CVE: read the patch diff, classify whether it's
  path-specific or root-cause, then try the alternatives.
- Kill: the patch adds impersonation + handle identity pinning (true root-cause fix).
- Cheapest test: diff the patched binary with idalib — is the fix a path check or an
  impersonation/handle change?
- Rank: H × SYSTEM × systematic (every path-specific TOCTOU patch is a bypass candidate).
```

## Ranking discipline
Sort OPEN hypotheses by **cheapest-disproof-first**, not by excitement. Burn down the
ones a single `decompile` can kill before touching a PoC. Keep a running table of
OPEN / KILLED / CONFIRMED so coverage is visible. Only CONFIRMED (primitive demonstrated)
graduates to `triage-validation` and `report-writing`.
