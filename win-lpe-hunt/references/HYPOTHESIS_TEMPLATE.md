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
```

## Ranking discipline
Sort OPEN hypotheses by **cheapest-disproof-first**, not by excitement. Burn down the
ones a single `decompile` can kill before touching a PoC. Keep a running table of
OPEN / KILLED / CONFIRMED so coverage is visible. Only CONFIRMED (primitive demonstrated)
graduates to `triage-validation` and `report-writing`.
