---
name: win-lpe-hunt
description: Hunt Windows local privilege escalation (LPE) in SYSTEM services, antivirus/EDR agents, updaters and drivers by binary analysis + hypothesis generation. Confused-deputy-against-a-privileged-file/registry-op bug class. Generates MULTIPLE falsifiable hypotheses, each pairing a privileged operation × a redirect primitive × a race-win × a SYSTEM-conversion, then validates them with IDA (idalib MCP) static analysis and Procmon dynamic tracing. Use when auditing any Windows binary that runs as SYSTEM/admin and touches user-influenced paths — AV/EDR, vendor updaters, profile/logon services, installers, GPU/audio/print helpers, kernel drivers — or when the user wants new LPE ideas from a target binary. 中文触发词：本地提权、Windows提权、LPE、驱动漏洞、杀软提权
tags: [windows, lpe, privilege-escalation, ida, idalib, reverse-engineering, antivirus, edr, toctou, symlink, confused-deputy]
---

# win-lpe-hunt — Windows LPE hypothesis engine

You are hunting **local privilege escalation** on Windows. The unifying bug class,
distilled from MSNightmare's public research (see `references/PRIMITIVES.md` and the
memory `msnightmare-lpe-methodology`) plus derived hypotheses:

> **A SYSTEM/admin-privileged process performs a file or registry operation on a path
> the low-priv attacker can influence, and the attacker controls the namespace
> underneath that path.** Redirect the privileged op with a symlink/junction/registry
> indirection, win the TOCTOU with an oplock or a Cloud Filter callback, and convert the
> resulting arbitrary write / delete / read into SYSTEM.

Your job is NOT to write one exploit. It is to **generate many falsifiable hypotheses**
about a target, rank them, then kill or confirm each with binary evidence. Reproduced or
it didn't happen. Verified vs inferred, always.

**Authorization gate (do this first, one line):** confirm the target binary/product is
one the user is authorized to test (own machine, licensed product, research VM, or an
in-scope program). Detonate weaponized artifacts only in an isolated VM the user owns.
If a step would touch a system the user does not own, stop and say so.

---

## Inputs this skill expects

- A **target**: a path to a binary/driver/DLL, a product name, or "survey my box".
- Available tooling in this environment:
  - **IDA Pro via `idalib` MCP** — tools are `mcp__plugin_ida-pro-mcp_idalib__*`
    (referred to below by short name: `survey_binary`, `decompile`, `imports_query`,
    `xrefs_to`, `xref_query`, `trace_data_flow`, `find_regex`, `search_text`,
    `list_globals`, `func_query`, `list_funcs`, `entity_query`, `disasm`, `callgraph`).
    Claude can read any binary.
  - Bash (Procmon/accesschk/WinObj live on a Windows VM; here you reason from output the
    user pastes, or from static analysis).
  - Sibling skills: `driver-analysis` (kernel IOCTL surface), `ida-scripting`,
    `smart-patch-ida`, `triage-validation`, `cve-hunt` (patch-bypass framing),
    `report-writing`.

---

## The loop (each phase gates the next)

### Phase 0 — Scope + target intake
State the target and authorization in one line. Identify what privilege the target runs
at (SYSTEM service? PPL? admin? kernel? another user's session?) and what low-priv entry
points reach it (RPC/ALPC, COM, IOCTL, a watched folder, a registry value it reads, a
named object). If unknown, resolve it in Phase 1.

### Phase 1 — Static surface mapping with idalib
Open the binary (`idb_open`) and `survey_binary` for orientation. Then hunt the three
ingredients (full recipes in `references/PRIMITIVES.md`):

1. **Privileged operations on attacker-influenceable input.** `imports_query` /
   `xrefs_to` for: `CreateFileW`, `NtCreateFile`, `MoveFileEx`, `CopyFile*`,
   `DeleteFile*`, `ReplaceFile`, `SetFileSecurity`, `RegLoadKey`/`RegLoadAppKey`,
   `RegSaveKey`, `RegRestoreKey`, `RegOpenKeyEx`, `SHFileOperation`, `CreateProcess*`.
2. **The missing impersonation.** This is the single highest-signal tell. For each
   privileged op, `decompile` the caller and check whether the code
   `ImpersonateLoggedOnUser` / `RpcImpersonateClient` / `ImpersonateNamedPipeClient`
   **before** the op and reverts after. A privileged file op on a caller-supplied or
   caller-influenced path with **no impersonation** around it is a prime LPE candidate.
   Also flag `FILE_FLAG_OPEN_REPARSE_POINT` **absent** (follows symlinks) and final-path
   re-validation absent.
3. **Attacker-controlled input reaching the path.** `trace_data_flow` from the input
   source (RPC arg, IOCTL input buffer, a `RegQueryValueEx` of an HKCU string, a config
   file read) to the path argument of the privileged op. If a user-writable
   `REG_EXPAND_SZ` or a user-writable directory feeds the path, that is your redirect
   point.

Also sweep for **weak-DACL named objects**: `find_regex`/`search_text` for
`BaseNamedObjects`, `CreateFileMappingW`, `NtCreateSection`, GUID-named sections; check
whether the DACL is set from `Everyone`/`NULL` and whether the mapped data is validated
once at creation but trusted on later reuse (the GreenSection pattern).

For **kernel drivers**, hand off to the `driver-analysis` skill for the IOCTL dispatch
table, then come back here to frame the IOCTL as the "privileged op" in a hypothesis.

### Phase 2 — Generate MULTIPLE hypotheses (the core of this skill)
Do NOT stop at one. Emit **at least 5–8 hypotheses** for a non-trivial target, each in
the `references/HYPOTHESIS_TEMPLATE.md` format. Build each by picking one item from each
column:

```
PRIVILEGED OP          ×  REDIRECT PRIMITIVE        ×  RACE-WIN            ×  SYSTEM CONVERSION
- scan+clean (MpClient)   - NTFS junction              - batch oplock         - DLL plant in SYSTEM search path
- quarantine RESTORE      - object-mgr symlink+shadow   - cfapi FETCH_DATA     - arbitrary delete → reload hijack
- sandbox/agent read      - \.\globalroot bridge       - filter oplock        - SAM/LSA read → linked token → service
- config/self-heal reload - DefineDosDevice \??\        - CfExecute stall      - hive load → HKCU\Classes COM hijack
- installer/MSI repair    - HKCU REG_EXPAND_SZ poison   - hardlink swap        - protected read → DPAPI/creds → lateral
- updater manifest fetch  - hardlink to victim file     - (deterministic       - weak section OOB → DWM/cross-session
- IOCTL file/reg op       - weak-DACL section write        via cfapi)          - pre-auth WinRE config → unlocked shell
```

For each hypothesis you MUST write:
- **Claim** (one sentence, falsifiable): "Because X does Y without impersonation, a
  standard user can Z to get SYSTEM."
- **Evidence so far**: the decompiled function, line, import, or data-flow that suggests
  it — cite the idalib finding. If purely inferred, say so.
- **Kill condition**: the single observation that would disprove it (e.g. "it opens with
  `FILE_FLAG_OPEN_REPARSE_POINT`", "it impersonates at line N", "the path is fixed and
  not user-influenced").
- **Cheapest next test**: static (decompile one more function) or dynamic (one Procmon
  filter). Prefer the cheapest disproof first.
- **Rank**: likelihood × impact × novelty (is this the shipped bug, an adjacent verb, or
  genuinely new?).

Spawn subagents to draft hypotheses per subsystem in parallel when the target is large
(one agent per DLL/dispatch region), but **you** form and rank the final list.

### Phase 3 — Kill the cheap ones statically
For each hypothesis, do the cheapest disproof first with idalib: `decompile` the
suspected function and confirm/deny impersonation, reparse-flag, path re-validation, and
that attacker input truly reaches the sink (`trace_data_flow`). Cross off every
hypothesis whose kill condition fires. Report the dead ones honestly — a killed
hypothesis is a result.

### Phase 4 — Dynamic confirmation (on the user's VM)
For survivors, confirm the privileged op happens on the attacker-influenceable path with
the caller's context, via Procmon (filter on the target PID; watch Operation =
`CreateFile`/`SetReparsePoint`/`RegLoadKey`, Path, and the Integrity/Token detail). Then
build the smallest PoC that proves the *primitive* (arbitrary write/delete/read as
SYSTEM), not yet full SYSTEM. Use `references/PRIMITIVES.md` for the redirect + race-win
recipes, and prefer the **cfapi FETCH_DATA oracle** over oplocks for reliability.

### Phase 5 — Convert to SYSTEM + validate
Turn the primitive into SYSTEM using the conversion column (DLL plant, delete→reload,
SAM→linked-token→service, hive→COM hijack). Then run the finding through the
`triage-validation` skill's gates: is the primitive real, is the conversion real, is it
reachable by a standard user with no prior admin, does it survive a reboot/clean profile?
Kill anything that needs pre-existing admin or an unrealistic precondition.

### Phase 6 — Report
Write it up with `report-writing`. Impact-first, primitive-proven, with the exact
decompiled evidence and the PoC steps. Recommend the fix (almost always: impersonate the
caller before the op; open with `FILE_FLAG_OPEN_REPARSE_POINT`; re-verify final path;
tighten the object DACL). If framing as a patch bypass of a known CVE, borrow `cve-hunt`.
Never auto-submit; the human decides.

---

## Rules of engagement
- **Reproduced or it didn't happen.** Never claim SYSTEM without a demonstrated conversion.
- **Verified vs inferred** on every claim. idalib evidence is verified; "probably" is inferred.
- **Cheapest disproof first.** Most hypotheses die in one decompile — do that before any PoC.
- **Impersonation is the north star.** ~90% of this bug class is a service that forgot to
  impersonate. Grepping for the *absence* of impersonation around a privileged op is the
  fastest path to a real bug.
- **VM-only for detonation.** Embedded ISOs / OLE macro docs / planted DLLs are live.
- Record dead hypotheses in the report; they show coverage and prevent re-treading.

## Pointers
- `references/PRIMITIVES.md` — the full primitive toolkit with API sequences and idalib queries.
- `references/HYPOTHESIS_TEMPLATE.md` — the hypothesis format + a worked example + a starter
  set of ranked hypotheses (the bug class is distilled from public MSNightmare LPE research).
- The primitive names (MpClient clean, cfapi FETCH_DATA oracle, object-manager symlink +
  globalroot, User Shell Folders indirection, weak-DACL section) are documented inline in
  `references/PRIMITIVES.md` so the skill is self-contained.
