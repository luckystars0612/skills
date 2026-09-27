---
name: bin-vuln-hunt
description: >
  Hunt new CVEs and 0-days in Windows kernel drivers (.sys), PE binaries (.exe/.dll), and
  software bundles using the REverie framework and IDA/WinDbg/x64dbg MCP tooling. Map the
  attack surface (IOCTLs, exports, RPC interfaces, named pipes, file/registry ops), screen
  for vulnerable patterns (memory corruption, integer overflow, UAF, race conditions, auth
  bypass, info leak), generate ranked hypotheses, then confirm or kill each with binary
  evidence. Uses REverie's Package/Component/Hypothesis/Chain domain model, its knowledge
  base for cross-session learning, and its Advisory writer for vendor-ready reports. Pure
  vulnerability research — no weaponization, no exploit payloads, no EDR/AV killing. Use
  when the user hands you a binary, a driver, a software package, or a product name and
  wants to find new bugs, not when they want a BYOVD killer (use byovd-killer) or an LPE
  hypothesis (use win-lpe-hunt).
  中文触发词：漏洞挖掘、二进制分析、驱动分析、PE分析、CVE挖掘、0day、安全审计、
  逆向分析、IOCTL漏洞、内核漏洞、缓冲区溢出、整数溢出、UAF、竞态条件、模糊测试、REverie。
disable-model-invocation: true
tags: [vulnerability-research, binary-analysis, driver, pe, kernel, ioctl, cve, 0day, ida, idalib, reverse-engineering, fuzzing, memory-corruption, integer-overflow, uaf, race-condition, info-leak, reverie]
---

# bin-vuln-hunt — find new CVEs in drivers, PE files, and software bundles

You are performing **binary vulnerability research** on a Windows target: a kernel driver
(`.sys`), a userland PE (`.exe`/`.dll`), or a software bundle (installer, service pack,
multiple interacting binaries). The goal is to **discover new, previously unreported
vulnerabilities** — not to weaponize them or build exploits, but to produce a clear,
reproducible finding suitable for responsible disclosure.

The unifying target model:

> **A binary accepts input from a lower-privilege boundary — an IOCTL buffer, a network
> packet, a file format, an RPC call, a named-pipe message, a registry value, a command-
> line argument, an environment variable — and processes that input with insufficient
> validation. The gap between what the code assumes about the input and what an attacker
> can actually supply is the vulnerability.**

Your job is to (1) **map every input boundary** the binary exposes, (2) **screen each
boundary for known-vulnerable patterns** using import/code signatures, (3) **generate
ranked hypotheses** — each pairing a specific input path with a specific bug class and a
predicted consequence, (4) **confirm or kill each hypothesis** with binary evidence from
decompilation and data-flow analysis, and (5) **write up confirmed findings** as
structured vulnerability reports with reproduction steps.

**Authorization gate (do this first, one line):** confirm the target binary or product is
one the user is authorized to test — their own software, a licensed product, open-source
code, a research VM, or an in-scope engagement. If a step would require dynamic testing on
a system the user does not own, stop and say so.

---

## Inputs this skill expects

- A **target**: a path to a `.sys`, `.exe`, `.dll`, or a directory containing a software
  bundle; a driver/product name; or "audit this binary". If given only a name, help the
  user obtain the binary (vendor download, NuGet, driver store) before analyzing — you
  reason from the actual binary, not from memory.
- Tooling in this environment:
  - **REverie** (`C:\Users\a\Desktop\REverie`) — the researcher's own agentic RE framework
    for coordinated-disclosure vulnerability research. Use its domain model, knowledge base,
    and reporting pipeline throughout. See `references/REVERIE_INTEGRATION.md` for the mapping
    between this skill's phases and REverie's types.
  - **IDA Pro via `idalib` MCP** — `mcp__plugin_ida-pro-mcp_idalib__*` (short names below:
    `idb_open`, `survey_binary`, `imports_query`, `imports`, `decompile`, `xrefs_to`,
    `xref_query`, `trace_data_flow`, `find_regex`, `search_text`, `list_funcs`, `func_query`,
    `entity_query`, `disasm`, `get_string`, `callgraph`). Claude can read any binary.
    REverie wraps these as `static.*` capabilities via `reverie-tools-ida`.
  - **WinDbg via `mcp-windbg` MCP** for live kernel/userland debugging on a VM
    (`open_kd_session`/`open_session`, `run_kd_command`/`run_command`) — set breakpoints on
    suspicious paths, trace data flow dynamically, catch crashes. REverie wraps these as
    `dynamic.kd_*` capabilities via `reverie-tools-windbg`.
  - **x64dbg via `x64dbgmcp` MCP** for userland dynamic analysis (breakpoints, stepping,
    memory inspection). REverie wraps these as `dynamic.*` capabilities via
    `reverie-tools-x64dbg` (managed provider — server appears after x64dbg loads the plugin).
  - **REverie CLI** — `reverie info <path>` for PE triage (SHA256, sections, imports, packing
    heuristic), `reverie capabilities` for the assembled tool catalog, `reverie explore` for
    the full agentic loop.
  - Bash / PowerShell on the user's Windows machine for running test harnesses, Procmon
    traces, building fuzz stubs.
  - Sibling skills: `byovd-killer` (if the finding is a weaponizable driver primitive),
    `win-lpe-hunt` (if the finding leads to an LPE), `cve-hunt` (if starting from an
    existing advisory).

---

## The loop (each phase gates the next)

### Phase 0 — Scope + intake
State the target, its vendor/signer, and authorization in one line. Identify the binary
type: kernel driver, userland service, DLL loaded by a privileged process, COM server,
installer, etc. The type determines which attack-surface boundaries matter. Record SHA256.

**REverie model.** Create a `Package` for the target:
- Single binary → `Package::single(target)` with the appropriate `ComponentRole`
  (`KernelDriver`, `Service`, `Dll`, etc.).
- Software bundle → `Package` with multiple `Component`s connected by `Relation` edges
  (`Loads`, `IoctlTo`, `IpcTo`, `TrustsInputFrom`). List every binary and note which run
  elevated or as SYSTEM.

Run `reverie info <path>` (or `recon.pe_info` capability) for automated PE triage: SHA256,
sections with entropy (packing heuristic), imports, and basic identification. This replaces
manual `dumpbin` / `sigcheck` for the initial pass.

**Knowledge base check.** Query `knowledge.search` / `knowledge.suggest_leads_for` against
the target's vendor, product, and platform. Prior findings in the same binary or from the
same vendor are *gold* — they tell you what the developers worried about and, more
importantly, what they *didn't*. Prior `Technique`s with high confidence get seeded as
hypotheses automatically by `KnowledgeLeadGenerator`.

For drivers: note the OS build (structure offsets and available APIs vary between builds).
Check the Microsoft driver block list and any known advisories.

### Phase 1 — Attack surface mapping (the cheap overview)
Before deep reversing, map every input boundary the binary exposes. The goal is a table:
**boundary → reach → trust level → handler function**.

`idb_open` then `survey_binary` for the overview. Then:

**For kernel drivers** (see `references/ATTACK_SURFACE.md` §1):
- `imports_query` for `IoCreateDevice`/`IoCreateDeviceSecure` → device path → reachable
  from usermode via `CreateFile`.
- MajorFunction dispatch table from the initializer → which IRP types are handled:
  - `IRP_MJ_DEVICE_CONTROL` (index 14) — DeviceIoControl, the primary attack surface.
  - `IRP_MJ_CREATE` (0), `IRP_MJ_CLOSE` (2) — often overlooked, can carry state bugs.
  - `IRP_MJ_READ` (3), `IRP_MJ_WRITE` (4) — alternative data paths (WriteFile-driven).
  - `IRP_MJ_INTERNAL_DEVICE_CONTROL` (15) — only from kernel callers, lower priority.
- IOCTL map: every IOCTL code → handler → buffer method (low 2 bits) → input/output sizes.
- `IoCreateSymbolicLink` → DOS device name → user-mode path `\\.\X`.
- `IoCreateDeviceSecure` SDDL → access restrictions.
- Registered callbacks: `PsSetCreateProcessNotifyRoutine`, `CmRegisterCallbackEx`,
  `ObRegisterCallbacks` — these are *code that runs on external events*, another input path.

**For userland PE files** (see `references/ATTACK_SURFACE.md` §2):
- Exports (DLLs): every exported function is a potential entry point if the DLL is loaded
  by a higher-privilege process (DLL side-loading, COM).
- RPC interfaces: `imports_query` for `RpcServerRegisterIf*` / `NdrServerCall*` → find the
  IDL-derived dispatch table → each method is an input boundary.
- Named pipes: `CreateNamedPipe` → pipe name → reachable from lower-privilege callers?
- File operations: `CreateFile`, `MoveFile*`, `DeleteFile*`, `SetFileAttributes*` on
  user-writable paths → symlink/junction/TOCTOU surface (→ hand off to `win-lpe-hunt`).
- Registry operations: `RegOpenKeyEx`, `RegSetValueEx` on user-writable keys.
- Network listeners: `bind`, `listen`, `accept`, `WSARecv` → network-reachable input.
- COM interfaces: `DllGetClassObject` exports, `IUnknown` vtable → remotely activatable?
- Command-line / environment: `GetCommandLine`, `GetEnvironmentVariable` → injection if
  the binary runs elevated.

**For software bundles** (see `references/ATTACK_SURFACE.md` §3):
- Map the privilege topology: which processes run as SYSTEM/admin, which as user, and
  the IPC channels between them (named pipes, shared memory, COM, window messages).
- Focus on **cross-privilege boundaries**: a user-privilege process sending data to a
  SYSTEM-privilege process is the highest-value target.

Output: a numbered attack-surface table with columns `#`, `Boundary`, `Reach`, `Trust`,
`Handler`, `Priority`. Rank by: attacker reachability × impact × code complexity (more
code = more bugs).

### Phase 2 — Pattern screening (the fast hypothesis generator)
For each high-priority boundary from Phase 1, screen for known-vulnerable patterns.
This is import-level and shallow-decompile screening — fast, not deep. See
`references/BUG_CLASSES.md` for the full catalog with signatures.

**Memory corruption patterns:**
- **Buffer overflow (stack):** `memcpy`/`RtlCopyMemory`/`memmove` where the size comes from
  user input and the destination is a stack buffer (local variable). Check: does the size
  exceed the buffer allocation? Is there a bounds check?
- **Buffer overflow (pool/heap):** `ExAllocatePoolWithTag`/`HeapAlloc`/`malloc` with a
  user-controlled size, followed by a copy of user-controlled length. Check: does alloc
  size match copy size? Is the user length validated against the allocation?
- **Integer overflow:** arithmetic on user-supplied sizes before allocation/copy. Classic:
  `alloc(count * element_size)` where `count` is user-controlled → wraparound to a small
  allocation → subsequent copy overflows. Also: `size + header_len` overflow, signed/
  unsigned confusion (`(int)user_len < 0` bypasses `if (user_len > max)`).
- **Off-by-one:** loop bounds `<=` vs `<`, null-terminator not counted in size checks.
- **Use-after-free:** pool/heap allocations freed in one code path while still referenced
  from another. See `references/BUG_CLASSES.md` §UAF for the race-condition variant
  (concurrent handlers without locking).
- **Double free:** error-path cleanup that frees a buffer already freed on the success path.
  `find_regex` for paired `ExFreePoolWithTag`/`HeapFree` calls on the same tag/pointer.
- **Type confusion:** a union or variant field used as the wrong type. In drivers: an IOCTL
  handler that casts the input buffer to different struct types depending on a sub-command
  but shares a single size check.
- **Uninitialized memory:** output buffer not fully initialized before `IoStatus.Information`
  copies it back → kernel pool pointer leak (KASLR bypass). See `references/BUG_CLASSES.md`
  §InfoLeak.

**Logic / validation patterns:**
- **Missing or wrong size check:** the IOCTL handler doesn't validate
  `InputBufferLength` / `OutputBufferLength` before reading/writing the buffer.
- **TOCTOU (time-of-check-time-of-use):** two accesses to user-mode memory (METHOD_NEITHER)
  — the second can see a different value if the user swaps it between the check and the use.
  `ProbeForRead` + read is a single check; a *second* read from the same user VA is the bug.
- **Missing `ProbeForRead`/`ProbeForWrite`:** METHOD_NEITHER IOCTLs that dereference
  `Type3InputBuffer` without probing → user can supply a kernel-mode address → arbitrary
  kernel read/write.
- **Requestor mode not checked:** `ExGetPreviousMode` not called, or called but the result
  not used to gate a dangerous operation → user-mode caller gets kernel-mode privileges.
- **NULL pointer dereference (kernel):** a function returns NULL on failure (e.g.,
  `MmGetSystemAddressForMdlSafe`) and the caller doesn't check → BSOD, or on older systems
  with mappable NULL page, code execution.
- **Path traversal / injection:** string operations on file paths from user input without
  canonicalization → `..\..\` escape or symlink following.

**Concurrency patterns:**
- **Race condition (driver):** shared state (global list, device extension field) accessed
  from multiple dispatch handlers (CREATE/CLOSE/IOCTL) without synchronization. The UAF
  variant is the most exploitable.
- **Race condition (userland):** TOCTOU on file/registry operations between check and use.

For each pattern hit, record a **hypothesis**: `H<n>: <boundary> × <bug class> →
<predicted consequence> — INFERRED`. This is the target list for Phase 3.

**REverie model.** Each hypothesis maps to a `Hypothesis` in the session. Spawn an
`InvestigationThread` per hypothesis — they can run in parallel and branch from each other.
The `Stage` label (`Hypothesize` → `StaticProbe` → `DynamicProbe` → `Correlate`) tracks
what each thread is doing, but transitions are never gated — jump freely between static and
dynamic views. If two findings in different components compose into a greater impact (e.g.,
user-reachable service IOCTL → kernel R/W), create a `Chain` linking the `ChainLink`s.

### Phase 3 — Deep analysis (confirm or kill each hypothesis)
Take each hypothesis from Phase 2, highest-priority first. `decompile` the handler chain
from boundary to sink. Trace the user-controlled data through every function call.

For each hypothesis, answer three questions:
1. **Is the data actually attacker-controlled at the sink?** Trace from the input boundary
   to the dangerous operation. If the data is transformed, copied, or checked along the way,
   note each transform. `trace_data_flow` is the primary tool.
2. **Is the dangerous operation actually reachable?** Check every branch condition between
   the boundary and the sink. A size check that caps the user length at a safe value kills
   the hypothesis. A check that compares the wrong field doesn't.
3. **What is the actual consequence?** A stack overflow in a kernel driver → BSOD or code
   execution. A heap overflow in a userland service → crash or code execution in the service
   context. An info leak → KASLR bypass. A NULL deref in kernel → BSOD (DoS). Be specific.

Mark each hypothesis:
- **CONFIRMED** — the data flow from input to sink is verified in the decompilation, no
  intervening check blocks it, and the consequence is clear. Include the exact function
  addresses, the decompiled code snippet, and the data-flow chain.
- **KILLED** — an intervening check blocks the attack, or the data is not actually
  attacker-controlled at the sink. State what killed it.
- **INFERRED (needs dynamic)** — static analysis is ambiguous (e.g., the check may or may
  not be sufficient depending on runtime state). Flag for dynamic validation in Phase 4.

### Phase 4 — Dynamic validation (on the VM, optional but preferred)
For CONFIRMED and INFERRED findings, validate dynamically if the user has a test VM.

**REverie lab harness.** If the user has configured a `LabProfile` (VM target with
`SshTransport` or `LocalTransport`), use `dynamic.run_poc` to upload and run the PoC in one
call. The lab harness ties the userland PoC execution to kernel-effect observation via the
WinDbg KD provider, so a driver crash and its cause are correlated automatically. Build the
fuzz harness from `templates/fuzz_harness.rs`, then `run_poc` delivers it.

**For kernel drivers:**
- Load the driver (`sc create`/`sc start` or via the product installer).
- Craft a test IOCTL with the malformed input predicted by the hypothesis.
- Attach WinDbg (`dynamic.kd_*` / `open_kd_session`), set a breakpoint on the handler,
  single-step through the vulnerable path.
- Observe: does the overflow/UAF/NULL-deref actually occur? What crashes? What's the
  register state?
- **If it crashes → CONFIRMED dynamically.** Promote the `Hypothesis` to a `Finding`.
- **If it doesn't crash → investigate why.** A runtime check not visible in the static
  decompile? A different code path taken? Update the hypothesis.

**For userland binaries:**
- Run the binary under a debugger (x64dbg via `dynamic.*` capabilities, or WinDbg usermode).
- Craft input (file, RPC call, pipe message) to trigger the predicted path.
- Enable page heap (`gflags /p /enable target.exe /full`) for heap corruption detection.
- Observe: crash? Access violation? Heap corruption detected?

**For race conditions:**
- Multi-threaded stress test: spawn N threads hitting the racy paths concurrently.
- Kernel: `!poolused` before and after to detect pool leaks (indicator of UAF).
- Procmon for file/registry TOCTOU: filter on the target's operations, look for
  interleaved user operations on the same path.

### Phase 5 — Severity assessment + write-up
For each confirmed finding, assess severity:

**CVSS v3.1 base score** (estimate):
- Attack Vector: Local (driver IOCTL), Network (network listener), Adjacent.
- Attack Complexity: Low (reliable trigger), High (race condition needed).
- Privileges Required: None / Low / High.
- User Interaction: None / Required.
- Impact: Confidentiality / Integrity / Availability.

**Bug class and CWE:**
- CWE-120: Buffer Copy without Checking Size (stack overflow)
- CWE-122: Heap-based Buffer Overflow
- CWE-190: Integer Overflow
- CWE-416: Use After Free
- CWE-415: Double Free
- CWE-476: NULL Pointer Dereference
- CWE-908: Uninitialized Resource (info leak)
- CWE-362: Race Condition (concurrent access)
- CWE-822: Untrusted Pointer Dereference (missing probe)
- CWE-284: Improper Access Control

**Write it up** two ways:
1. **REverie advisory** — use `report.write_advisory` capability to generate a polished,
   vendor-ready Markdown advisory with CVSS scoring (computed via `Cvss::from_vector`).
   This is the document the researcher sends to the vendor.
2. **Internal record** — fill `templates/VULN_REPORT.md` with full technical detail
   (decompiled code, data-flow trace, exact reproduction steps). This is the researcher's
   own reference.

Every claim is VERIFIED (seen in the binary) or INFERRED (predicted, needs dynamic
confirmation). Include:
- Affected binary, version, SHA256.
- The vulnerable code path: function addresses, decompiled snippets.
- The exact input that triggers the bug (IOCTL code + malformed buffer, or crafted file).
- Root cause: why the code is wrong (missing check, wrong size, no lock).
- Impact: what an attacker achieves (BSOD/DoS, info leak, code execution, LPE).
- Suggested fix: what the vendor should change.

The researcher decides disclosure. Never auto-submit to any vendor, bug tracker, or
advisory database.

### Phase 6 — Variant analysis (bonus)
If a finding is confirmed, look for variants:

- **Same bug, other IOCTLs:** if one IOCTL handler has a buffer overflow, check every other
  IOCTL handler in the same driver for the same pattern. Developers often copy-paste.
- **Same bug, other versions:** if the binary has multiple versions available, diff the
  vulnerable function between versions. Was it always there? Was it introduced in a specific
  version? Is it fixed in a newer version?
- **Same bug class, sibling binaries:** if a driver from vendor X has a race condition, check
  other drivers from vendor X — the same developer likely made the same mistake.
- **Patch bypass:** if the binary has a known CVE fix, check whether the fix is complete. The
  fix tells you what the developer thought was dangerous; check what they *didn't* fix. (For
  deep patch-bypass analysis, hand off to `cve-hunt`.)

### Phase 7 — Distill (feed the knowledge base)
After findings are written up, distill them back into REverie's knowledge base so future
sessions start smarter:

- **Classify novelty** — `PossiblyNovel` (first of its `BugClass` on this `Platform`),
  `Variant` (similar to a known technique), or `Known` (text similarity ≥ 0.6 with an
  existing technique).
- **Mint technique** — if novel, create a reusable `Technique` with preconditions (what a
  binary needs to have for this bug class to apply) and the platform/vendor context.
- **Mint skill** — create a `Skill` (check procedure) from the technique, so future sessions
  have a concrete checklist to follow.
- **Record finding** — `FindingRecord` with title, class, platform, target SHA256, summary.
- **Reinforce** — bump `confirmed` counter on the `Technique`s that seeded the leads that
  became findings. This raises their confidence for future `suggest_leads_for` rankings.
- **Grow platform model** — mark explored surfaces, add discovered invariants and
  mitigations, note gaps that remain.

Use `GrowingDistiller` (extends `DefaultDistiller` with platform model growth). Persist with
`engine.persist(&session)` to save both the session and the updated knowledge base.

```sh
# Or via CLI:
reverie explore driver.sys --store C:\research\store  # auto-distills at the end
```

---

## Rules of engagement

- **VERIFIED vs INFERRED on every claim.** A code path seen in the decompilation is VERIFIED.
  A predicted crash that hasn't been dynamically tested is INFERRED. Never claim a bug is
  confirmed without showing the evidence.
- **Hypothesis-driven, not exhaustive.** Don't decompile every function. Screen fast in
  Phase 1–2, go deep only on high-probability hypotheses. Kill bad hypotheses early.
- **Be honest about severity.** A NULL-pointer BSOD in a driver is a DoS, not code execution
  (on modern Windows with NULL page unmapped). An info leak is a KASLR bypass aid, not an
  RCE. Overclassification erodes credibility.
- **No weaponization.** This skill finds vulnerabilities. It does NOT build exploits,
  shellcode, or weaponized payloads. If the user wants to turn a finding into a BYOVD killer,
  hand off to `byovd-killer`. If they want an LPE exploit, hand off to `win-lpe-hunt`.
- **Responsible disclosure.** Produce a report the researcher can submit. Never auto-submit
  to any vendor, bug tracker, or advisory database. The human decides when and how to
  disclose.
- **VM-only for dynamic testing.** Dynamic validation (crashing a driver, stress-testing
  race conditions) happens only in an isolated VM the user owns.

## Pointers
- `references/BUG_CLASSES.md` — the full catalog of bug classes with import/code signatures,
  decompiler patterns, and idalib queries to find them.
- `references/ATTACK_SURFACE.md` — how to map the attack surface for drivers, userland PEs,
  and software bundles; the boundary → handler mapping methodology.
- `references/PE_ANALYSIS.md` — PE structure analysis: headers, sections, imports, exports,
  resources, version info, digital signatures, and what each reveals about vulnerability
  potential.
- `references/REVERIE_INTEGRATION.md` — how each skill phase maps to REverie's domain model,
  capabilities, and CLI commands; the complete capability ID catalog.
- `templates/VULN_REPORT.md` — the structured vulnerability report template (internal record).
- `templates/fuzz_harness.rs` — a template fuzzing harness for driver IOCTLs (Rust, using
  the `windows` crate).
- **REverie repo** (`C:\Users\a\Desktop\REverie`) — the framework source; see
  `docs/ARCHITECTURE.md` for the design and `docs/ROADMAP.md` for milestone status.
