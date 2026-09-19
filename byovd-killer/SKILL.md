---
name: byovd-killer
description: Reverse a Windows kernel driver into a working BYOVD (Bring Your Own Vulnerable Driver) AV/EDR process killer. Screen a .sys for a process-kill or arbitrary-physical-memory primitive, reverse the IOCTL dispatch chain (DriverEntry → device/symlink → MajorFunction table → IOCTL handler → the dangerous sink), extract the device path + IOCTL code + input-buffer layout, classify the kill primitive into a tier, then emit a thin Rust killer on the byovd-lib DriverConfig trait (or a standalone PoC for physical-R/W and handle-stomp tiers). Use when the user hands you a driver, a driver name, or a LOLDrivers entry and wants a process/EDR killer, an IOCTL map, a byovd-lib DriverConfig, or an assessment of whether a driver is weaponizable. Also for extending the BlackSnufkin/BYOVD repo with a new *-Killer. 中文触发词：BYOVD、脆弱驱动、进程终结、EDR杀软对抗、驱动逆向、IOCTL、物理内存读写、SSDT。
tags: [byovd, windows, kernel-driver, edr, av, process-kill, ioctl, ida, idalib, reverse-engineering, ssdt, physical-memory, rust, loldrivers]
---

# byovd-killer — turn a vulnerable driver into a process killer

You are reverse-engineering a signed Windows kernel driver to determine whether it can be
abused as a **BYOVD process/EDR killer**, and if so, producing a working PoC. The unifying
target model, distilled from the `BlackSnufkin/BYOVD` collection (24 reproduced killers) and
its documented A–Z methodology:

> **A signed third-party driver exposes a kernel primitive to an unprivileged-or-admin
> user-mode caller — a direct process-terminate IOCTL, a handle-table manipulation, or
> arbitrary physical/virtual memory read-write — with weak or absent authorization. That
> primitive is repurposed to terminate a protected process (PPL Defender, an EDR agent)
> that user mode cannot touch, because the action executes in ring 0 under the driver's
> signature and below the OS callback layer.**

Your job is NOT just to fire one IOCTL. It is to (1) **decide the driver is weaponizable**
from its imports and dispatch, (2) **extract the three facts a killer needs** — device path,
IOCTL/command code, and input-buffer layout (where the PID lives) — with binary evidence,
(3) **classify the kill primitive into a tier** so you pick the right PoC shape, and (4)
**produce a killer** — a ~50-line `DriverConfig` on `byovd-lib` for the common case, or a
standalone exploit for the physical-R/W and handle-stomp tiers. Verified vs inferred, always.

**Authorization gate (do this first, one line):** confirm the driver and the machine you will
run it on are ones the user is authorized to test — their own box, a research VM, a licensed
product's driver, or an in-scope engagement. This class of tool disables security software and
loads a known-vulnerable driver; **detonate only in an isolated VM the user owns**, never
against a third party's endpoint. If a step would touch a system the user does not own, stop
and say so. Terminating Defender/EDR on a production host is out of scope by default.

---

## Inputs this skill expects

- A **target**: a path to a `.sys`, a driver/product name, a LOLDrivers entry, or "assess
  this driver". If given only a name, help the user obtain the `.sys` (LOLDrivers hash,
  vendor package) before reversing — you reason from the actual binary, not from memory.
- Tooling in this environment:
  - **IDA Pro via `idalib` MCP** — `mcp__plugin_ida-pro-mcp_idalib__*` (short names below:
    `idb_open`, `survey_binary`, `imports_query`, `imports`, `decompile`, `xrefs_to`,
    `xref_query`, `trace_data_flow`, `find_regex`, `search_text`, `list_funcs`, `func_query`,
    `entity_query`, `disasm`, `get_string`, `callgraph`). Claude can read any binary.
  - **WinDbg via `mcp-windbg` MCP** for live kernel confirmation on a VM (`open_kd_session`,
    `run_kd_command`) — resolve `\Device\X`, dump the dispatch table, watch the IOCTL land.
  - Bash / PowerShell on the user's Windows VM for `sc create`/`sc start`, `cargo build`,
    running the PoC. `OSRLoader` is an alternative loader.
  - The **`byovd-lib`** crate (in the BYOVD repo) — the shared SCM-lifecycle + IOCTL-dispatch
    library your thin killers build on. See `references/BYOVD_LIB.md`.
  - Sibling skills: `ida-pro-mcp:idapython`, `win-lpe-hunt` (adjacent driver-IOCTL framing),
    `mcp-windbg-skills:kernel-debug`.

---

## The loop (each phase gates the next)

### Phase 0 — Scope + intake
State the target, its vendor/signer, and authorization in one line. Note the OS build you will
test on (kill primitives are build-sensitive: HVCI/VBS on Win11 24H2+ blocks code-exec tiers;
Win32k syscall stubs move between builds). Get the `.sys` on disk. Record its SHA256 and check
LOLDrivers / the Microsoft driver block list — a blocked driver still works as a PoC but won't
load on a machine that enforces the block list, which is worth stating up front.

### Phase 1 — Import screening (the cheap go/no-go gate)
Before any deep reversing, screen imports. `idb_open` then `imports` / `imports_query`. A
driver is a **process-killer candidate** if it imports a *terminate* primitive **and** a way
to get a process handle/pointer. A driver is a **memory-primitive candidate** (the powerful
tier) if it maps physical or arbitrary memory. Score against `references/KILL_PRIMITIVES.md`:

- **Direct-terminate imports** — `ZwOpenProcess`/`NtOpenProcess` **+**
  `ZwTerminateProcess`/`NtTerminateProcess` (Tier 1); or `PsLookupProcessByProcessId` +
  `ZwTerminateProcess`; or `ObOpenObjectByPointer` + terminate.
- **Handle-stomp imports** — `KeStackAttachProcess` + `ObSetHandleAttributes` + `ZwClose`
  (no terminate needed — yank a critical handle and the target faults, the `xhunter1.sys`
  pattern) (Tier 2).
- **Memory-primitive imports** — `MmMapIoSpace`, `MmMapMemoryDumpMdl`, `ZwMapViewOfSection`
  (on `\Device\PhysicalMemory`), `HalTranslateBusAddress`, `MmGetPhysicalAddress`,
  `__readmsr`/`__writemsr` intrinsics (Tier 3 — arbitrary R/W → data-only or code-exec kill).
- **UAF candidate imports** — `ExAllocatePoolWithTag` + `ExFreePoolWithTag` with list ops
  (`InsertTailList`/`RemoveEntryList`) across CREATE/CLOSE/IOCTL handlers. The tell is absent
  or inconsistent mutex — list accessed from multiple dispatch paths without
  `ExAcquireFastMutex`/`KeAcquireSpinLock`. UAF → pool spray → kernel R/W (Tier 3).
- **PCI/SMN/SMU candidate (AMD SoC)** — `HalSetBusDataByOffset` + `HalGetBusDataByOffset`
  (HAL module). If writing PCI config 0xC4/0xC8 on bus 0 dev 0, driver accesses AMD's SMN
  register bus → SMU firmware mailbox → potential hardware DMA write. See 3i in
  `references/KILL_PRIMITIVES.md`.
- **Info leak** — look for `IoStatus.Information = OutputBufferLength` in shared dispatch
  epilogue. If all IOCTLs hit this path, METHOD_BUFFERED IOCTLs return uninitialized
  NonPagedPool residue → instant KASLR bypass (see 3j in `references/KILL_PRIMITIVES.md`).

If none of these appear, the driver is likely not a killer; say so and stop (a killed target
is a result). Note that intrinsics (`__readmsr`, `movq cr3`) won't show as imports — grep the
disassembly (`find_regex` for `0F 32` rdmsr, `0F 20`/`0F 22` cr moves) when you suspect a
memory-primitive driver with a thin import table.

### Phase 2 — Reverse the dispatch chain (extract device path + IOCTL + buffer layout)
Follow the six-step chain from `references/DRIVER_ANATOMY.md`. Each step has the exact idalib
query. The goal is the three facts a killer needs, each **VERIFIED** against the binary:

1. **DriverEntry** — the PE entry; find the real init (often a tail call).
2. **Init** — `RtlInitUnicodeString` + `IoCreateDevice` gives `\Device\X`;
   `IoCreateSymbolicLink` gives `\DosDevices\X` → the user-mode path `\\.\X`. The
   `DriverObject->MajorFunction[...]` assignments give the dispatch routine; index **14
   (0xE) = IRP_MJ_DEVICE_CONTROL** is the one you want (15/0xF = INTERNAL_DEVICE_CONTROL).
3. **Dispatch** — inside the `MajorFunction[14]` handler, find where it reads the IOCTL code
   (`IoGetCurrentIrpStackLocation`, then `Parameters.DeviceIoControl.IoControlCode`) and
   branches. Map every IOCTL code to its handler (the IOCTL map).
4. **IOCTL handler** — for the terminate/memory branch, note the **size check** (often the only
   validation) and how it reaches the input buffer (`Type3InputBuffer` for
   METHOD_NEITHER, `AssociatedIrp.MasterIrp`/`SystemBuffer` for buffered — the low 2 bits of
   the IOCTL code tell you the method).
5. **The sink** — `decompile` the dangerous function. Note the **exact offset** the PID is read
   from in the input buffer (`*(a1 + 4)` → PID at +4), whether the input is binary DWORD, a
   u64, an ASCII string, or a process **name**, and any magic value it checks.
6. **Auth check** — is there a caller check (`SeSinglePrivilegeCheck`, a shared-secret in the
   buffer, an SDDL on the device via `IoCreateDeviceSecure`, a requestor-mode check)? Absence
   is what makes it exploitable; presence tells you what the killer must satisfy.

Record everything in `templates/DRIVER_PROFILE.md`. If the sink is not a terminate but a
memory map/write, you're in Tier 3 — the "IOCTL" gives you a physical/virtual R/W primitive and
the kill is a second layer you build on top (Phase 3).

### Phase 3 — Classify the kill primitive into a tier
Pick the tier from `references/KILL_PRIMITIVES.md`; it decides the PoC shape:

- **Tier 1 — Direct kill IOCTL.** Driver terminates by PID (or name) for you. The killer is a
  thin `byovd-lib` `DriverConfig`: device path, IOCTL code, `build_ioctl_input` placing the PID
  at the reversed offset. ~90% of the repo. Works against PPL because the terminate runs in
  ring 0.
- **Tier 2 — Handle / object stomp.** No terminate export; the driver lets you attach to a
  target and close/alter its handles (`KeStackAttachProcess` + strip `ProtectFromClose` +
  `ZwClose`), or open a full-access handle to a protected process. The target dies indirectly.
  Standalone PoC (custom flow, often `IRP_MJ_WRITE` not DeviceIoControl). PPL-capable.
- **Tier 3 — Arbitrary memory R/W.** The IOCTL maps physical memory (`MmMapIoSpace`,
  `\Device\PhysicalMemory`, or `HalTranslateBusAddress` fail-open with
  `InterfaceType=0xFFFFFFFF`). You build the kill yourself in user mode: brute/derive kernel
  CR3, resolve ntoskrnl + exports, then either **data-only** (patch a Shadow SSDT entry through
  an `FF 25` thunk and swap its IAT slot via physical write to chain
  `PsLookupProcessByProcessId`→`PsTerminateProcess`→`ObfDereferenceObject` — no shellcode, HVCI-
  safe) or **code-exec** (hijack a Win32k syscall E9/indirect stub → trampoline in CC padding →
  stage-2 shellcode in kernel pool that calls `PsTerminateProcess`). KASLR bypass via reading
  `IA32_LSTAR` MSR. This tier defeats PPL **and** EDR kernel callbacks because the terminate is
  `PsTerminateProcess` invoked from ring 0, not `NtTerminateProcess` from user mode.

### Phase 4 — Build the killer
- **Tier 1:** add a workspace member modeled on `templates/killer_main.rs`. Implement
  `DriverConfig` (name, file, `\\.\device`, `ioctl_code`, `build_ioctl_input`), plus the
  overrides the driver needs: `device_access` (some want `GENERIC_READ|GENERIC_WRITE` not
  `SERVICE_ALL_ACCESS`), `skip_unload` (drivers that BSOD on unload), `ignore_ioctl_error`
  (drivers that report failure on success, e.g. NSecKrnl), `ioctl_output_size`,
  `preflight_check` (LocalSystem-gated drivers). Call `byovd_lib::run(...)`. See
  `references/BYOVD_LIB.md` for the trait, the five typed IOCTL shapes, and the low-level API
  for custom flows.
- **Tier 2 / 3:** standalone crate with its own `[workspace]` and `[profile.release]`, not a
  member of the root workspace. Build the primitive (handle enumeration, or physical R/W +
  page-table walk), then the kill layer. `references/KILL_PRIMITIVES.md` carries the physical-
  R/W helpers, CR3 discovery, export resolution, SSDT/stub hijack, and the two-stage shellcode
  recipe as reproduced in `Astra64-Killer` and `Ktapi-Killer`.
- **Tier 3 Defender-specific (24H2+):** for a complete Defender kill that survives reboot, the
  PoC must: (a) neuter WdFilter's tamper protection CM callback (section 3d in
  `references/KILL_PRIMITIVES.md`), (b) disable all 6 services via kernel registry writes
  (section 3e), (c) clear FailureActions, (d) run a multi-round kill loop with delays matching
  SCM FailureActions timing (section 3e), and (e) follow SSDT safety rules — restore between
  operations, skip ObfDereferenceObject (section 3f). On 24H2, CM callbacks use a linked list
  (not EX_CALLBACK array), function pointer at node+0x28.

Match the repo's conventions: a `README.md` per killer (SHA256, LOLDrivers link, IOCTL, usage),
the `.sys` committed next to the binary, `opt-level="z"` + `lto` + `strip` + `panic="abort"`.

### Phase 5 — Validate on the VM
Load the driver (`sc create X type= kernel binPath= …\X.sys` + `sc start X`, or let the target
product load it for the LPE variant), run the killer against a benign target first
(`notepad.exe`), confirm the kill, then against the intended EDR/Defender process on the VM.
Confirm with WinDbg if available: break, `!drvobj`, `!devobj`, watch the dispatch. For Tier 3,
verify the primitive independently (read a known kernel VA, compare to `dd`) before trusting the
kill. Note PPL/HVCI behavior honestly: did `MsMpEng.exe` actually die and stay dead, or did the
service revive it? **Reproduced or it didn't happen.**

### Phase 6 — Write it up
Per-killer README + an entry in the repo's top-level `README.md` POC list and workspace
`Cargo.toml` members (for Tier 1; Tier 2/3 are standalone and only get the README entry). State:
device path, IOCTL/command, buffer layout with the PID offset, the tier, the auth gap that makes
it work, tested OS build, and what it kills (incl. whether PPL/HVCI held). VERIFIED vs INFERRED
on every claim. Never weaponize against anything but the user's own VM; the human decides
disclosure.

---

## Rules of engagement
- **Reproduced or it didn't happen.** No "this should kill Defender" — show the dead PID on the VM.
- **VERIFIED vs INFERRED** on every fact. A device path / IOCTL / PID-offset seen in the
  decompilation is VERIFIED; a guessed buffer layout is INFERRED until the kill confirms it.
- **Import screening first.** The two-import test (open-process + terminate) or the memory-map
  imports decide weaponizability in seconds — do it before deep reversing.
- **The PID offset is the whole game for Tier 1.** Most Tier-1 bugs are one size check and a
  `*(buf+offset)` read. Get that offset exact from the sink; a wrong offset = no kill.
- **Tier decides shape.** Don't force a physical-R/W driver into the `DriverConfig` trait, and
  don't hand-roll SCM for a plain terminate IOCTL — `byovd-lib` already does it.
- **VM-only for detonation.** The `.sys` is a known-vulnerable, often-signed driver and the tool
  disables security software. Isolated VM the user owns, always.

## Pointers
- `references/DRIVER_ANATOMY.md` — the six-step reverse chain with the exact idalib query per
  step, IOCTL method decoding, and how to read the PID offset out of the sink.
- `references/KILL_PRIMITIVES.md` — the tiered catalog: direct-terminate, handle-stomp, and the
  physical-R/W toolkit (CR3 brute, export resolution, Shadow-SSDT + Win32k-stub hijack, two-stage
  shellcode, HalTranslateBusAddress fail-open, LSTAR KASLR bypass), each with import signatures
  and the reproduced example from the BYOVD repo.
- `references/BYOVD_LIB.md` — the `DriverConfig` trait, the five typed IOCTL dispatch shapes, the
  trait-override cheatsheet, and the low-level API for standalone/custom flows.
- `templates/killer_main.rs` — a fill-in Tier-1 `DriverConfig` killer.
- `templates/DRIVER_PROFILE.md` — the record sheet for the three extracted facts + tier + auth gap.
