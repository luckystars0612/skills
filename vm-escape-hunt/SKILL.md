---
name: vm-escape-hunt
description: Hunt hypervisor guest-to-host escapes (VM escape) in the virtual device emulation of a Type-2 VMM — primarily VMware Workstation/Fusion's vmware-vmx, and the same bug class in VirtualBox/QEMU/Hyper-V device models. Encodes the modern escape recipe — a guest-controllable virtual device or backchannel makes the host VMM process do a memory operation on guest-supplied descriptors/counts/lengths without correctly bounding it (OOB write/read, integer over/underflow, UAF, type confusion, uninitialized read), chained info-leak + corruption to defeat host ASLR/LFH, then a hijacked device callback pointer + CFG-bypass gadget to host RCE. Generates MULTIPLE falsifiable hypotheses, each pairing an attack-surface device × a bug primitive × a leak × a control-flow-hijack, then validates them with IDA (idalib MCP) static analysis, patch-diffing, and WinDbg dynamic tracing. Use when auditing a hypervisor's device emulation, diffing a VMSA/CVE patch, or asking for new VM-escape ideas from vmware-vmx / VBoxDD / a QEMU device. 中文触发词：虚拟机逃逸、VMware逃逸、Guest到Host、虚拟化逃逸、hypervisor逃逸、虚拟设备漏洞、PVSCSI、vmxnet3、USB逃逸、backdoor后门通道
tags: [vm-escape, hypervisor, vmware, vmware-vmx, guest-to-host, device-emulation, ida, idalib, reverse-engineering, heap-grooming, lfh, cfg-bypass, patch-diff, pwn2own]
---

# vm-escape-hunt — hypervisor guest-to-host escape hypothesis engine

You are hunting a **guest-to-host escape**: code execution in the host VMM process
(`vmware-vmx.exe` for VMware Workstation/Fusion; `VBoxHeadless`/`VirtualBox` device DLLs;
a QEMU device model; a Hyper-V VSP) driven from an attacker who fully controls a guest VM.
The unifying bug class, distilled from a decade of public Pwn2Own / conference research
(see `references/ATTACK_SURFACE.md` and `references/HYPOTHESIS_TEMPLATE.md`):

> **A guest-controllable virtual device or backchannel makes the privileged host VMM
> process perform a memory operation sized or indexed by guest-supplied data —
> descriptor counts, scatter-gather lengths, ring indices, packet fields — without
> correctly bounding it.** The result is an OOB write/read, integer over/underflow, UAF,
> type confusion, or uninitialized-memory read inside `vmware-vmx`. A *modern* escape
> chains **two** bugs: an info-leak to defeat host ASLR and heap randomization, plus a
> memory-corruption to hijack control flow — usually by overwriting a **device callback /
> vtable function pointer**, then pivoting through a **CFG-whitelisted gadget** to
> `WinExec`/`system` in the host.

Your job is NOT to write one exploit. It is to **generate many falsifiable hypotheses**
about a target device, rank them, then kill or confirm each with binary evidence.
Reproduced or it didn't happen. VERIFIED vs INFERRED, always.

**Authorization gate (do this first, one line):** confirm the hypervisor build is one the
user is licensed to test and that all guest detonation happens in **an isolated guest VM
inside a research host the user owns**, with host snapshots. A working escape gives code
execution on the *host* — never run one against a machine the user does not own, and never
against shared/production virtualization infrastructure. If a step would touch a host the
user does not own, stop and say so.

---

## Inputs this skill expects

- A **target**: a path to a VMM binary/device module (`vmware-vmx.exe`, a `.dll`/`.so`
  device backend, `VBoxDD.dll`, a QEMU `hw/` binary), a product+version, a specific
  virtual device name ("PVSCSI", "vmxnet3", "UHCI", "SVGA", "VBluetooth"), **or a VMSA /
  CVE advisory to diff**, or "survey vmware-vmx".
- Available tooling in this environment:
  - **IDA Pro via `idalib` MCP** — tools are `mcp__plugin_ida-pro-mcp_idalib__*`
    (short names used below: `survey_binary`, `idb_open`, `decompile`, `imports_query`,
    `xrefs_to`, `xref_query`, `trace_data_flow`, `find_regex`, `search_text`,
    `list_globals`, `func_query`, `list_funcs`, `entity_query`, `disasm`, `callgraph`,
    `search_structs`, `read_struct`). Claude can read any binary.
  - **WinDbg via `mcp-windbg` MCP** — `open_cdb_dump`, `open_cdb_remote`,
    `run_cdb_command`, `open_kd_session`, `run_kd_command`. Attach to a live `vmware-vmx`
    (user-mode, cdb) or a crash dump to confirm a hypothesis dynamically.
  - **WebFetch / WebSearch** — pull the VMSA advisory, the CVE description, and prior
    public writeups for the target device so you diff against known work and check novelty.
  - Guest-side: the user drives the guest kernel driver (Linux `pvscsi`/`vmxnet3`/`uhci-hcd`,
    or a custom kernel module) to reach the device; you reason from what they paste.
  - Sibling skills: `cve-hunt` (patch-bypass framing when you're diffing a VMSA fix),
    `win-lpe-hunt` (the host RCE often lands as the VMX process → chain to SYSTEM there).

---

## The loop (each phase gates the next)

### Phase 0 — Scope + target intake
State the target, the hypervisor build/version, and authorization in one line. Decide the
mode:
- **Device-audit mode** — "find escapes in device X of vmware-vmx". Go to Phase 1.
- **Patch-diff mode** — "diff VMSA-2025-0013 / CVE-2025-41238". WebFetch the advisory,
  identify the device and bug class it names, obtain pre- and post-patch binaries, and
  jump straight to the changed function (borrow `cve-hunt` framing: the fix boundary is
  the richest hypothesis seed, and the *incomplete* fix / adjacent-verb is a fresh bug).

### Phase 1 — Static surface mapping with idalib
Open the binary (`idb_open`) and `survey_binary` for orientation. `vmware-vmx` is large;
scope to one device backend at a time. Map the four ingredients (full catalog + exact
idalib queries in `references/ATTACK_SURFACE.md`):

1. **The guest→host entry point.** How guest bytes reach this device handler:
   - **PIO/MMIO BAR handlers** — the register read/write callbacks of an emulated PCI
     device (PVSCSI, vmxnet3, SVGA, AHCI/SATA, NVMe, xHCI/UHCI/EHCI). `find_regex` for the
     device's register-dispatch switch; these are the front door.
   - **DMA reads of guest physical memory** — the VMM reads guest RAM for descriptor
     rings, scatter-gather lists, command blocks, URBs, packet buffers. This is where the
     *sizes and counts* come from, and it is the highest-yield surface.
   - **Backchannels** — GuestRPC / the VMware **backdoor** port (0x5658 `VX`), VMCI,
     vSockets, `vmx.capability.*` commands, the shared-folder (HGFS) protocol, drag-and-drop
     / copy-paste. `search_text` for `RPCI`, `TCLO`, `guestrpc`, `VMCI`, backdoor magic.
2. **The sized/indexed memory operation.** For each entry point, find the `memcpy`/
   `alloc`/loop that is sized or indexed by a guest field. Flag: a fixed-size buffer
   fed a guest count (PVSCSI S/G 0x4000 case); `alloc(n*sz)` where `n` is guest-controlled
   (integer overflow — vmxnet3 CVE-2025-41236); `len - x` where guest sets `len` (integer
   underflow — VMCI CVE-2025-41237); a ring index used without modulo/bounds.
3. **The missing/incorrect bound.** The tell is a guest length/count used **before or
   without** a range check, a `signed` comparison on a size, a check on the *requested*
   size but a copy of a *different* (coalesced/summed) size, or a struct-size mismatch
   between what the guest supplies and what the VMM stores (PVSCSI `{u64,u32,u32}` vs
   `{u64,u64}`). `decompile` the handler and read the arithmetic.
4. **Uninitialized / lifetime bugs.** Structs sent back to the guest that aren't fully
   zeroed (info-leak — vSockets CVE-2025-41239, historical uninitialized-buffer bugs);
   objects freed on one path but still referenced on another (UAF — Bluetooth/DHCP UAF
   chains); a handle/object table the guest can desync.

### Phase 2 — Generate MULTIPLE hypotheses (the core of this skill)
Do NOT stop at one. Emit **at least 5–8 hypotheses** for a non-trivial device, each in the
`references/HYPOTHESIS_TEMPLATE.md` format. Build each by picking one item per column
(full column contents + why each matters in `references/ATTACK_SURFACE.md` and
`references/EXPLOIT_PRIMITIVES.md`):

```
ATTACK SURFACE          ×  BUG PRIMITIVE            ×  INFO-LEAK (defeat ASLR)   ×  CONTROL-FLOW HIJACK
- PVSCSI / SCSI ring       - OOB write (fixed buf)     - uninitialized struct       - device callback fn-ptr overwrite
- vmxnet3 / e1000 net      - integer overflow n*sz     - OOB read past buffer       - vtable / dispatch-table ptr
- SVGA / 3D / shaders      - integer underflow len-x   - UAF read of freed obj      - URB/pipe callback (UHCI TDBuffer)
- USB UHCI/EHCI/xHCI/URB   - use-after-free            - type-confusion read        - heap metadata → fake object
- AHCI / SATA / NVMe       - type confusion            - backdoor/RPC reply leak    - freelist poison → arb-write
- Bluetooth SDP (default)  - uninitialized read        - side-channel (LFH timing)  - + CFG-bypass gadget → WinExec
- GuestRPC / backdoor      - OOB read (disclosure)     - predictable heap layout    - (host RCE = VMX proc; then LPE)
- VMCI / vSockets          - stack overflow (canary?)     via grooming              - ROP if no CFG / canary-free path
- HGFS shared folders      - double-free / desync
- DnD / copy-paste
```

For each hypothesis you MUST write:
- **Claim** (one sentence, falsifiable): "Because device X sizes op Y with guest field Z
  and does not bound it, a guest can A to get primitive B, leaked via C, hijacked via D."
- **Evidence so far**: the decompiled function, line, register handler, or data-flow that
  suggests it — cite the idalib finding. Mark **VERIFIED** (seen in the binary) vs
  **INFERRED** (assumed from the device spec / analogy to a known bug).
- **Kill condition**: the single observation that disproves it (e.g. "the count is masked
  to 9 bits before the multiply", "the copy uses the allocated size not the guest size",
  "the struct is memset first", "the object is refcounted").
- **Cheapest next test**: static (`decompile`/`trace_data_flow` one more function) or
  dynamic (one WinDbg breakpoint + a guest-driver poke). Prefer the cheapest disproof.
- **Rank**: likelihood(H/M/L) × impact(host-RCE / host-info-leak / DoS) × novelty
  (shipped-CVE / incomplete-fix / adjacent-device / genuinely new).

Spawn subagents to draft hypotheses per device backend in parallel when the target is
large (one agent per device region), but **you** form and rank the final list.

### Phase 3 — Kill the cheap ones statically
For each hypothesis, do the cheapest disproof first with idalib: `decompile` the suspected
handler and confirm/deny the bound, the signedness, the struct-size match, the memset, the
refcount; `trace_data_flow` to prove the guest field truly reaches the sink. A limited
primitive (null-constrained bytes, tiny overflow, read-only) is NOT dead — note the
constraint and carry it to Phase 5, where legitimate device algorithms launder it. Cross
off only hypotheses whose **kill condition** actually fires. Report the dead ones honestly;
a killed hypothesis documents coverage.

### Phase 4 — Dynamic confirmation (on the user's research host)
For survivors, prove the bug fires. Drive the device from a guest kernel driver (or a raw
PIO/MMIO/DMA poke) and attach WinDbg to `vmware-vmx` (user-mode cdb: `open_cdb_remote`
or attach; break on the handler; watch the guest-controlled size reach the copy; catch the
access violation / heap corruption). Confirm **which heap** the corrupted chunk lives on
(segment vs LFH bucket size) — this decides the grooming plan. Prove the *primitive*
(controlled OOB write / a leaked host pointer), not yet full RCE.

### Phase 5 — Build the chain: leak → groom → hijack → RCE
Escalate the primitive using `references/EXPLOIT_PRIMITIVES.md`:
1. **Leak** first — turn an OOB/uninitialized/UAF read into a host `vmware-vmx` base and
   heap address (defeat ASLR). Often a *separate* bug (the two-bug chain); pair it now.
2. **Groom** the host heap deterministically — on Windows 11 the target chunk is usually
   in the **LFH**, which randomizes allocation order. Use dual spray objects (a freely
   sprayable/freeable one like **shaders** + a lifetime-pinned one like **URBs**), the
   hole-punch / **ping-pong** two-bucket alternation, and if needed an **LFH-timing
   side-channel** (bucket-creation latency measured through the synchronous backdoor
   channel) to recover the offset.
3. **Hijack** — overwrite a device **callback / vtable function pointer** (e.g. a USB
   pipe callback, a device reset/IO completion handler) for a controlled indirect call.
4. **Bypass CFG** — the indirect call is CFG-guarded; find a **CFG-whitelisted gadget** in
   `vmware-vmx` that pivots controlled data (RCX+offset) into `WinExec`/`CreateProcess`.
   If a code path is canary-free and CFG-free, plain ROP is simpler — check first.
Then build the smallest guest-side PoC that pops a process on the host. Reproduce it
across a host reboot / fresh snapshot to prove reliability, not a one-off.

### Phase 6 — Report
Impact-first, primitive-proven, with the exact decompiled evidence, the device path from
guest to sink, and the guest PoC steps. State the affected build range and diff against the
nearest known CVE/VMSA (shipped-bug / incomplete-fix / new). Recommend the fix (bound the
guest count before the multiply; match the stored struct size to the guest struct; memset
reply buffers; refcount the object; validate the final coalesced size). If framing as a
patch bypass, borrow `cve-hunt`. Never auto-submit; the researcher decides disclosure
(Broadcom PSIRT / ZDI / Pwn2Own).

---

## Rules of engagement
- **Reproduced or it didn't happen.** Never claim an escape without a demonstrated host
  primitive; never claim RCE without a popped host process (or a WinDbg-confirmed
  controlled `rip`/indirect call).
- **VERIFIED vs INFERRED** on every claim. idalib/WinDbg evidence is verified; "the spec
  says" or "the analogous bug was" is inferred until seen in *this* binary.
- **Two bugs, not one.** Modern escapes need a leak + a corruption. If you only have
  corruption, your next hypothesis is "where is the paired info-leak on this device?"
- **The raw primitive is usually weak; the device's own algorithms are the weapon.** S/G
  coalescing, URB lifetime, ring wraparound, DMA re-read — laundering a constrained
  overwrite through legitimate device logic is the dominant modern technique. Don't
  discard a null-constrained 16-byte write; that was CVE-2025-41238.
- **Know your heap.** Windows 11 LFH determinism (grooming + timing oracle) is the hard
  part of a Workstation escape; segment-heap and glibc behave differently. Confirm the
  chunk's home before grooming.
- **Cheapest disproof first.** Most hypotheses die in one `decompile` of the size check.
- **Host-only for detonation.** A working escape executes on the host — isolated research
  host you own, snapshots on. The guest is disposable; the host is the crown jewel.
- Record dead hypotheses; they show coverage and stop re-treading a checked device.

## Pointers
- `references/ATTACK_SURFACE.md` — the virtual-device taxonomy (which devices, which
  entry points, which historical bugs), the four-ingredient hunt with exact idalib
  queries, the VMware backdoor/GuestRPC surface, and the historical arc (xairy timeline
  through 2024 + the 2024–2025 Pwn2Own cluster).
- `references/EXPLOIT_PRIMITIVES.md` — the leak → groom → hijack → CFG-bypass toolkit:
  LFH grooming (shaders/URBs, ping-pong, timing side-channel), callback-pointer hijack,
  the CFG-whitelisted-gadget → WinExec pivot, and how to launder a weak primitive through
  device algorithms.
- `references/HYPOTHESIS_TEMPLATE.md` — the hypothesis format + two worked examples
  (PVSCSI heap overflow CVE-2025-41238; Bluetooth SDP stack overflow CVE-2023-20869) + a
  starter set of ranked hypotheses across the device surface.
- All device names, CVEs, and techniques are documented inline in the references so the
  skill is self-contained.
