# VM-escape attack surface — virtual devices, entry points, idalib queries, and the historical arc

This is the map. A guest-to-host escape lives wherever the host VMM process turns
**guest-controlled bytes** into a **sized or indexed memory operation**. The surface is
the set of emulated devices and backchannels, ranked by historical yield. Everything here
is distilled from public research (the `xairy/vmware-exploitation` timeline through 2024
plus the 2024–2025 Pwn2Own cluster); reconfirm each claim against *your* binary — versions
drift and code moves.

---

## 0. The process model (VMware, the primary target)

- The escape target is **`vmware-vmx.exe`** (Windows) / `vmware-vmx` (Linux/macOS) — one
  per running VM, running at the privilege of the user who launched it (on Windows,
  historically high; the RCE lands as the VMX process, then chain `win-lpe-hunt` to SYSTEM).
- Guest code reaches it three ways: **PIO/MMIO** to an emulated device's registers, **DMA**
  where the VMM reads guest physical memory (rings, descriptors, S/G lists, URBs), and
  **backchannels** (backdoor port, GuestRPC, VMCI/vSockets, HGFS, DnD/copy-paste).
- Device backends are compiled into `vmware-vmx` (VMware) or split into DLLs/SOs
  (VirtualBox `VBoxDD`, QEMU `hw/` objects). The bug class is identical across all of them.

---

## 1. The four-ingredient hunt (what to grep for)

For each device, find these four with idalib. The exact tool names are the short forms
from `SKILL.md` (`mcp__plugin_ida-pro-mcp_idalib__*`).

### Ingredient 1 — the guest→host entry point
- **Register dispatch:** `find_regex` / `search_text` for the device's IO callback switch.
  VMware device backends register read/write handlers; look for large `switch` on a
  register offset. Names/strings often survive: `search_text` for `PVSCSI`, `Vmxnet3`,
  `SVGA`, `AHCI`, `EHCI`, `UHCI`, `xHCI`, `HDAudio`, `e1000`.
- **DMA of guest memory:** the functions that read a guest physical address into a host
  buffer — the descriptor-ring / command-block / S-G readers. These carry the guest
  **counts and lengths**. `xrefs_to` the guest-physical-read helper (often a single
  `*_PhysRead`/`MemAccess` primitive) and inspect every caller that reads a *count* then
  loops.
- **Backchannels:** `search_text` for `RPCI`, `TCLO`, `guestrpc`, `Message_`, `VMCI`,
  `vsock`, `HGFS`, and the backdoor magic `0x564D5868` ("VMXh") / port `0x5658`.

### Ingredient 2 — the sized/indexed memory operation
- `imports_query` / `xrefs_to`: `memcpy`, `memmove`, `malloc`/operator new, the internal
  heap alloc wrapper, and the guest-physical-read helper.
- For each, `decompile` the caller and identify whether the **size/count/index comes from
  a guest field**. `trace_data_flow` from the register-write / DMA-read to the size arg.

### Ingredient 3 — the missing or incorrect bound (the actual bug)
Read the arithmetic around the sized op. High-signal patterns:
- **Fixed buffer, guest count:** a constant-size allocation (`0x4000`, `0x1000`…) then a
  loop bounded by a *guest* count with no clamp. → OOB write. *(PVSCSI CVE-2025-41238: a
  0x4000 S/G buffer that should double but doesn't; entries past 1024 write 16 bytes OOB.)*
- **`alloc(n * size)` with guest `n`:** multiply overflows to a small allocation, then a
  full-size copy. → heap overflow. *(vmxnet3 CVE-2025-41236: integer overflow.)*
- **`len - k` with guest `len`:** underflow to a huge unsigned length. → massive OOB.
  *(VMCI CVE-2025-41237: integer underflow → OOB write.)*
- **Signed size compare:** `if ((int)len > MAX)` passes for negative-looking large values.
- **Struct-size mismatch:** guest supplies `{u64 addr; u32 len; u32 flags}` but the VMM
  stores `{u64 addr; u64 len}` (or vice-versa) — trailing bytes are attacker-zeroed or
  stale. *(The PVSCSI type detail that made the overwrite null-constrained.)*
- **Requested-size checked, different-size copied:** validates the header length but
  copies a **coalesced/summed** length (S/G merge, fragment reassembly). Check the *final*
  size, not the requested one.
- **Ring index unbounded:** a producer/consumer index used without modulo against ring
  size → arbitrary in-ring (or past-ring) access.

### Ingredient 4 — leak / lifetime bugs (the ASLR-defeat half)
- **Uninitialized reply:** a struct/buffer sent back to the guest that isn't fully
  `memset` — stale heap contents (pointers) leak to the guest. `decompile` reply builders;
  look for a partial fill then a full-size copy-to-guest. *(vSockets CVE-2025-41239.)*
- **OOB read:** the read-side twin of any OOB-write bug — often the same handler.
- **UAF:** an object freed on a reset/teardown/error path but still referenced by a ring
  entry, a pending request, or another device. `xrefs_to` the free; check every path that
  keeps a pointer. *(Bluetooth UAF chains; DHCP UAF.)*
- **Type confusion / handle desync:** a guest-controlled handle/index resolves to an
  object of the wrong type after a state change.

---

## 2. The device surface, ranked by yield

| Device / channel | Why it's rich | Historical / recent bugs |
|---|---|---|
| **Paravirtual SCSI (PVSCSI)** | Guest builds S/G lists, ring descriptors, command blocks — counts and lengths everywhere; DMA-heavy | **CVE-2025-41238** heap overflow (Pwn2Own Berlin 2025, Synacktiv); "Rogue CDB" disk-controller escape (2023) |
| **vmxnet3 / e1000 (NIC)** | TX/RX descriptor rings, offload lengths, packet reassembly; guest sets sizes | **CVE-2025-41236** integer overflow; ESXi vmxnet3 case study (2021) |
| **USB: UHCI / EHCI / xHCI + URBs** | URB (USB Request Block) parsing, TD buffers, variable-size transfers; URBs are great heap-spray objects | Hariri UHCI series (2017–2019); "URB Excalibur" all-platform escapes (2024); URB callback = a classic hijack target |
| **SVGA II / 3D / shaders** | Huge command FIFO, shader bytecode, surface dimensions; shaders are ideal controlled-content spray | "Straight outta VMware" (2018); shader bugs; SVGA remains a top surface |
| **VMCI / vSockets** | Kernel-adjacent shared transport; integer math on message sizes | **CVE-2025-41237** underflow (RCE); **CVE-2025-41239** uninitialized-memory leak |
| **Bluetooth (VBluetooth) SDP** | Default-on, bridges host adapter, SDP needs no pairing — large pre-auth-ish parser | **CVE-2023-20869** SDP stack overflow; **CVE-2023-20870 / -34044** UAF leak chain (NCC Group PoC) |
| **AHCI/SATA, NVMe, floppy, CD (IDE/ATAPI)** | Command blocks, PRDT scatter-gather, less-fuzzed than net/SCSI | "Rogue CDB" (disk controller); NVMe/xHCI relatively under-explored — good novelty odds |
| **GuestRPC / backdoor (RPCI/TCLO)** | Text+binary command interface; huge historical surface; also a *tool* (timing oracle, spray driver) | RPC sniffing/UAF (2017–2018); backdoor `vmx.capability.unified_loop` used as the LFH timing oracle in 2025 |
| **HGFS shared folders** | Path + file protocol parsed in host | Recurrent path/parse bugs |
| **DnD / copy-paste (VMware Tools)** | Complex serialized objects | Historical escape surface |
| **HD Audio, parallel/serial (COM1), EMF/GDI print** | Older, simpler, sometimes canary-free | "Escaping through COM1" (2015); EMF metafile surface (2016) |

**Novelty heuristic:** net and SCSI are heavily fuzzed; **xHCI, NVMe, newer SVGA 3D paths,
and VMCI/vSockets revisions** are comparatively fresh. Integer-boundary math on
guest-supplied descriptor counts/lengths remains the single most productive seed.

---

## 3. The VMware backdoor / GuestRPC surface (both target and tool)

- **Backdoor:** guest executes `in`/`out` on port **0x5658** with magic **0x564D5868**
  ("VMXh") in EAX; the command is in a register. Enumerated commands cover time, mouse,
  clipboard, and **RPC** (`RPCI`/`TCLO` sub-protocol). `search_text` for the magic and for
  the command dispatch table.
- **GuestRPC:** open a channel, send `RPCI` requests (`info-set`, `info-get`,
  `tools.capability`, `vmx.capability.*`). The host parses length-prefixed strings/blobs —
  historically a parse-bug mine.
- **As a tool:** the *synchronous* backdoor call is a clean timing oracle. Synacktiv drove
  `vmx.capability.unified_loop` to measure **LFH bucket-creation latency** and defeat heap
  randomization. Any synchronous, guest-triggerable, host-allocating command works as an
  allocation clock (see `EXPLOIT_PRIMITIVES.md`).

---

## 4. Historical arc (context for novelty / prior-art checks)

- **2007–2008** — Kortchinsky "Cloudburst"; Ormandy exposure study. Device emulation as an
  escape surface established.
- **2015** — "Escaping VMware Workstation through COM1" (serial).
- **2016–2018** — SVGA/graphics + GuestRPC era: "Straight outta VMware", shader bugs, RPC
  sniffing, EMF metafiles.
- **2017–2019** — USB (UHCI/EHCI) era: Hariri's escapology series; "Great Escape of ESXi".
- **2020–2021** — TOCTOU (Reno Robert), "SpeedPwning", DHCP UAF, ESXi vmxnet3.
- **2023–2024** — disk controllers ("Rogue CDB"), Bluetooth (CVE-2023-2087x), N-day
  chaining (Theori), "URB Excalibur" all-platform escapes. *(This is where the
  `xairy/vmware-exploitation` catalog ends.)*
- **2024 Pwn2Own Vancouver** — Theori's multi-bug Workstation→host chain ($130k).
- **2025 Pwn2Own Berlin → VMSA-2025-0013 (Jul 2025)** — four device bugs, all from the
  contest: **CVE-2025-41236** vmxnet3 integer overflow, **CVE-2025-41237** VMCI integer
  underflow, **CVE-2025-41238** PVSCSI heap overflow (Synacktiv's winning chain),
  **CVE-2025-41239** vSockets uninitialized-memory info-leak. The 41238+leak pairing is
  the canonical modern two-bug chain.

**Prior-art gate:** before claiming novelty, WebSearch the device + "VMware escape" /
"Pwn2Own" / the CVE, and check the nearest VMSA. Classify: shipped-CVE (reproducing) /
incomplete-fix (patch bypass — use `cve-hunt`) / adjacent-device (same class, new device) /
genuinely new.

---

## 5. Cross-hypervisor notes (same bug class, different binary)

- **VirtualBox** — device backends in `VBoxDD.dll`/`.so`; historically rich: e1000, AHCI,
  audio, VGA. Same descriptor/length bug class; often canary/CFG-lighter than VMware.
- **QEMU** — `hw/` device models in C; classic surfaces: net (e1000, virtio), USB, block,
  audio. Bugs are the same integer/OOB/UAF classes; ASLR/heap is glibc, not LFH.
- **Hyper-V** — VMBus + VSPs in the root partition; a different trust model but the same
  "host parses guest-controlled ring data" shape.

The methodology (four-ingredient hunt → multi-hypothesis → leak+corruption chain)
transfers directly; only the entry-point plumbing and the heap/mitigation model change.
