# Hypothesis engine — format, worked examples, and a starter set

## Why multiple hypotheses
One device yields many candidate bugs. You enumerate the cross-product of
(attack surface × bug primitive × info-leak × control-flow hijack), then **falsify
aggressively**. A killed hypothesis is a result: it documents coverage and stops
re-treading a checked handler. Aim for 5–8+ hypotheses on any non-trivial device; spawn a
subagent per device backend to draft, but YOU rank and own the final list.

## The template (fill one per hypothesis)

```
### H<n>: <one-line name>
- Claim (falsifiable): Because <device> sizes/indexes <op> with guest field <Z> and
  <fails to bound / mismatches struct size / underflows / doesn't zero / doesn't refcount>,
  a guest can <trigger> to get <primitive>, leaked via <leak>, hijacked via <hijack>.
- Attack surface:     <PVSCSI / vmxnet3 / UHCI / SVGA / VMCI / Bluetooth / GuestRPC / ... + the exact handler fn/addr>
- Bug primitive:      <OOB write / int overflow / int underflow / UAF / type-confusion / uninit read / OOB read>
- Entry point:        <PIO/MMIO register + offset | DMA descriptor read | backdoor/RPC command>
- Info-leak (paired): <the leak bug that defeats ASLR, or "TBD — find the twin">
- Hijack:             <device callback ptr / vtable / URB pipe callback / freelist poison → arb-write>  + <CFG-gadget→WinExec | ROP if canary/CFG-free>
- Evidence so far:    <idalib finding: fn @ addr, decompiled line, register handler, data-flow;
                       VERIFIED (seen in binary) vs INFERRED (from device spec / analogy)>
- Kill condition:     <the single observation that disproves it>
- Cheapest next test: <static: decompile fn X / trace_data_flow | dynamic: WinDbg bp + guest poke>
- Rank:               likelihood(H/M/L) × impact(host-RCE / host-leak / DoS) × novelty
                      (shipped-CVE / incomplete-fix / adjacent-device / new)
- Status:             OPEN | KILLED(<why>) | CONFIRMED(<evidence>)
```

---

## Worked example 1 — PVSCSI heap overflow (CVE-2025-41238, Pwn2Own Berlin 2025)

```
### H1: PVSCSI scatter-gather buffer not doubled → 16-byte OOB heap write → host RCE
- Claim: Because the PVSCSI S/G processor allocates a fixed 0x4000 buffer instead of
  doubling as entries grow, a guest sending >1024 S/G entries writes 16 bytes past the
  buffer per extra entry into adjacent LFH chunks; laundered via S/G coalescing into
  arbitrary R/W, leaked via a coalesced OOB read, hijacked via a USB pipe callback + a
  CFG-whitelisted gadget → WinExec on the host.
- Attack surface:     PVSCSI controller S/G processing (the ring/command-block S/G reader)
- Bug primitive:      OOB write (fixed buffer, guest-controlled entry count)
- Entry point:        Guest pvscsi driver issues SCSI ops with a large S/G list (DMA read of PVSCSISGElement[])
- Info-leak (paired): "Hybrid URB" — corrupt a URB's actual_len via coalescing, OOB-read
                      adjacent URB headers → heap pointers (defeat ASLR)
- Hijack:             overwrite USB pipe object callback ptr → controlled indirect call
                      (RCX+0x90 data); CFG bypass via whitelisted gadget pivot → WinExec
- Evidence so far:    VERIFIED (public writeup + patch): struct mismatch guest {u64 addr;
                      u32 len; u32 flags} vs stored {u64 addr; u64 len} → trailing 4 bytes
                      always zero (null-constrained write); fix doubles the buffer.
- Kill condition:     the copy uses the allocated size, or the entry count is clamped to
                      <=1024 before the loop.
- Cheapest next test: decompile the S/G size/alloc arithmetic; confirm no clamp before loop.
- Rank:               H × host-RCE × shipped-CVE (CVE-2025-41238; this IS the Berlin winner)
- Status:             CONFIRMED (Synacktiv public chain)
```

Lesson encoded: the raw write was null-constrained and only 16 bytes — useless alone. The
exploit came from **S/G coalescing** (device algorithm) + **shader/URB LFH grooming** +
an **LFH timing side-channel** through the backdoor + **CFG-gadget → WinExec**. Reproduce
that reasoning, not just the bug.

---

## Worked example 2 — Bluetooth SDP stack overflow (CVE-2023-20869)

```
### H2: VBluetooth SDP integer read overruns 16-byte stack buffer → return-addr overwrite
- Claim: Because SDPData_ReadRawInt copies a guest-controlled length into a 16-byte stack
  buffer with no bounds check and the path has no stack canary, a guest sending an
  SDP_SVC_SEARCH_ATTR_REQ (type 0x06) with an oversized integer overwrites the return
  address → ROP → host code execution. Bluetooth is default-on and SDP needs no pairing.
- Attack surface:     VBluetooth SDP handler: process_request → proc_search_attr_req →
                      sub_14083C7F0 → SDPData_ReadRawInt
- Bug primitive:      stack buffer overflow (guest-controlled memcpy length, canary-free)
- Entry point:        guest sends crafted SDP packet (Linux: libbluetooth; Windows guest:
                      hook bthport.sys @ SdpL2cap_SendInitialRequestToServer, then WSALookupServiceBegin/Next)
- Info-leak (paired): none required for the corruption; ASLR handled via the paired UAF
                      leak (CVE-2023-20870 / -34044) in the full chain
- Hijack:             overwrite saved return address → ROP via memcpy (no canary on path)
- Evidence so far:    VERIFIED (public writeup + patch): fix adds `if (len > 0x10) return 0;`
- Kill condition:     a length check <=0x10 before the copy, or a canary on the frame.
- Cheapest next test: decompile SDPData_ReadRawInt; confirm the copy length is guest-set and unchecked.
- Rank:               H × host-RCE × shipped-CVE (patched; use as patch-bypass seed only)
- Status:             CONFIRMED (patched — hunt adjacent SDP verbs for incomplete-fix variants)
```

Lesson encoded: **delivery ≠ trigger** (Windows guests needed a `bthport.sys` hook to shape
SDP), default-on convenience devices are prime surface, and canary-free host paths let a
single bug skip the two-bug dance.

---

## Starter hypothesis set (derived; mostly OPEN/INFERRED — validate before believing)

Use these as seeds when handed "survey vmware-vmx" with no specific device. Each is a
class-level bet from the attack-surface map; confirm/kill against the actual binary.

```
### H3: vmxnet3 TX/RX descriptor count integer overflow → heap overflow
- Class of CVE-2025-41236. Look for alloc(n * desc_size) with guest n; kill if n is masked/clamped.
- Rank: H × host-RCE × adjacent-device(net) — net is well-fuzzed, so likely incomplete-fix territory.

### H4: VMCI/vSockets message-size integer underflow → OOB write
- Class of CVE-2025-41237. Look for len - header with guest len; kill if len >= header is enforced.
- Rank: M × host-RCE × adjacent-device.

### H5: vSockets/GuestRPC reply built without full memset → host pointer leak
- Class of CVE-2025-41239 — the ASLR-defeat twin. Find a reply struct with a partial fill.
- Rank: H × host-leak × pairs-with-any-corruption (highest value as a chain component).

### H6: xHCI / NVMe descriptor parsing OOB — under-explored surface
- Newer controllers, less public work. Map the descriptor/PRP readers; hunt count/length math.
- Rank: M × host-RCE × new (best novelty odds).

### H7: SVGA 3D / shader length or surface-dimension overflow
- Shaders double as spray objects; a bug here is both primitive and grooming tool.
- Rank: M × host-RCE × adjacent-device.

### H8: UHCI/EHCI URB lifetime UAF → leak + fake-object hijack
- URBs are the canonical hijack object (pipe callback). Hunt free-then-use across reset paths.
- Rank: M × host-RCE × adjacent-device (URB Excalibur lineage).

### H9: AHCI/SATA/ATAPI (CD) command-block S/G — the "Rogue CDB" class
- Disk controllers are less fuzzed than net/SCSI. Map PRDT / command-block readers.
- Rank: M × host-RCE × adjacent-device.

### H10: HGFS shared-folder path/length parse bug
- If shared folders are enabled. Host-side path handling has recurring bugs.
- Rank: L/M × host-RCE × adjacent.
```

Rank the final list by **likelihood × impact × novelty**, do the cheapest disproof on the
top few, and record every KILLED hypothesis with its reason.
