# Target selection — which driver to hunt next

Phase 0 assumes someone handed you a `.sys`. This file is for the prior question: **which driver
should we pick at all?** The answer is *never* "whichever one is available" — it is "the one that
adds a primitive class the collection does not already have", because a killer's research value is
its primitive, not its filename.

---

## Rule 1 — Count primitives, not drivers

Before accepting a target, ask what it adds. A collection of ten drivers that all expose
arbitrary physical memory R/W is **one** result reproduced ten times: same CR3 brute-force, same
export resolution, same Shadow-SSDT hijack, same BSOD classes (0x3B DWM race, 0x0A stack
exhaustion, 0x50 HVCI on non-`.text` gadgets — see `KILL_PRIMITIVES.md` 3c-1). Every additional
physmem driver inherits all of it and teaches nothing new.

**Saturation check (run it out loud before starting):** list the primitive class of every killer
already in the repo. If the candidate lands in a class that already has two or more entries and
adds no new *bypass* (caller validation, address blocklist, HVCI posture, loader), say so and
recommend a different class instead. The `MmMapIoSpace` / port-I/O / WinRing0-derivative family
saturates fastest — `throttlestop.sys`, `pstrip64.sys`, `MyPortIO_x64.sys`, `CorsairLLAccess64.sys`,
`SONiXDDRx64.sys`, `gdrv3.sys` and `GoFly64.sys` all collapse to the same two IOCTLs.

## Rule 2 — Prefer primitives that delete kill-chain stages

Rank candidates by how much of the fragile chain they remove, not by how powerful they sound:

| Candidate primitive | Stages it deletes | Class |
|---|---|---|
| Driver terminates by PID itself | CR3 brute, export resolution, SSDT hijack, all three BSOD classes | Tier 1 |
| Controlled kernel function call | SSDT hijack plus its restore window and race | Tier 4 |
| Kernel-**virtual** memory R/W | CR3 brute-force and page-table walk | Tier 3 (3l) |
| Kernel file delete/rename | the entire memory chain; adds reboot persistence | Tier 5 |
| Kernel registry write | the entire memory chain (callback caveat applies) | Tier 6 |
| Callback / minifilter teardown | the memory chain, but needs a kill partner (no PPL strip) | Tier 7 |
| Another physical-memory map IOCTL | nothing | Tier 3 |

## Rule 3 — Freshness gate (standing preference)

The target must be **validly signed by a real vendor** and **absent from both the Microsoft
recommended driver block list and LOLDrivers**. A catalogued or blocked driver only validates
methodology against ground truth; it is not a research result, and it will not load on a machine
that enforces the block list (default-on from Win11 24H2). Check the hash against both lists in
Phase 0 and state the outcome before spending reversing effort.

---

## Where fresh, unlisted drivers actually come from

Ranked by yield. The recurring theme: **drivers that ship inside consumer application installers
are under-audited and almost never listed**, and a bundled driver also gives you a finding against
the bundler — the driver is pre-positioned on every one of that vendor's customers, which is a
materially stronger disclosure than "an attacker could download this `.sys`".

1. **Bundled hardware-access drivers in consumer utilities.** The highest-yield ground, and the
   method that produced the `iGameCenter` result (a GPU utility shipping AMD's CPU overclocking
   driver). Sweep: MSI Center, Gigabyte Control Center, ASRock Motherboard Utility / Polychrome,
   Zotac Firestorm, Palit/Gainward ThunderMaster, Galax Xtreme Tuner, Inno3D TuneIT, Sapphire
   TriXX, Biostar, Thermaltake TT RGB Plus, Cooler Master MasterPlus, NZXT CAM.
2. **Security products' own drivers** — the best ground for Tier 1, 5 and 7, because kill,
   force-delete and callback removal are *features* there, not bugs. AV self-defense and
   AV-removal/cleanup drivers, and anti-cheat: Huorong `sysdiag`, 360, Tencent PC Manager / ACE,
   Kingsoft, Baidu, AhnLab, nProtect, Wellbia XIGNCODE, EQU8. "Kill AV with AV" is also the
   strongest disclosure narrative available.
3. **Anti-rootkit / system-analysis toolkits** — PCHunter, YDArk, PowerTool, Wsyscheck-class
   tools. Their drivers *by design* expose force-kill, force-delete, driver unload and kernel
   callback removal from one device: Tier 1 + 5 + 7 in a single binary. Check listing status
   first — the famous ones (PCHunter, TDSSKiller) are already catalogued; the clones are not.
4. **Backup / imaging / disk utilities** — Acronis, Paragon, AOMEI, EaseUS, Macrium, plus
   secure-erase tools. Best ground for Tier 5 (kernel file ops) and raw-volume write.
5. **Storage vendor toolboxes** — Samsung Magician, Crucial Storage Executive, Kingston, ADATA,
   Netac, Lexar. Phison and SMI reference drivers get rebundled under a dozen brands, so one bug
   often covers many vendors at once.
6. **Laptop OEM system utilities and EC-access drivers** — the HONOR `Os2Ec` family, Huawei PC
   Manager, Xiaomi/Redmi Book utilities, Acer Care Center / PredatorSense, ASUS Armoury Crate,
   HP Omen, Lenovo Legion. EC/ACPI access can also reach SMI, and from there SMM.
7. **Firmware/SPI flashing and platform tools** — AMIFLDRV, Insyde H2OFFT, Intel FPT / PMX, ME
   utilities. Highest novelty but a **different research goal** (persistence, Secure Boot,
   bootkits), not EDR kill. Track it as a separate thread so it does not compete with killer work.

**Sweep procedure for a bundled driver.** Install (or just unpack) the product in the VM, find
every `.sys` it drops or carries — including inside nested installers, `.cab`/`.msi`/`.7z`
payloads and per-model subdirectories — then for each: record SHA256, confirm the Authenticode
signer is a real vendor with a valid chain, check the block list and LOLDrivers, and only then
import-screen. Note which drivers the product **loads on demand as SYSTEM**: those give a
no-drop, no-`sc create` load path (see `LOAD_AND_AUTH_BYPASS.md`).

---

## Cheap screening signature table

Grep the raw `.sys` for import names before opening IDA — the import table holds them as ASCII,
so one command classes a whole directory:

```bash
grep -a -o -E '(Zw|Nt|Ps|Mm|Ob|Ke|Ex|Io|Flt|Hal|Cm|Se)[A-Za-z]+' target.sys | sort -u
```

| If you see | Class | Reference |
|---|---|---|
| `ZwOpenProcess` or `PsLookupProcessByProcessId`, plus `ZwTerminateProcess` | Tier 1 direct kill | Tier 1 |
| `KeStackAttachProcess` + `ObSetHandleAttributes` + `ZwClose` | Tier 2 handle stomp | Tier 2 |
| `MmMapIoSpace`, `MmMapMemoryDumpMdl`, `ZwMapViewOfSection`, `HalTranslateBusAddress` | Tier 3 physical R/W | 3a |
| `MmCopyVirtualMemory`, `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` | Tier 3 kernel-VA R/W (no CR3 brute) | 3l |
| `HalGetBusDataByOffset`/`HalSetBusDataByOffset`, or port I/O to `0xCF8`/`0xCFC` | Tier 3 PCI to DMA | 3i, 3m |
| `PsCreateSystemThread`, `KeInsertQueueApc`, `ExQueueWorkItem`, `KeInitializeDpc` fed from the input buffer | Tier 4 kernel call | Tier 4 |
| `ZwDeleteFile`, `ZwSetInformationFile`, `IoCreateFileEx`, `ZwWriteFile` with a buffer-sourced path | Tier 5 kernel file ops | Tier 5 |
| `ZwCreateKey`/`ZwSetValueKey`/`ZwDeleteValueKey`, `RtlWriteRegistryValue` | Tier 6 kernel registry write | Tier 6 |
| `FltUnregisterFilter`, `FltDetachVolume`, `ObUnRegisterCallbacks`, `CmUnRegisterCallback`, `PsSetCreateProcessNotifyRoutine(Ex)` | Tier 7 callback teardown | Tier 7 |
| `ExAllocatePoolWithTag`/`ExFreePoolWithTag` + list ops with no consistent lock | Tier 3 via UAF | 3h |

Intrinsics never import — if the table is thin, `find_regex` the disassembly for `0F 32` (rdmsr),
`0F 30` (wrmsr), `0F 20`/`0F 22` (CR moves), and the `in`/`out` opcodes (`E4`–`E7`, `EC`–`EF`).

**Screen for all classes in one pass.** A driver often carries several: an AV-removal driver with
a kill IOCTL usually also has force-delete (Tier 5) and callback removal (Tier 7), and a file-op
driver usually also writes the registry (Tier 6). Record every class you find in the profile, not
just the first one that would make a killer — the extra ones are what make the write-up novel.
