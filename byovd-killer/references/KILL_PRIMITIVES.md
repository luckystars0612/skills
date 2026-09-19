# Kill primitives — the tiered catalog

A BYOVD killer = **a driver primitive** repurposed to terminate a process user mode can't touch.
Three tiers, in ascending power and effort. Each entry lists the **import/artifact signature** to
recognize it, **how it kills**, the **PPL/HVCI** posture, and the **reproduced example** in the
`BlackSnufkin/BYOVD` repo. Pick the tier in Phase 3; it decides the PoC shape (Phase 4).

Short names map to `mcp__plugin_ida-pro-mcp_idalib__<name>`.

---

## Tier 1 — Direct kill IOCTL (≈90% of the repo)

**Signature.** Imports a handle-getter + a terminator, and an IOCTL branch feeds a
user-supplied PID straight into them:
`ZwOpenProcess(PROCESS_TERMINATE, …, &ClientId)` → `ZwTerminateProcess`, or
`PsLookupProcessByProcessId(pid,&ep)` → `ZwTerminateProcess`/`PsTerminateProcess` →
`ObfDereferenceObject`.

**How it kills.** The terminate executes in ring 0 under the driver's signature, so it defeats
PPL (the OS lets a kernel caller terminate a protected process) — no user-mode
`OpenProcess(PROCESS_TERMINATE)` on `MsMpEng.exe` needed. EDR **user-mode** hooks are bypassed;
whether an EDR **kernel** `PsSetCreateProcessNotifyRoutine`/`ObRegisterCallbacks` sees it depends
on the driver, but the terminate itself isn't blockable from user land.

**PPL/HVCI.** PPL: yes (kills protected processes). HVCI: irrelevant (no code injection).

**PoC shape.** Thin `byovd-lib` `DriverConfig` — device path, IOCTL code, `build_ioctl_input`
placing the PID at the reversed offset/width/encoding. See `references/BYOVD_LIB.md` and
`templates/killer_main.rs`. Overrides you'll commonly need: `device_access` (GENERIC_READ|WRITE),
`skip_unload` (BSOD-on-unload), `ignore_ioctl_error` (NSecKrnl), `preflight_check` (LocalSystem).

**Repro examples.** TfSysMon, BdApiUtil64, CcProtect, GameDriverX64, EnPortv, PCTcore64, Wsftprm,
Viragt64 (by name), PoisonX (ASCII PID), NSecKrnl, STProcessMonitor, HNOs2Ec/MonProcess (HONOR).

**idalib.** `imports_query` for the pair; `xrefs_to ZwTerminateProcess`; `trace_data_flow` from
the IOCTL buffer to `ClientId.UniqueProcess` to lock the PID offset.

---

## Tier 2 — Handle / object stomp (no terminate export)

**Signature.** No terminator import, but `KeStackAttachProcess` + `ObSetHandleAttributes` +
`ZwClose`, or an IOCTL/command that returns a full-access handle to an arbitrary process
(`ObOpenObjectByPointer` with `KernelMode` access override). Dispatch may be `IRP_MJ_WRITE`
(index 4), driven by `WriteFile`, not DeviceIoControl.

**How it kills.** Attach into the target with `KeStackAttachProcess`, walk its handle table,
strip `OBJ_PROTECT_CLOSE` via `ObSetHandleAttributes(KernelMode)`, and `ZwClose` every entry.
Once a critical kernel object (a section, a process/thread handle it depends on) is yanked, the
target faults on its next I/O and exits — an **indirect** kill. Alternatively, mint a kernel-mode
`PROCESS_ALL_ACCESS` handle to a PPL process and hand it back to user mode.

**PPL/HVCI.** PPL: yes (the handle op is a kernel op; PPL doesn't stop a kernel caller). HVCI:
irrelevant.

**PoC shape.** Standalone crate (custom flow — `byovd-lib`'s `DeviceHandle` assumes
DeviceIoControl; a WRITE-dispatch driver needs `WriteFile`). Enumerate the target's handles via
`NtQuerySystemInformation(SystemExtendedHandleInformation)`, then drive the driver's command per
handle. Consider a two-tier privilege approach: try the cheapest handle right first
(`PROCESS_QUERY_LIMITED_INFORMATION`), fall back to the driver's full-access-handle command only
when an EDR `ObRegisterCallbacks` filter denies the cheap path.

**Repro example.** `Xhunter1-Killer` — `xhunter1.sys` cmd `800` handle stomp; cmd `785` as the
full-access-handle fallback (CVE-2026-3609). WRITE-dispatch, standalone.

**idalib.** `xrefs_to KeStackAttachProcess`, `ObSetHandleAttributes`, `ObOpenObjectByPointer`;
check `MajorFunction[4]` vs `[14]` to learn the dispatch verb.

---

## Tier 3 — Arbitrary physical / virtual memory R/W

The powerful tier: the IOCTL doesn't kill, it **maps or writes memory**. You build the entire
kill in user mode on top of an R/W primitive. Defeats PPL **and** EDR kernel callbacks, because
the terminate is `PsTerminateProcess` invoked from a hijacked kernel context — no
`NtTerminateProcess` syscall, no notify-routine, nothing user mode did that a callback can see.

### 3a. Recognize the primitive
- **`MmMapIoSpace` / `MmMapMemoryDumpMdl`** on a user-supplied physical address → map arbitrary
  physical memory into the caller's address space (`Astra64` pattern, IOCTL returns a VA).
- **`ZwMapViewOfSection` of `\Device\PhysicalMemory`** → same, via the physical-memory section.
- **`HalTranslateBusAddress` fail-open** → when `InterfaceType = 0xFFFFFFFF` (an out-of-range
  bus type), HAL returns the input address unchanged, turning a *bus*-address mapper into an
  *arbitrary physical* mapper (`ktapi.sys` / "The Gentlemen" pattern; map IOCTL `0x82007000`,
  unmap `0x82007100`).
- **MSR read IOCTL** (`__readmsr`) → read `IA32_LSTAR` (`0xC0000082`) = the syscall entry =
  `KiSystemCall64`, a fixed offset into ntoskrnl → **KASLR bypass** without a leak.

### 3b. Build the R/W ladder (user mode)
1. **Physical R/W wrapper** over the map IOCTL: `map_phys(pa,size)` → VA, copy, `unmap`. Cache
   the last mapping; probe the returned handle's high 32 bits with `VirtualQuery`+`MEM_COMMIT`
   when the driver only returns the low dword.
2. **Find kernel CR3.** Brute-force: scan low physical pages (`0..0x400_0000` step `0x1000`),
   read the PML4 entry for the `KUSER_SHARED_DATA` VA index (`0xFFFFF78000000000 >> 39 & 0x1FF`),
   keep pages whose PML4E is present and points below a sane ceiling, then confirm by walking
   `KUSD_VA` to physical and checking `KUSD+0x2C6/0x26C` (`NtMajorVersion == 10`).
3. **Page-table walk** `virt_to_phys(cr3, va)`: PML4→PDPT→PD→PT, honoring the huge-page bit;
   gives `vread/vwrite` over any kernel VA.
4. **ntoskrnl base**: from `IA32_LSTAR`, walk the VA backward page by page until an `MZ`/valid
   `PE` header → base.
5. **Export resolution** over physical R/W: parse ntoskrnl's export directory to resolve
   `ExAllocatePoolWithTag`, `PsLookupProcessByProcessId`, `PsTerminateProcess` (or find it by
   pattern near `PsGetProcessExitStatus`), `ObfDereferenceObject`.

### 3c. Turn R/W into a kernel call — two families
- **Data-only Shadow SSDT hijack (HVCI-safe, no shellcode).** Resolve
  `KeServiceDescriptorTableShadow` (via `KeAddSystemServiceTable` refs), locate an `FF 25`
  (indirect `jmp [rip+disp]`) thunk inside the win32k host module, point one Shadow SSDT entry
  (e.g. `NtUserSetWindowPos`) at that thunk (encode the KiServiceTable relative offset), then
  **swap the thunk's IAT slot via physical write** between syscalls to chain
  `ExAllocatePoolWithTag` → per target `PsLookupProcessByProcessId` → `PsTerminateProcess` →
  `ObfDereferenceObject`. Trigger each by calling the hijacked Win32k syscall (must be a GUI
  thread — call `IsGUIThread(TRUE)` first). Restore the SSDT entry + IAT slot when done. No
  RWX pool, no code written to executable kernel memory → HVCI/VBS page protections don't apply.
  **Repro:** `Astra64-Killer`.
- **Code-exec via Win32k stub hijack (shellcode).** Find a Win32k syscall's `E9` (rel32 jmp)
  or `FF 25`/`4C 8B 15` indirect stub in `win32kfull.sys` (locate the module base in session
  space). Overwrite the stub to jump to a **stage-1 trampoline written into the CC padding** after
  the function, which `mov rax,imm64; jmp rax` into a **stage-2 shellcode in a kernel pool
  allocation**. Stage-2 loads 4 args from pool slots (`mov rcx/rdx/r8/r9,[pool+off]`), calls the
  target kernel function, stores the return to a pool slot, `ret`. KernelCall primitive: write
  `(fn,args)` to pool, fire the syscall, read the result. Use it to call `PsLookupProcess
  ByProcessId`→`PsTerminateProcess`→`ObfDereferenceObject` per target. Restore the stub + padding.
  Note **build sensitivity**: the specific hijackable syscall stub moves between Windows builds —
  the ones one blog documents may not exist on your build; scan for a present stub. **Repro:**
  `Ktapi-Killer` (used `NtGdiSetMagicColors` on 25H2 build 26200 after the blog's
  `NtUserFrostCrashedWindow`/`NtUserSetGestureConfig` stubs were absent).

### 3d. Defeating WdFilter Tamper Protection (required before registry writes)

On Win11 24H2+, WdFilter.sys registers a `CmRegisterCallbackEx` callback that blocks
`ZwSetValueKey` on Defender service registry keys (WinDefend, WdNisSvc, WdFilter, etc.).
This must be neutered **before** any registry-based service disabling.

**How to find and patch it (data-only, HVCI-safe):**
1. **Find `CmUnRegisterCallback`** in ntoskrnl exports.
2. **Scan its code for RIP-relative references** (REX.W prefix 0x48/0x4C, opcode 0x8D/0x8B,
   ModRM & 0xC7 == 0x05) → these point to the CM callback list head.
3. **Walk the linked list** (LIST_ENTRY at node+0x00). On 24H2, CM callbacks use a **linked
   list** (NOT the EX_CALLBACK array from older builds). The callback function pointer is at
   **node offset +0x28**.
4. **Find WdFilter's module** via `PsLoadedModuleList` walk (KLDR_DATA_TABLE_ENTRY: DllBase
   +0x30, SizeOfImage +0x40, BaseDllName at +0x58/+0x60). Compare each node's function
   pointer against WdFilter's address range [base, base+size).
5. **Replace the function pointer** at node+0x28 with a `xor eax,eax; ret` gadget (31 C0 C3
   or 33 C0 C3) found in ntoskrnl's `.text` section. This makes the callback return
   STATUS_SUCCESS for all registry operations. Data-only patch (modifies pool data, not code)
   → HVCI-safe.

### 3e. Complete Defender kill chain (disable services + kill processes)

After neutering tamper protection, disable all 6 Defender services via kernel registry writes
and clear their FailureActions to prevent SCM restart loops:

**Services to disable** (set `Start` = 4 via `ZwOpenKey` + `ZwSetValueKey`):
```
WinDefend, WdNisSvc, WdFilter, SecurityHealthService, Sense, MDCoreSvc
```
Note: the real service name for `MpDefenderCoreService.exe` is **`MDCoreSvc`** (not
`MpDefenderCoreService`). Use `!reg findkcb` in WinDbg to verify.

**FailureActions clearing**: Write `FailureActions` as REG_BINARY with 16 bytes of zeros
(cActions=0). Without this, SCM FailureActions specifies 3 restart attempts with delays of
1s, 10s, and 60s — processes come back even after killing them.

**SCM caching caveat**: SCM caches service config in memory. Registry writes (Start=4) only
take effect **after reboot**. For the current session, a **multi-round kill loop** is needed:
```
Round 0: kill immediately
Round 1: wait 2s, kill respawns (catches 1s FailureActions delay)
Round 2: wait 12s, kill respawns (catches 10s delay)
Round 3: wait 65s, kill respawns (catches 60s delay)
```
After reboot, the registry changes prevent the services from starting at all.

### 3f. SSDT safety rules (critical — violating these causes BSOD)

- **MUST restore SSDT entry + IAT pointer between every operation group.** Leaving the hijack
  active during sleep/wait means any thread calling the hijacked syscall (e.g.
  `NtUserSetWindowPos`) gets redirected to whatever kernel function is currently in the IAT
  (PsTerminateProcess, ZwSetValueKey, etc.) with garbage arguments → instant BSOD. The hijack
  window must be milliseconds, not seconds.
- **Skip `ObfDereferenceObject` after `PsTerminateProcess`.** `PsTerminateProcess` initiates
  async cleanup; the EPROCESS can be freed on another core before the separate
  `ObfDereferenceObject` syscall executes from user mode → BSOD 0x3B
  (SYSTEM_SERVICE_EXCEPTION). Accept the minor reference leak.
- **Restore SSDT+IAT during kill loop delays.** The kill loop can run for ~80 seconds total.
  Re-patch only for the brief kill windows in each round.

### 3g. PoC shape
Standalone crate (its own `[workspace]`, `[profile.release]`), `windows` crate for the Win32
surface. No `byovd-lib`. Structure: driver R/W wrapper → page-table walk → kernel discovery →
tamper protection bypass → service disable → hijack install → kill loop over targets → restore.
Default targets are the Defender set (`MsMpEng.exe`, `MpDefenderCoreService.exe`,
`SecurityHealthService.exe`, `MsSense.exe`).

**PPL/HVCI.** PPL: yes. HVCI: **data-only sub-tier is HVCI-safe**; the shellcode sub-tier needs
a writable+executable kernel target and can be blocked by HVCI/KDP depending on where it writes —
prefer data-only when HVCI/VBS is enforced.

**idalib (on the driver).** `xrefs_to MmMapIoSpace`/`HalTranslateBusAddress`; read the map-IOCTL
handler for the input struct (interface type, bus number, physical addr, size) and the fail-open
condition. The kernel-side hijack targets (SSDT, Win32k stubs) are discovered at runtime by the
PoC over the R/W primitive, not statically in the driver.

### 3h. UAF (Use-After-Free) → kernel pool R/W primitive

**Signature.** A driver maintains a kernel-mode linked list (process tracking, session list,
client list) protected by inadequate synchronization — missing mutex, missing interlocked ops,
or a FastMutex only on some paths. The list nodes are allocated from NonPagedPool. The UAF
arises when a node is freed (on handle close / process detach) while another thread still
holds a pointer to it via the list.

**Platform independence.** Unlike physical-memory-map Tier 3 killers, a UAF-based chain
exploits **software bugs**, not hardware interfaces. It works on **any x64 Windows system**
(AMD and Intel alike) and cannot be detected by import screening for `MmMapIoSpace` or
`ZwMapViewOfSection`. The only prerequisite is the vulnerable driver.

**How it works (the AMDRyzenMasterDriver v2.6 pattern):**

The driver tracks callers in a singly-linked list of pool-allocated nodes. Three IRP handlers
access the list concurrently with **zero synchronization**:

| Handler | Operation | Lock |
|---------|-----------|------|
| IRP_MJ_CREATE | Allocate node, walk to tail, append | **NONE** |
| IRP_MJ_CLOSE | Walk list, find by PID, unlink (`prev->Next = current->Next`), free | **NONE** |
| IOCTL 0x81112FFC | Walk list, copy PID + name entries, follow Next pointers | **NONE** |

Node allocation: `ExAllocatePoolWithTag(NonPagedPool, 80, 'Tag4')`.
Node layout (verified from IDA decompilation):
```
Offset  Size  Field
+0x00   4     ProcessId (DWORD)
+0x04   64    ImageFileName (char[64])
+0x44   4     padding (uninitialized)
+0x48   8     Next pointer (QWORD → next node or NULL)
Total:  80 bytes (0x50)
```

**Step 1 — UAF read primitive via named pipe spray.**

The spray vehicle is `NpfsDataQueueEntry` — writing data to a named pipe server creates an
inline allocation in NonPagedPool:
```
NpfsDataQueueEntry layout (x64):
  [+0x00] LIST_ENTRY       (16 bytes)
  [+0x10] IRP*              (8 bytes)
  [+0x18] SecurityContext*   (8 bytes)
  [+0x20] DataEntryType     (4 bytes)
  [+0x24] QuotaInEntry      (4 bytes)
  [+0x28] DataSize          (4 bytes)
  [+0x2C] QuotaCharged      (4 bytes)
  Header total:              0x30 bytes (48)
  [+0x30] Data payload       (N bytes, inline after header)
```

With a **32-byte pipe write**: `0x30 header + 0x20 data = 0x50 = 80 bytes` — same pool
bucket as the driver's tracking node. The critical byte math:
```
Pipe data byte [0..23]  → allocation offset [0x30..0x47] → overlaps padding
Pipe data byte [24..31] → allocation offset [0x48..0x4F] → Next pointer field
```
Placing a target kernel VA at pipe data bytes `[24..31]` sets the freed node's Next pointer
to that address. The LIST IOCTL traversal follows this pointer and reads 68 bytes (4-byte PID
+ 64-byte name) from the target address.

**Reliable race pattern:**
1. **Defragment**: Open 2048 driver handles → fill LFH bucket for 80-byte chunks
2. **Create victims**: Open 64 handles → victim nodes to be freed
3. **Create separators**: Open 64 more handles → stay alive as "prev" nodes
4. **Free victims**: Close the 64 victim handles → 64 holes in the pool
5. **Spray holes**: Write 32 bytes to 256 named pipes (4× overcommit), each carrying the
   target VA at bytes [24..31] → reclaim freed slots with controlled Next pointers
6. **Trigger**: Call IOCTL 0x81112FFC → list traversal follows sprayed Next pointers
7. **Detect**: Entries with invalid PIDs (>0x100000) or non-ASCII names indicate reads from
   the target address. Each such entry contains 68 bytes read from the target.

Threading: 4 open/close racer threads + 2 list-reader threads for timing the race window.

**Step 2 — UAF write primitive via unlink.**

The CLOSE handler's unlink provides a **constrained 8-byte write**:
```c
// IRP_MJ_CLOSE handler:
while (P != NULL && P->PID != myPID) {
    v31 = P;          // prev
    P = P->Next;
}
v31->Next = P->Next;  // UNLINK: writes P->Next to prev->Next
ExFreePoolWithTag(P, 'Tag4');
```

If `P` (current node) is freed and sprayed with controlled data:
- `P->Next` = attacker-controlled 8-byte value (from pipe spray bytes [24..31])
- This value gets written to `v31->Next` = `prev + 0x48`

**Constraint:** The destination (`prev + 0x48`) is always a pool-allocated node address.
For targeted kernel writes (e.g. SSDT patching), chain list corruption:
1. UAF read → discover kernel addresses of existing list nodes
2. Corrupt one node's Next to point near the SSDT entry (offset so `+0x48` lands on target)
3. Subsequent CLOSE propagates the controlled value through the corrupted chain
4. The write lands at `(corrupted_prev + 0x48)`, which is now near the target

**Step 3 — SSDT hijack and kill.**

With UAF R/W established, the chain follows the same Shadow SSDT hijack as 3c-3f:
1. UAF read → `KeServiceDescriptorTableShadow` → `W32pServiceTable`
2. Find `FF 25` gadget in win32k within ±128MB of SSDT base
3. UAF write → patch `SSDT[NtUserSetWindowPos]` with encoded gadget offset
4. UAF write → write `PsLookupProcessByProcessId` to IAT slot
5. `SetWindowPos(pid)` → `PsLookupProcessByProcessId(pid, &eproc)` in kernel
6. UAF read → retrieve EPROCESS pointer
7. UAF write → swap IAT to `PsTerminateProcess`
8. `SetWindowPos(eproc)` → `PsTerminateProcess(eproc, 0)` → process killed
9. Restore SSDT + IAT immediately (BSOD prevention per 3f rules)
10. Skip `ObfDereferenceObject` (EPROCESS freed on another core → BSOD 0x3B race)

**Import signature.** `ExAllocatePoolWithTag` + `ExFreePoolWithTag` (or `ExAllocatePool2`),
plus a list-management pattern (`InsertTailList`/`RemoveEntryList` or manual FLINK/BLINK
manipulation). The key tell is the **absence** of proper synchronization — no
`ExAcquireFastMutex` / `KeAcquireSpinLock` on list operations, or mutex present on some
IOCTLs but missing on others.

**idalib.** `imports_query` for `ExAllocatePoolWithTag`; `xrefs_to` the alloc call to find
the node struct; `decompile` the CREATE/CLOSE/LIST handlers and check for mutex acquisition.
If the same list is accessed from CREATE, CLOSE, and an IOCTL handler without consistent
locking → UAF candidate. Cross-reference `ExAcquireFastMutex` xrefs against the list-
manipulation functions to confirm the gap.

**Fix detection.** If a newer version of the same driver adds `ExAcquireFastMutex` /
`ExReleaseFastMutex` around list operations that previously lacked them, the UAF is patched.
Example: AMDRyzenMasterDriver v3.2 added FastMutex to process tracking (stru_140029700),
closing the v2.6 UAF.

**Repro example.** `AMDRyzenMasterV26-Killer` — full 8-phase chain: driver load → KASLR
bypass (NtQuerySystemInformation) → pool info leak (CWE-908) → UAF read (named pipe spray,
CWE-416/362) → kernel function resolution (on-disk PE + sig scan) → UAF write (unlink) →
Shadow SSDT hijack (NtUserSetWindowPos → FF 25 → PsTerminateProcess) → multi-round EDR kill
with SCM FailureActions timing → cleanup. Platform-independent (works on AMD and Intel).
Fixed in v3.2 (FastMutex added).

### 3i. PCI config space → SMN → SMU command injection (AMD SoC)

**Signature.** Driver imports `HalSetBusDataByOffset` + `HalGetBusDataByOffset` (HAL module)
and writes to PCI config offsets 0xC4 (SMN index) and 0xC8 (SMN data) on bus 0, device 0,
function 0. This is the AMD-specific System Management Network (SMN) access pattern — writing
a 32-bit address to 0xC4 and reading/writing 32-bit data at 0xC8 gives full access to the
SoC's internal register bus.

**How it chains to a kill primitive:**
1. **SMN R/W** — read/write any SoC internal register (GPU, memory controller, USB, audio,
   SDMA engines, power management, etc.)
2. **SMU mailbox** — the System Management Unit firmware has a command mailbox at known SMN
   addresses. Write command ID to MSG register, arguments to ARG registers, read response
   from RSP register. This gives arbitrary SMU firmware command injection.
3. **DRAM address redirect** — SMU commands include `SetToolDramAddress` (sets the physical
   address where `TransferTable` DMA writes PM table data). If this command is available on
   the target firmware, redirect it to a kernel physical page → the SMU hardware performs
   DMA write to the target address. This is a **hardware-level write primitive** that
   bypasses all software memory protections.
4. Physical write → same SSDT hijack as 3c-3f.

**SMU mailbox addresses (AMD Family 25 / Zen 3-4):**
```
Desktop (MP1):  MSG=0x3B10570  RSP=0x3B10A40  ARG=0x3B10524
APU (Renoir+):  MSG=0x3B10528  RSP=0x3B10564  ARG=0x3B10998
```
Commands: 0x01=TestMessage, 0x02=GetSmuVersion, 0x05=TransferTableSmu2Dram,
0x06=GetDramBaseAddress, 0x0A/0x0B=SetToolDramAddress (firmware-dependent).

**Import signature.** `HalSetBusDataByOffset` + `HalGetBusDataByOffset` from HAL. The driver
may also import `MmMapIoSpace` (read-only usage for PM table), `__readmsr`/`__writemsr`
intrinsics for MSR access. Key difference from a direct MmMapIoSpace write driver: the PCI
config write is the entry point, not MmMapIoSpace — the physical memory write comes
indirectly through SMU hardware DMA.

**idalib.** `imports_query` for `HalSetBusDataByOffset`; `xrefs_to` the import; `decompile`
callers to find the PCI offset table (look for constants 0xC4, 0xC8); check whether the
IOCTL allows user-controlled bus/offset or is restricted to the SMN pair.

**Repro examples.** `AMDRyzenMasterV26-Killer` (v2.6: SMN + UAF combo),
`AMDRyzenMasterV32-Killer` (v3.2: SMN + SMU probe, UAF fixed → hardware DMA path).

### 3j. Generic info leak via IoStatus.Information (KASLR bypass)

**Signature.** The dispatch handler sets `Irp->IoStatus.Information = OutputBufferLength` on
ALL successful IOCTLs, regardless of how much data was actually written to the output buffer.
For METHOD_BUFFERED IOCTLs, the I/O manager allocates `max(InputBufferLength,
OutputBufferLength)` from NonPagedPool, copies only `InputBufferLength` bytes of input into
it, and after the IOCTL completes, copies `IoStatus.Information` bytes back to user mode.
If `OutputBufferLength > InputBufferLength`, bytes beyond the input are **uninitialized pool
residue** — kernel pointers, pool headers, freed object fragments.

**How it helps.** Send any IOCTL with OutputBufferLength=4096, InputBufferLength=12 (typical
minimum). Bytes [12..4095] are raw NonPagedPool residue. Parse for kernel pointers
(high 16 bits == 0xFFFF, value in ntoskrnl range) → **instant KASLR bypass** without needing
NtQuerySystemInformation or any admin-only API.

**idalib.** `decompile` the dispatch handler; look for `a2->IoStatus.Information = v_outlen`
(or equivalent) in a common exit path that ALL IOCTL branches reach. If it's in a shared
epilogue (not per-IOCTL), every IOCTL leaks. Check that the output-buffer-length variable
is assigned from `IO_STACK_LOCATION.Parameters.DeviceIoControl.OutputBufferLength`, not from
actual bytes written.

**Repro example.** AMDRyzenMasterDriver v3.2 — `LABEL_149` at `0x140002A71` sets
`IoStatus.Information = OutputBufferLength` for ALL 10 IOCTLs. Confirmed via IOCTL
0x81112FF8 (SMN write) with OutputBuf=4096, InputBuf=12 → 4084 bytes kernel pool residue.

### 3k. Unrestricted MSR write (P-state / HWCR abuse)

**Signature.** Driver provides an MSR write IOCTL that accepts a user-supplied MSR index
(from a lookup table) and value. If the value validation is absent or insufficient, the
attacker can write arbitrary values to CPU model-specific registers.

**Typical restrictions to check:**
- **Lookup table**: the IOCTL maps a user-supplied index (0-N) to an actual MSR address via
  a driver-internal array (`dword_140009000[index]`). The index range limits which MSRs are
  writable.
- **Value restrictions**: some indices have full validation (HWCR/0xC0010015: only bits
  21/24 toggleable, SmmLock bit 0 protected), others have NO validation (P-state MSRs
  0xC0010064-0xC0010068: arbitrary Fid/Did/Vid → frequency/voltage control → DoS or
  hardware damage).
- **SmmLock check**: if the driver's HWCR handler prevents clearing bit 0 (SmmLock), the
  SMM attack path is blocked. This is a deliberate security measure — note it as a
  dead-end, not a bypass target.

**Kill potential.** MSR writes alone do NOT provide a memory write primitive. They modify CPU
state (frequency, voltage, power). Useful for: DoS (invalid P-state → CPU halt),
Plundervolt-style fault injection (undervoltage → computation errors), or as supporting
evidence in a vulnerability report. NOT sufficient for EDR kill without a separate memory
write primitive.

---

## Quick tier picker
- Terminate imports + PID-in-buffer IOCTL → **Tier 1** (byovd-lib DriverConfig).
- Handle/attach imports, no terminate, maybe WRITE-dispatch → **Tier 2** (standalone).
- Physical/arbitrary memory map or write, MSR read → **Tier 3** (standalone; data-only if HVCI).
- UAF in kernel list + pool spray → **Tier 3** (kernel pool R/W → SSDT hijack).
- PCI config → SMN → SMU injection → **Tier 3** (hardware DMA write → SSDT hijack; AMD only).
- IoStatus.Information leak → **supports Tier 3** (KASLR bypass without NtQuerySystemInformation).
