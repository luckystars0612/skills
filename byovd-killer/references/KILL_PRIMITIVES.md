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

### 3d. PoC shape
Standalone crate (its own `[workspace]`, `[profile.release]`), `windows` crate for the Win32
surface. No `byovd-lib`. Structure: driver R/W wrapper → page-table walk → kernel discovery →
hijack install → kill loop over targets → restore. Default targets are the Defender set
(`MsMpEng.exe`, `MpDefenderCoreService.exe`, `SecurityHealthService.exe`, `MsSense.exe`).

**PPL/HVCI.** PPL: yes. HVCI: **data-only sub-tier is HVCI-safe**; the shellcode sub-tier needs
a writable+executable kernel target and can be blocked by HVCI/KDP depending on where it writes —
prefer data-only when HVCI/VBS is enforced.

**idalib (on the driver).** `xrefs_to MmMapIoSpace`/`HalTranslateBusAddress`; read the map-IOCTL
handler for the input struct (interface type, bus number, physical addr, size) and the fail-open
condition. The kernel-side hijack targets (SSDT, Win32k stubs) are discovered at runtime by the
PoC over the R/W primitive, not statically in the driver.

---

## Quick tier picker
- Terminate imports + PID-in-buffer IOCTL → **Tier 1** (byovd-lib DriverConfig).
- Handle/attach imports, no terminate, maybe WRITE-dispatch → **Tier 2** (standalone).
- Physical/arbitrary memory map or write, MSR read → **Tier 3** (standalone; data-only if HVCI).
