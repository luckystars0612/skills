# Driver anatomy — the six-step reverse chain (x64)

Goal of this pass: extract the **three facts** a Tier-1 killer needs, each VERIFIED against the
binary — (1) the **user-mode device path** `\\.\X`, (2) the **IOCTL / command code**, (3) the
**input-buffer layout** (where the target PID lives, and its width/encoding) — plus the **auth
gap** that makes the call reachable. For memory-primitive drivers (Tier 3) the same chain leads
to the map/write sink instead of a terminate, and the "IOCTL" becomes an R/W primitive.

Short names map to `mcp__plugin_ida-pro-mcp_idalib__<name>`. Open once with `idb_open`, orient
with `survey_binary`.

---

## Step 0 — Import screening (the go/no-go)
`imports` / `imports_query`. Decide the class before spending time:
- **Kill candidate:** a *handle-getter* (`ZwOpenProcess`/`NtOpenProcess`,
  `PsLookupProcessByProcessId`, `ObOpenObjectByPointer`) **and** a *terminator*
  (`ZwTerminateProcess`/`NtTerminateProcess`, or `PsTerminateProcess` resolved internally).
- **Handle-stomp candidate:** `KeStackAttachProcess` + `ObSetHandleAttributes` + `ZwClose`.
- **Memory-primitive candidate:** `MmMapIoSpace`, `MmMapMemoryDumpMdl`, `ZwMapViewOfSection`,
  `HalTranslateBusAddress`, `MmGetPhysicalAddress`. MSR/CR intrinsics won't import — if the table
  is thin, `find_regex` the disassembly for `0F 32` (rdmsr), `0F 30` (wrmsr), `0F 20`/`0F 22` (cr
  moves).
No hit in any bucket ⇒ probably not a killer; report and stop.

## Step 1 — DriverEntry
The PE entry point (`survey_binary` names it, or the `AddressOfEntryPoint`). It is usually a
stub that does stack-cookie/`__security_init` setup and **tail-calls** the real initializer —
follow that call. `decompile` the entry; the interesting work is the callee that takes
`DriverObject`.

## Step 2 — Device creation + dispatch table
In the initializer, find:
- `RtlInitUnicodeString(&u, L"\\Device\\X")` immediately before `IoCreateDevice(...&u...)` →
  the **kernel device name**. `IoCreateDeviceSecure` instead means the device has an **SDDL**
  (an auth gate) — read the SDDL string argument.
- `IoCreateSymbolicLink(L"\\DosDevices\\X", ...)` → the DOS name. User mode opens it as
  **`\\.\X`** (strip `\DosDevices\`, prefix `\\.\`). If there's no symlink, the device may only
  be reachable by native path — note it.
- `DriverObject->MajorFunction[i] = handler`. Index **14 (0xE) = IRP_MJ_DEVICE_CONTROL** is the
  DeviceIoControl path. **15 (0xF) = IRP_MJ_INTERNAL_DEVICE_CONTROL**. **0 = CREATE**,
  **2 = CLOSE**, **3 = READ**, **4 = WRITE**. A driver that does its work in `MajorFunction[4]`
  (WRITE) is driven with `WriteFile`, not `DeviceIoControl` (the `xhunter1.sys` case).
idalib: `xrefs_to` `IoCreateDevice`/`IoCreateSymbolicLink`; `get_string` on the referenced
UNICODE_STRING; `decompile` the initializer to read the MajorFunction assignments; several often
share one handler.

## Step 3 — Dispatch: read the IOCTL code and branch
`decompile` the `MajorFunction[14]` handler. It typically:
- validates `DeviceObject == g_DeviceObject`,
- gets the stack location (`IoGetCurrentIrpStackLocation`, i.e. `Irp->Tail.Overlay.CurrentStack
  Location`), and reads **`IoControlCode`** at `IO_STACK_LOCATION.Parameters.DeviceIoControl`.
  In a raw decompile that is often `*(a2 + 0x18)` (the IOCTL code), with
  `Parameters.DeviceIoControl.InputBufferLength` at `+0x10` and `OutputBufferLength` at `+0x08`.
- branches on the code (switch / if-ladder / binary search on the value).
Map **every** code → handler = the IOCTL table. Note codes with a `switch`; the terminate/map
one is your target.

**Decode the IOCTL code** to learn the buffer transfer method (low 2 bits):
`IOCTL = (DeviceType<<16) | (Access<<14) | (Function<<2) | Method`.
- `Method 0 = BUFFERED` → input & output share `Irp->AssociatedIrp.SystemBuffer`.
- `Method 1 = IN_DIRECT`, `2 = OUT_DIRECT` → MDL at `Irp->MdlAddress`.
- `Method 3 = NEITHER` → raw user pointers `Type3InputBuffer` /
  `Irp->UserBuffer` (no probe by the I/O manager — extra-dangerous, common in these drivers).
Example: `0xB4A00404 & 3 = 0` → buffered; `0x222024 & 3 = 0` → buffered; `0x22E010 & 3 = 0`.

## Step 4 — The IOCTL handler: validation + buffer reach
`decompile` the target branch's function. Note:
- the **size check** — very often the *only* validation, e.g. `if (InputLength >= 0x18)`. That
  minimum size is a strong hint at the struct size.
- how it reaches the input: `SystemBuffer` (buffered), `Type3InputBuffer` (neither),
  `MmGetSystemAddressForMdlSafe(Irp->MdlAddress)` (direct).
- any `ProbeForRead`/`ProbeForWrite` (often missing on NEITHER — note it), and any
  `ExGetPreviousMode`/requestor-mode check.

## Step 5 — The sink: the exact PID offset and encoding
`decompile` the function the handler calls with the buffer. This is where you read the killer's
buffer layout, VERIFIED:
- **PID offset & width:** `*(_DWORD *)(buf + 4)` → PID is a **DWORD at +4**;
  `*(_QWORD *)(buf)` → **u64 at +0**; `_strtoui64(buf,...)`/`atoi(buf)` → the PID is an **ASCII
  string**, not binary. Some drivers take a **process name** (ASCII, fixed buffer) and do their
  own lookup — then `build_ioctl_input` writes the name, not a PID.
- **magic values:** an `if (*(buf) == 0xFA123456)` header the killer must reproduce.
- **the kill:** `ZwOpenProcess(PROCESS_TERMINATE)` → `ZwTerminateProcess`, or
  `PsLookupProcessByProcessId` → `PsTerminateProcess` → `ObfDereferenceObject`. Retry loops are
  common and harmless to mirror. `PsTerminateProcess` (undocumented, resolved by pattern from
  `PsGetProcessExitStatus` or a fixed offset) is the PPL/EDR-bypassing variant.
idalib: `trace_data_flow` from the handler's buffer arg to the `ClientId.UniqueProcess` /
`ZwOpenProcess` argument to pin the offset without eyeballing; `xrefs_to` `ZwTerminateProcess`.

**Observed Tier-1 layouts from the BYOVD repo** (targets to recognize, not to trust blindly):
| Driver | Device | IOCTL | Buffer layout |
|---|---|---|---|
| TfSysMon (sysmon) | `\\.\TfSysMon` | `0xB4A00404` | 24B; PID DWORD @ **+4** |
| BdApiUtil64 | `\\.\BdApiUtil` | `0x800024B4` | PID DWORD @ +0 |
| CcProtect / Unknown | `\\.\...` | `0x222024` | PID DWORD @ +0 |
| GameDriverX64 | `\\.\...` | `0x222040` | `{magic:0xFA123456, pid}` |
| EnPortv | `\\.\...` | `0x00223078` | 0x10B; self_pid @ +0, target_pid @ **+8** |
| PCTcore64 | `\\.\...` | `0x80008644` | 0x10B; PID **u64** @ +0 |
| Wsftprm | `\\.\...` | `0x22201C` | 1036B; PID DWORD @ +0 (rest padding) |
| Viragt64 | `\\.\...` | `0x82730030` | 256B **process name** ASCII (kills by name) |
| PoisonX | `\\.\{GUID}` | `0x22E010` | PID as **ASCII string** |
| NSecKrnl | `\\.\...` | `0x2248E0` | PID **u64**; driver reports error on success |
| STProcessMonitor v114/v2618 | `\\.\...` | `0xB822200C` / `0xB822A00C` | 8B; PID DWORD @ +0; v2618 needs LocalSystem |

## Step 6 — The auth gap
The reason the call works from a normal caller. Look for the **absence** of:
- `IoCreateDeviceSecure` + a restrictive SDDL (device open would be denied),
- a shared secret / magic checked in the buffer,
- `SeSinglePrivilegeCheck` / token checks,
- a requestor-mode / `ExGetPreviousMode == UserMode` reject.
Presence of any tells you what the killer must satisfy (supply the secret, run as LocalSystem,
etc. — mirror it in `preflight_check`/`build_ioctl_input`). Absence is the vulnerability; state
it plainly in the write-up.

---

## Live confirmation with WinDbg (optional, on a VM kernel target)
`open_kd_session`, then:
- `!drvobj \Driver\X 2` — dump the MajorFunction table; confirm your dispatch address.
- `!devobj \Device\X` — confirm the device exists and its type.
- `x X!*` / `u <handler>` — sanity-check the decompiled dispatch against live disassembly.
- set a bp on the sink, fire the IOCTL from the killer, confirm the PID argument matches your
  offset. This turns an INFERRED offset into VERIFIED before you rely on it.
