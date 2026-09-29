# Driver profile — <DRIVER_NAME>

Fill during Phase 1–3. Every fact is VERIFIED (seen in the binary/live) or INFERRED (assumed until
the kill confirms it). A Tier-1 killer needs the three bolded facts exact.

## Identity
- Driver file / SHA256: `<file>.sys` / `<hash>`
- Vendor / signer: `<vendor>` / `<cert>`
- LOLDrivers: `<url or "not listed">` · MS block list: `<yes/no>`
- Test OS build: `<e.g. Win11 25H2 26200, HVCI on/off>`
- Authorization: `<own VM / research / in-scope>` — detonation VM: `<name>`

## Phase 1 — Import screening
- Terminate imports: `<ZwTerminateProcess? PsTerminateProcess? none>`
- Handle-getter: `<ZwOpenProcess / PsLookupProcessByProcessId / ObOpenObjectByPointer / none>`
- Handle-stomp: `<KeStackAttachProcess + ObSetHandleAttributes + ZwClose? >`
- Memory-primitive: `<MmMapIoSpace / HalTranslateBusAddress / ZwMapViewOfSection / MSR? >`
- Kernel-VA R/W: `<MmCopyVirtualMemory (PreviousMode?) / MmProbeAndLockPages / unprobed store? >`
- Kernel call: `<indirect call from buffer / PsCreateSystemThread / KeInsertQueueApc / ExQueueWorkItem? >`
- Kernel file ops: `<ZwDeleteFile / ZwSetInformationFile rename+dispose / IoCreateFileEx / ZwWriteFile? >`
- Kernel registry write: `<ZwSetValueKey / ZwDeleteValueKey / RtlWriteRegistryValue? >`
- Callback teardown: `<FltUnregisterFilter / FltDetachVolume / ObUnRegisterCallbacks / CmUnRegisterCallback / ZwUnloadDriver? >`
- **All** classes found (not just the first): `<e.g. Tier 1 + Tier 5 + Tier 7>`
- Verdict: **Tier <1..7>** — `<one-line why, and what this class adds that the repo lacks>`

## Phase 2 — Dispatch chain (the three facts)
- DriverEntry → init fn: `<addr>`
- **Device path** (user mode): `\\.\<DEVICE>`  (VERIFIED via IoCreateSymbolicLink @ `<addr>`)
- Dispatch handler (MajorFunction[14]): `<addr>`   [or WRITE=index 4 → `<addr>`]
- **IOCTL / command code**: `0x<IOCTL>`  (method = `<buffered/neither/direct>` from low 2 bits)
- IOCTL table (all codes → handlers): `<code:fn, code:fn, …>`
- Size check on input: `<>= 0xNN>`
- **Buffer layout**: `<PID DWORD @ +N / u64 @ +0 / ASCII string / process NAME @ 256B>`; magic: `<none / 0x…>`
- Sink fn: `<addr>` — kill = `<ZwOpenProcess→ZwTerminateProcess / PsLookup→PsTerminate→Obf>`

## Phase 3 — Auth gap (the five gates — see LOAD_AND_AUTH_BYPASS.md)
- Gate 1 load: `<sc create / vendor service already installed & demand-start / blocked>`
- Gate 2 device open: SDDL (IoCreateDeviceSecure) `<none / admin / SYSTEM-only>`; symlink
  `<present / NT path only>`; exclusive `<yes/no>`; access mask required `<…>`
- Gate 3 caller validation: `<none / image SHA-256 / path / name / PID allowlist>` — bypass used:
  `<n.a. / handle theft from <process> / injection / per-IOCTL check = fatal>`
- Gate 4 argument validation: `<none / phys-addr blocklist (bypass: map from 0) / index table bound /
  bus-device check but not address>`; mapping API `<MmMapIoSpace → MiShowBadMapper risk / MDL-based>`
- Gate 5 telemetry left behind: `<7045 + service key + dropped .sys / none (vendor-loaded)>`
- Buffer secret / magic required: `<none / value>`
- Why it's reachable: `<the gap>`

## Phase 4 — PoC
- Shape: `<byovd-lib DriverConfig / standalone>`
- Overrides used: `<device_access / skip_unload / ignore_ioctl_error / ioctl_output_size / preflight_check>`
- Crate path: `<Driver-Killer/>`

## Phase 5 — Validation (on the VM)
- Benign kill (notepad.exe): `<PASS/FAIL — evidence>`
- Target kill: `<process, PID, dead & stayed dead? PPL held? HVCI? — evidence>`
- WinDbg confirmation: `<!drvobj / bp on sink / n.a.>`
- Status: **OPEN / CONFIRMED(<evidence>) / KILLED(<why not weaponizable>)**
