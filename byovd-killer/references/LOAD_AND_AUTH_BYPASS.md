# The load gate — getting the driver loaded and the IOCTL accepted

A weaponizable primitive is only half the problem. Between "the sink is reachable in the
decompilation" and "the IOCTL landed" there are **five independent gates**, and a driver can be
perfectly vulnerable and still unexploitable because of gate 3 or 4. Work them in order; each has
its own bypass family and its own evidence.

| Gate | Question | Fails with |
|---|---|---|
| 1 | Will the image load at all? | block list, HVCI/DSE, attestation, revoked cert |
| 2 | Can you open the device? | device SDDL, exclusive open, `\Device` with no symlink |
| 3 | Does the driver validate *the caller*? | image hash, path, process name, PID allowlist |
| 4 | Does the primitive validate *its own arguments*? | physical-address blocklist, MSR/PCI index table, bus/device check |
| 5 | What does loading leave behind? | Event 7045, driver-load ETW, Sysmon 6 |

---

## Gate 1 — Image load

Ordinary path: `sc create X type= kernel binPath= <path>\X.sys` then `sc start X` (or
`NtLoadDriver` with the service key written directly, or `OSRLoader`). Requires admin and
`SeLoadDriverPrivilege`. Three ways it fails and what to do:

- **On the Microsoft block list.** The load is refused on any machine enforcing it (default-on
  from Win11 24H2). Pick an unlisted driver — see `TARGET_SELECTION.md` Rule 3. Testing with the
  block list disabled is allowed, but the write-up must say so; a PoC that only works with
  enforcement off is a much weaker result.
- **Certificate expiry is not a problem; revocation is.** A driver signed before the 2015
  cross-signing cutoff still loads if the cert chain was valid at signing time. A revoked chain
  does not.
- **Already installed by the vendor.** The best case, and worth checking before you drop
  anything: if the target product is installed, its driver is already on disk in a signed
  location with a service registered, often demand-start and loaded by a SYSTEM service on first
  use. You then need no file drop, no `sc create`, and no 7045 — you trigger the vendor's own
  load path. This is the "pre-positioned BYOVD" framing that makes bundled drivers (the
  `iGameCenter` case) a stronger finding than a downloaded `.sys`.

## Gate 2 — Opening the device

`CreateFileW("\\\\.\\X", …)`. Common blockers:

- **Restrictive SDDL** via `IoCreateDeviceSecure` or a device-object ACL — an admin-only device
  is fine for BYOVD (you are already admin to load), a SYSTEM-only device is not; check whether
  the DACL admits `BA` (built-in admins) or only `SY`.
- **No symbolic link** — the driver created `\Device\X` but never `IoCreateSymbolicLink`. Open it
  through the NT namespace with `NtCreateFile` on `\Device\X` instead of the Win32 `\\.\` path.
- **Exclusive device** (`IoCreateDevice` with `Exclusive = TRUE`), or the vendor service holds it
  open without sharing — you get `ERROR_SHARING_VIOLATION` or `ACCESS_DENIED` until that process
  closes it. Stopping the vendor service, or gate-3 handle theft, both solve this.
- **Wrong access mask.** Some drivers demand `GENERIC_READ|GENERIC_WRITE` and reject
  `MAXIMUM_ALLOWED`; `byovd-lib`'s `device_access` override exists for exactly this.

## Gate 3 — Caller validation, and how to bypass it

Modern vendor drivers increasingly check *who is calling* before honoring a dangerous IOCTL. What
you will see in the dispatch path, and the corresponding bypass:

- **Caller image hash / path / name check.** The driver resolves the requesting process
  (`PsGetCurrentProcess`, `SeLocateProcessImageName`, `ZwQueryInformationProcess`) and compares a
  SHA-256 of the caller's image, or its path or filename, against an embedded allowlist of the
  vendor's own binaries.
  **Bypass — handle theft.** Let the vendor's own trusted binary open the device, then take its
  handle: enumerate system handles with
  `NtQuerySystemInformation(SystemExtendedHandleInformation)`, find the handle whose object is the
  target device and whose owner is the allowlisted process, open that process with
  `PROCESS_DUP_HANDLE`, and `DuplicateHandle` it into yourself. The validation already passed at
  open time, so every IOCTL you send through the stolen handle inherits it. **Repro:** the
  `AsIO3_64.sys` killers steal the device handle from `AsusCertService.exe`.
  Alternatives when the check happens per-IOCTL rather than at open: inject into the allowlisted
  process, or start it yourself and make it issue the call. A per-IOCTL check on the *current*
  process defeats handle theft — read the dispatch carefully to learn which of the two it is.
- **Shared secret / magic value in the input buffer.** Lift the constant from the decompilation.
- **Requestor-mode check** (`Irp->RequestorMode == KernelMode` required) — usually fatal from user
  mode; look for a second entry point (an internal-device-control path, or another driver in the
  same product that forwards IRPs) before giving up.
- **Privilege check** (`SeSinglePrivilegeCheck`) or a LocalSystem-only gate — you are admin, so
  impersonate or run as SYSTEM; `byovd-lib`'s `preflight_check` is where that goes.

## Gate 4 — Argument validation inside the primitive

The sink often guards its own arguments, and these guards are where the *new* bugs live — an
incomplete argument check is a CVE even when the driver already has a patched one:

- **Physical-address blocklist / allowlist.** The mapper refuses ranges that cover kernel memory.
  **Bypass:** ask for a mapping that *starts* at a permitted address — address 0 with a length
  large enough to cover the target range — if the check only validates the base. **Repro:** the
  `AsIO3_64.sys` killers map from physical address 0.
- **Mapping API choice decides whether 24H2 stops you.** `MmMapIoSpace`-based mappers can trip
  `MiShowBadMapper` on 24H2 and fail; MDL/section-based mappers (`ZwMapViewOfSection`,
  `MmMapMemoryDumpMdl`) do not. **Repro:** `Astra64.sys` is usable on 24H2 for this reason.
  Treat "which mapping API" as a *selection* criterion, not just an implementation detail.
- **Index tables.** MSR and PCI IOCTLs typically map a small user index onto an internal array of
  permitted registers. Check the bound for a signed comparison or an off-by-one — an OOB index
  reads a function pointer or an arbitrary register address out of adjacent data.
- **Partial checks.** The classic incomplete fix: the handler validates one field and not the one
  that matters. **Repro:** `IOMap64.sys` v3.2 validates the PCI bus/device but not the physical
  address, which is why the CVE-2024-41498 patch is bypassable.

## Gate 5 — What loading leaves behind

Note it in the write-up; defenders read this part. Service creation raises **Event ID 7045** (and
Sysmon 6 on driver load), the service key persists under
`HKLM\SYSTEM\CurrentControlSet\Services`, and the dropped `.sys` is on disk with a known hash.
Loading a *vendor-installed* driver through the product's own path produces none of the
service-creation artifacts, which is the honest reason bundled drivers matter — not that they are
easier to exploit, but that abusing them is much quieter.

---

## Verification checklist (on the VM)

1. `sc query X` / `driverquery` — the driver is actually loaded (not just the service created).
2. WinDbg: `!drvobj \Driver\X 2` and `!devobj \Device\X` — the dispatch address matches the one
   you reversed.
3. The device opens from *your* process, with the exact access mask the killer uses.
4. One benign IOCTL round-trips (a read of a known-good value) **before** you trust any write.
5. If a gate-3 or gate-4 bypass is in play, prove it: the same IOCTL without the bypass must fail
   with the status you predicted. A bypass you never saw fail is INFERRED, not VERIFIED.
