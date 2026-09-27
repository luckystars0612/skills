# PE analysis — what the binary structure reveals about vulnerability potential

Before reversing code, the PE headers, sections, imports, exports, and metadata tell you
what the binary does, how it was built, and where to look for bugs. This is a 5-minute pass
that focuses the deeper analysis.

Short names map to `mcp__plugin_ida-pro-mcp_idalib__<name>`.

---

## 1. Basic identification

`survey_binary` gives the overview. Record:

| Field | Where | What it tells you |
|-------|-------|-------------------|
| Machine | PE header | x86 / x64 / ARM64 — determines pointer width, calling convention |
| Subsystem | Optional header | `NATIVE` (1) = kernel driver. `WINDOWS_GUI` (2) or `WINDOWS_CUI` (3) = userland |
| Characteristics | File header | `IMAGE_FILE_DLL` = DLL. `IMAGE_FILE_SYSTEM` = driver |
| DllCharacteristics | Optional header | ASLR, DEP/NX, CFG, CET — see §3 Mitigations |
| TimeDateStamp | File header | Build date — old = more likely to have legacy bugs |
| Linker version | Optional header | MSVC version → infer compiler security features |
| Checksum | Optional header | Non-zero and correct = signed/verified binary |

### Driver-specific
- `AddressOfEntryPoint` → `DriverEntry` (or a GS init stub that calls the real init).
- Section count and names: `.INIT` (discarded after init — interesting code runs only once),
  `.PAGE` (pageable — can't run at DISPATCH_LEVEL), `.text` (non-paged code).

### Userland-specific
- TLS directory → TLS callbacks execute before `main` — check for anti-debug or init code.
- Resource directory → version info (product name, version, vendor) + embedded binaries.
- Debug directory → PDB path (reveals build environment, developer paths).

---

## 2. Import analysis — the first-pass X-ray

`imports` gives the full import table. The imports are the most efficient single indicator of
what a binary does and what bugs to look for.

### 2a. Kernel driver import patterns

**Dangerous (prioritize):**
| Import | What it does | Bug class |
|--------|-------------|-----------|
| `memcpy`/`RtlCopyMemory` | Copy bytes | Buffer overflow if size unchecked |
| `strcpy`/`wcscpy` | Copy string (no bounds) | Stack/heap overflow |
| `sprintf`/`swprintf` | Format string (no bounds) | Stack overflow, format string |
| `ExAllocatePoolWithTag` | Pool allocation | UAF, double free (with Free) |
| `ExFreePoolWithTag` | Pool free | Double free, UAF |
| `MmGetSystemAddressForMdlSafe` | Map MDL to VA | NULL deref if unchecked |
| `MmMapIoSpace` | Map physical → virtual | Arbitrary phys memory access |
| `ZwMapViewOfSection` | Map section into process | Arbitrary memory mapping |
| `HalTranslateBusAddress` | Bus → physical address | Fail-open phys mapping |
| `ZwOpenProcess` | Open process handle | Process manipulation |
| `ZwTerminateProcess` | Kill process | BYOVD primitive |
| `ObOpenObjectByPointer` | Get handle from pointer | Handle escalation |
| `KeStackAttachProcess` | Attach to process context | Handle stomp |
| `__readmsr`/`__writemsr` | Read/write MSR | CPU state manipulation |

**Safety indicators (check for presence):**
| Import | What it means |
|--------|--------------|
| `__security_check_cookie` | /GS stack cookies enabled |
| `ProbeForRead`/`ProbeForWrite` | Driver validates user pointers (METHOD_NEITHER) |
| `ExGetPreviousMode` | Driver checks caller's mode |
| `ExAcquireFastMutex`/`KeAcquireSpinLock` | Synchronization — less likely race conditions |
| `IoCreateDeviceSecure` | SDDL-restricted device |
| `SeSinglePrivilegeCheck` | Privilege gate |
| `RtlSizeTMult`/`RtlSizeTAdd`/`ULongMult` | Safe integer arithmetic |
| `RtlStringCbCopyW`/`RtlStringCchCopyW` | Safe string copy (counted) |

**Absence is often more interesting than presence:**
- No `__security_check_cookie` → no stack cookies → stack overflows are directly exploitable.
- No `ProbeForRead` + has METHOD_NEITHER IOCTLs → missing probe = arbitrary kernel R/W.
- No `ExGetPreviousMode` + has `Zw*` calls from IOCTL handlers → mode bypass.
- No locking imports + has multi-handler shared state → race condition.

### 2b. Userland import patterns

**Attack surface indicators:**
| Import | What it exposes |
|--------|----------------|
| `RpcServerRegisterIf*` | RPC interface (inter-process input) |
| `CreateNamedPipeW` | Named pipe server (IPC) |
| `bind`/`listen`/`accept` | Network listener |
| `DllGetClassObject` (export) | COM server |
| `RegisterClassExW` | Window message handler |
| `HttpAddUrl` | HTTP.sys listener |

**Dangerous operations in privileged processes:**
| Import | Risk |
|--------|------|
| `CreateProcessW`/`ShellExecuteW` | Command injection |
| `LoadLibraryW`/`LoadLibraryExW` | DLL injection / side-loading |
| `CreateFileW`/`MoveFileW`/`DeleteFileW` | File race / symlink |
| `RegSetValueExW`/`RegOpenKeyExW` | Registry manipulation |
| `SetSecurityInfo`/`SetNamedSecurityInfoW` | ACL manipulation |

---

## 3. Mitigation assessment

`DllCharacteristics` flags in the optional header reveal which OS mitigations apply:

| Flag | Value | Meaning |
|------|-------|---------|
| `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | 0x0040 | ASLR enabled |
| `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | 0x0100 | DEP/NX enabled |
| `IMAGE_DLLCHARACTERISTICS_NO_SEH` | 0x0400 | No SEH → SEH overwrite not useful |
| `IMAGE_DLLCHARACTERISTICS_GUARD_CF` | 0x4000 | Control Flow Guard (CFG) |
| `IMAGE_DLLCHARACTERISTICS_CET_COMPAT` | 0x... | CET shadow stack |

**For vulnerability research, mitigations DON'T change whether a bug exists — they change
exploitability.** Report the bug regardless; note the mitigations as factors in the severity
assessment. A buffer overflow with ASLR+DEP+CFG is harder to exploit but still a bug.

**Absence of mitigations increases severity:**
- No ASLR → code/data at predictable addresses → easier exploitation.
- No DEP → shellcode in data sections → trivial code execution.
- No CFG → vtable/function-pointer overwrites → direct control flow hijack.
- No stack cookies → stack buffer overflow = direct return-address overwrite.

Check with:
```
dumpbin /headers target.exe | findstr "DLL Characteristics"
```
Or via idalib: `survey_binary` often includes this in the PE metadata.

---

## 4. Export analysis (DLLs and drivers)

`survey_binary` or a direct export-table parse.

**For DLLs:** Every export is a function that external code can call. If the DLL runs in a
privileged process (loaded by a SYSTEM service), every export is a potential entry point
for attacks via the calling process.

**For drivers:** Exports are rare but meaningful. Some drivers export functions for other
kernel modules to call (e.g., filter manager APIs, crypto primitives). These are
kernel-to-kernel interfaces — lower priority than user-mode IOCTLs but worth noting.

---

## 5. Section analysis

Unusual sections can indicate interesting code regions:

| Section name | What it usually means |
|---|---|
| `.text` | Code (standard) |
| `.rdata` | Read-only data — constants, vtables, string literals |
| `.data` | Read-write data — globals, function pointers |
| `.pdata` | Exception handling data (x64 unwind info) |
| `.reloc` | Relocation table (needed for ASLR) |
| `.rsrc` | Resources — version info, embedded files, dialogs |
| `.INIT` (drivers) | Init code, discarded after DriverEntry — run-once bugs |
| `.PAGE` (drivers) | Pageable code — can't run at DISPATCH_LEVEL |
| `.edata` | Explicit export section |
| `.tls` | Thread-local storage — check for TLS callbacks |

**Red flags:**
- Writable + executable section (W+X) → can write and execute code in the same section →
  no DEP protection for that region.
- Very large `.data` or unnamed sections → possible embedded binaries, shellcode, or
  encrypted payloads (relevant for malware analysis).
- Custom section names (`.vmp0`, `.upx0`, etc.) → packer/obfuscator → the binary is
  protected, analysis will be harder.

---

## 6. Version info and digital signatures

### Version info (from the resource section)
- **ProductName** / **FileDescription** → identify the product and purpose.
- **FileVersion** / **ProductVersion** → check against known advisories for this version.
- **CompanyName** → identify the vendor for responsible disclosure.
- **OriginalFilename** → the intended filename (may differ from the actual filename).
- **LegalCopyright** → vendor confirmation.

### Digital signature
- **Signed?** → a signed driver loads on 64-bit Windows; unsigned drivers don't (without
  test-signing mode). A signed binary from a known vendor is a higher-value target for
  responsible disclosure.
- **Signer identity** → the vendor. Cross-sign vs WHQL vs attestation-signed.
- **Timestamp** → when the binary was signed (may differ from build date).
- **Revoked?** → check the Microsoft driver block list. A revoked driver is already known-
  bad; new findings in it are still valuable (variant analysis) but the driver may not load
  on machines with the block list enabled.

Check with:
```powershell
Get-AuthenticodeSignature target.sys | Format-List *
sigcheck -a target.sys   # from Sysinternals
```

---

## 7. String analysis

`get_string` / `search_text` for interesting strings:

| String pattern | What it reveals |
|---|---|
| `\\Device\\` | Kernel device names |
| `\\DosDevices\\` | DOS device names → user-mode paths |
| `\\.\pipe\` | Named pipe names |
| `SDDL:` or `D:P(A;;` | Security descriptors |
| `\\Registry\\Machine\\` | Registry paths the driver accesses |
| `%s`, `%d`, `%x` | Format strings → check if user-controlled |
| Error messages with `0x%08X` | Debug info → may leak addresses in output |
| File paths (`C:\`, `%TEMP%`) | File operations → TOCTOU surface |
| HTTP/URL patterns | Network activity |
| `password`, `key`, `secret`, `token` | Credential handling |
| Embedded SQL or command strings | Injection surface |
