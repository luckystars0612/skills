# Vendor-Agnostic AV/EDR Bug Hunting Methodology

Derived from 11 MSNightmare/Nightmare-Eclipse PoCs targeting Defender, CrowdStrike,
Kaspersky, Avast/GenDigital, NVIDIA, and Windows subsystems. This methodology
generalizes their patterns to any AV/EDR product.

**Scope: legitimate, verified-scope bug hunting and security research only.**
**All PoC detonation must be VM-only.**

---

## Phase 1: Reconnaissance — Map the Product's Attack Surface

### 1.1 Enumerate privileged processes
```
# List all SYSTEM/service processes belonging to the product
tasklist /svc | findstr <vendor>
sc query type=service state=all | findstr <vendor>
# Or via PowerShell:
Get-Process | Where-Object {$_.Path -like "*<vendor>*"} | Select Name,Id,Path
Get-Service | Where-Object {$_.DisplayName -like "*<vendor>*"}
```

### 1.2 Enumerate IPC endpoints
- **RPC:** `RpcView` or `NtObjectManager` PowerShell module to list ALPC endpoints
  owned by the product's processes. Each RPC interface = potential coercion target.
- **COM:** `OleViewDotNet` to enumerate COM classes registered by the product, especially
  those with `LocalServer32` pointing to SYSTEM services.
- **Named pipes:** `[System.IO.Directory]::GetFiles("\\.\pipe\")` filtered by vendor name.
- **WMI:** Check if the product registers WMI providers (`wmic /namespace:\\root\<vendor>`).

### 1.3 Enumerate file system footprint
- Install directory (usually `Program Files`) — check for writable subdirectories
- `ProgramData\<vendor>` — update staging, quarantine, logs
- Per-user directories: `%APPDATA%\<vendor>`, `%LOCALAPPDATA%\<vendor>`
- Temp directories used during updates/scans
- Driver files in `System32\drivers\`

### 1.4 Enumerate registry footprint
- `HKLM\SOFTWARE\<vendor>` — install config, license info
- `HKLM\SYSTEM\CurrentControlSet\Services\<service>` — service config
- `HKCU\SOFTWARE\<vendor>` — per-user settings (user-writable = poisonable)
- Scheduled tasks: `schtasks /query /v /fo LIST | findstr <vendor>`

### 1.5 Enumerate kernel components
- Minifilter drivers: `fltmc filters` — altitude reveals the type
- Callbacks: `driver-analysis` skill to enumerate process/thread/image callbacks
- IOCTL interface: `driver-analysis` for dispatch table of each driver

---

## Phase 2: Identify Confused Deputies (Privileged Operations)

For each SYSTEM process/service identified in Phase 1, ask:

### 2.1 Does it have user-callable verbs that operate on paths?
Map each RPC/COM/ALPC method. Focus on verbs that:
- **Scan/clean/remediate** a file path (Defender MpClient → A1)
- **Restore** from quarantine to a user-influenced path
- **Update** signatures/engine from a path (Defender RPC Proc42 → A7)
- **Repair/rollback** an installation or change
- **Move/copy/delete** files as part of remediation

For each verb: does it open/create/write files BY PATH (not by pre-opened handle)?

### 2.2 Does it load DLLs from redirectable paths?
- Does any product process load DLLs via search order (not absolute path)?
- Does the GUI/tray process inherit the user's DOS device map? (→ A8)
- Does the product use PowerShell, cmd.exe, or other interpreters that have
  their own DLL search-order surface? (→ FalconFlank pattern)

### 2.3 Does it read config/manifests from user-writable locations?
- Per-user registry values read by SYSTEM services (→ B3)
- Shell folder paths expanded from user-controlled REG_EXPAND_SZ
- JSON/XML/INI config files in `%APPDATA%` or `%LOCALAPPDATA%`

### 2.4 Does it expose a sandbox that can read protected files?
- Can code inside the sandbox read `SAM`, `SYSTEM`, `SECURITY` hives? (→ A3)
- Can it read DPAPI masterkeys, private keys, or credential stores?
- What's the difference between "inside sandbox" and "standard user" file access?

---

## Phase 3: Test Redirect Primitives Against Each Deputy

For each privileged operation found in Phase 2, try each redirect from PRIMITIVES.md
section B in order of likelihood:

| If the op opens... | Try (in order) |
|---|---|
| A path inside a user-writable dir | B1 (junction), B2 (obj-mgr symlink), B7 (TxF) |
| A native/object-manager path | B2 (shadow dir + symlink), B4 (DefineDosDevice) |
| A registry-derived path | B3 (registry indirection) |
| A specific file by name | B5 (hardlink), B4 (DOS device) |
| A shared memory section | B6 (weak DACL write) |
| A CLFS log or associated file | B8 (container path abuse) |

### 3.1 Check impersonation first (Section F — fastest disqualifier)
Before spending time on redirect testing, verify the privileged op does NOT
impersonate the caller. If it does → move to the next op. If it doesn't → high
likelihood of exploitability.

### 3.2 Race-win selection
- **Default choice:** C2 (cfapi FETCH_DATA) — deterministic, ~100% success rate
- **Fallback:** C1 (oplock) — probabilistic, easier to set up, works on all Windows
- **Special case:** if the op reads the file multiple times (scan then clean), cfapi's
  state machine can serve different content each time (ShieldBreak pattern)

---

## Phase 4: Self-Protection Bypass Analysis

AV/EDR products protect themselves. Map what's protected and what's NOT:

### 4.1 Typically protected (by minifilter/driver)
- File writes to the product's install directory
- Process injection into product processes (WriteProcessMemory, QueueUserAPC)
- Registry writes to product config keys
- Process termination of product processes

### 4.2 Typically NOT protected (gap = attack surface)
- **Object manager namespace operations** — creating symlinks, DOS devices (HardBreacher)
- **CLFS log operations** — kernel handles these before the minifilter sees them (SignDrop)
- **cfapi placeholder creation** — Cloud Filter operations bypass file-based monitoring
- **RPC calls to the product's own endpoints** — the product trusts its own IPC
- **Shared memory section writes** — typically not monitored (GreenSection)
- **Registry writes to HKCU keys** consumed by SYSTEM services (LegacyHive)
- **Scheduled task creation/modification** — usually allowed for standard users

### 4.3 Test self-protection boundaries
```
# Can you write to the product's install dir?
echo test > "C:\Program Files\<vendor>\test.txt"
# Can you create DOS devices shadowing product paths?
DefineDosDevice(DDD_RAW_TARGET_PATH, "VENDOR-test", "\??\C:\temp")
# Can you open the product's RPC endpoints?
RpcStringBindingCompose + RpcBindingFromStringBinding
# Can you modify HKCU keys the product reads?
reg add HKCU\SOFTWARE\<vendor>\settings /v test /d "value"
```

---

## Phase 5: Update/Install Pipeline Analysis

Every product has an update mechanism. These are high-value targets:

### 5.1 Signature/definition updates
- Where are updates downloaded to? (writable staging dir?)
- Is disk space verified atomically? (→ A9 / BigDiskBuster)
- Are update files verified by signature before installation?
- Can you race the verify→install window?

### 5.2 Engine/binary updates
- Does the updater verify the integrity of the new binary after write?
- Can you lock the current binary to prevent replacement? (FILE_SHARE_READ)
- Does the updater use a temp dir you can junction-redirect?

### 5.3 Installer repair/self-heal
- Does `msiexec /f <product-guid>` run as SYSTEM?
- Does the repair re-read source files from a redirectable path?

---

## Phase 6: Conversion to Impact

Once you have a primitive (arbitrary write, read, delete, or create), convert using
PRIMITIVES.md section D. Priority order:

1. **Arbitrary write → DLL plant** — fastest path to SYSTEM code execution
2. **Arbitrary create (with attacker DACL) → DLL plant** — SignDrop pattern
3. **Arbitrary read → SAM dump → SYSTEM** — PrettyPrague's driverless chain
4. **Arbitrary delete → reload hijack** — delete a DLL, service restarts and
   loads from a search-order fallback you control
5. **Namespace hijack → AV-trusted execution** — HardBreacher pattern

### Known DLL plant targets (phantom/missing DLLs loaded by SYSTEM)
- `C:\Program Files\Common Files\microsoft shared\ink\hid.dll` (osk.exe)
- `C:\Windows\System32\bcrypt.dll` relative loads (PowerShell host)
- `C:\Windows\System32\version.dll` (various)
- `C:\Windows\System32\wer.dll` (WerFault)
- Side-by-side assembly gaps — check `sxs` manifests for missing DLLs

---

## Phase 7: Patch Analysis and Bypass

When a bug gets patched:

1. **Diff the patch** — what specifically changed?
2. **Classify the fix** — per-path block, mechanism block, or root-cause fix?
3. **If per-path:** try all other redirect mechanisms from PRIMITIVES.md B
4. **If mechanism-specific:** try the mechanism the patch doesn't cover
5. **If root-cause (impersonation added):** verify the impersonation is correct —
   does it cover ALL code paths? Is there a TOCTOU between impersonation and the op?
6. See PRIMITIVES.md section G for the full patch-bypass methodology.

---

## Quick-Reference: Technique Mapping by Product

| Product | Known techniques | Ref file |
|---|---|---|
| Windows Defender | MpClient scan→clean TOCTOU, cfapi FETCH_DATA, CLFS .cnpf, RPC coercion, disk DoS | DEFENDER_*.md |
| CrowdStrike Falcon | Macro-remediation DLL sideload, junction+TxF, oplock, Task Scheduler trigger | CROWDSTRIKE_FALCONFLANK.md |
| Kaspersky Endpoint | DOS device namespace hijack, parent-spoof NtCreateUserProcess, avpui.exe DLL load | KASPERSKY_HARDBREACHER.md |
| Avast/AVG/Norton | Sandbox file read → SAM dump, SamiChangePasswordUser, CMSTPLUA UAC bypass | AVAST_PRETTYPRAGUE.md |
| NVIDIA drivers | Shared section weak DACL, cross-session memory corruption, GPU driver crash | NVIDIA_GREENSECTION.md |
| Windows BitLocker/WinRE | unattend.xml injection on recovery partition after Defender offline scan | BITLOCKER_GREATXML.md |
| User Profile Service | Offline hive poison, object-manager shadow dirs, oplock race on UsrClass.dat | UPS_LEGACYHIVE.md |

---

## Appendix: idalib Quick Queries for New Targets

When you open a new AV/EDR binary in IDA, run these queries first:

```
# Find RPC server interfaces
entity_query: type=rpc_server
# Find file operations without impersonation
imports_query: NtCreateFile, CreateFileW, ZwCreateFile
# then xref check: is Impersonate* called before each?

# Find DLL loading that might be redirectable
imports_query: LoadLibraryW, LoadLibraryExW, LdrLoadDll
# Check if paths are absolute or relative

# Find shared sections (weak DACL candidates)
imports_query: NtCreateSection, ZwCreateSection
# Check security descriptor parameter

# Find cfapi usage (pre-vulnerable to FETCH_DATA)
imports_query: CfRegisterSyncRoot, CfConnectSyncRoot, CfExecute

# Find CLFS usage
imports_query: CreateLogFile, AddLogContainer, ClfsCreateLogFile

# Find update/manifest parsing
find_regex: \.msi|\.cab|\.xml|manifest|update|signature
```
