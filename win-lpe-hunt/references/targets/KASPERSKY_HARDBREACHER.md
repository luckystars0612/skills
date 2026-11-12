# HardBreacher — Kaspersky Endpoint Security 0day LPE

## Target
- **Binary:** avpui.exe (Kaspersky GUI process)
- **Version:** Kaspersky Endpoint Security v14.0.0.504
- **Privilege:** SYSTEM (via Kaspersky's self-protection bypass)

## Vulnerability class
AV process namespace hijack — abuse object manager to redirect Kaspersky's own DLL
loading, making it load attacker code as a trusted AV component.

## Technique chain

### Reconnaissance — install path discovery
```cpp
RegOpenKeyExW(HKEY_LOCAL_MACHINE,
    L"SOFTWARE\\WOW6432Node\\KasperskyLab\\protected\\KES\\ProductRoot", ...)
RegQueryValueExW(hKey, L"", ...)  // default value = install path
```

### Object directory setup (A8 — namespace hijack)
1. Query current process token for `AuthenticationId`
2. Open `\Sessions\0\DosDevices\<AuthenticationId>` object directory
3. Create sub-directory named `KASPERSKY-<GUID>` (mimics Kaspersky's own naming)
4. Use `DefineDosDevice(DDD_RAW_TARGET_PATH)` to create DOS device symlinks:
   - Map Kaspersky DLL filenames to attacker's payload directory
   - Critical: `avpuimain.dll` → attacker's fake DLL path

### Process creation with parent spoofing
```cpp
NtCreateUserProcess(
    ...,
    PS_ATTRIBUTE_IMAGE_NAME: "avpui.exe",
    PS_ATTRIBUTE_PARENT_PROCESS: explorer_handle,  // parent spoof
    CREATE_SUSPENDED
)
```
- Creates `avpui.exe` suspended with explorer.exe as parent
- Before resume: create `C:` symlink in object namespace pointing to fake directory

### DLL hijack execution
Resume the process → Kaspersky's `avpui.exe` resolves DLL paths through the poisoned
object namespace → loads attacker's `avpuimain.dll` instead of the real one.

### Payload DLL (SolidSnake — x86)
```cpp
// dllmain.cpp behaviors:
// 1. Signal main PoC
SetEvent(OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\HardBreacher-SolidSnake-Sync-Event"))
// 2. Hide Kaspersky notification windows
EnumWindows(callback_that_hides_kaspersky_windows)
// 3. Terminate other avpui.exe instances
CreateToolhelp32Snapshot → terminate competing avpui.exe processes
```

### Post-exploitation demo (WannaCry-style)
The PoC demonstrates impact by encrypting files:
- AES-128-CBC with random keys per file
- `.WNCRY` / `.WNCRYT` extensions
- Creates hardlinks and sets junctions
- This is the demo payload — the LPE is the namespace hijack itself

## Key techniques from source

### DefineDosDevice as symlink primitive
```cpp
DefineDosDevice(DDD_RAW_TARGET_PATH, L"KASPERSKY-{GUID}\\file.dll",
    L"\\??\\C:\\attacker\\payload.dll")
```
This is a user-mode API that creates object-manager symlinks without needing
`NtCreateSymbolicLinkObject` directly. Simpler than raw NT API approach.

### Parent process spoofing
`PS_ATTRIBUTE_PARENT_PROCESS` in `NtCreateUserProcess` attributes — makes the new
process appear as a child of explorer.exe, evading process-tree heuristics.

## Hunt generalization for other AV/EDR
1. **Find the GUI process:** Most AV products have a user-facing tray/UI process
   (`avpui.exe`, `avgui.exe`, `NortonSecurity.exe`, etc.)
2. **Check DLL load paths:** Does the GUI process load DLLs from paths resolvable
   through the DOS device map?
3. **Check self-protection:** Does the AV's minifilter/driver protect its own
   processes from DLL injection but NOT from namespace manipulation?
4. **DefineDosDevice test:** Can you create DOS device entries that shadow the
   AV's DLL paths? This works because DOS devices are per-logon-session.
5. **WOW6432Node:** 32-bit AV components on 64-bit Windows have additional
   search-order attack surface

### Critical insight
AV self-protection (minifilters like klif.sys, WdFilter) typically blocks:
- Process injection (WriteProcessMemory, QueueUserAPC)
- File modification in AV install directories
- Registry modification of AV config keys

But they do NOT typically protect against:
- Object manager namespace manipulation
- DOS device map poisoning
- Parent process spoofing
- Creating new processes with the same name as AV binaries
