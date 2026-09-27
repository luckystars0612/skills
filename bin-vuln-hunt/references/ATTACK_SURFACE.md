# Attack surface mapping — boundary → handler → priority

The first real analysis step. Before deep reversing, enumerate every input boundary the
binary exposes to lower-privilege callers. The output is a ranked table:

| # | Boundary | Reach | Trust | Handler | Priority |
|---|----------|-------|-------|---------|----------|

- **Boundary**: the specific input path (e.g., `IOCTL 0x222004 METHOD_NEITHER`).
- **Reach**: who can send input (any user, admin only, network, local service).
- **Trust**: what validation the boundary applies (SDDL, requestor mode, size check, none).
- **Handler**: the function address that processes input from this boundary.
- **Priority**: attacker-reachable × high-impact × complex-code = high priority.

Short names map to `mcp__plugin_ida-pro-mcp_idalib__<name>`.

---

## §1. Kernel drivers (.sys)

### 1a. The device + IOCTL surface

**Step 1 — Find the device.** `idb_open`, `survey_binary`, then:
- `imports_query` for `IoCreateDevice` or `IoCreateDeviceSecure`.
- `xrefs_to` each → `decompile` the caller (the initializer, usually called from DriverEntry).
- `get_string` on the `RtlInitUnicodeString` argument immediately before `IoCreateDevice` →
  the kernel device name (`\Device\X`).
- `IoCreateSymbolicLink` → the DOS name (`\DosDevices\X`) → user-mode path `\\.\X`.
- If `IoCreateDeviceSecure` → read the SDDL string argument. A restrictive SDDL (e.g.,
  `D:P(A;;GA;;;SY)` = SYSTEM only) limits who can open the device. `D:P(A;;GA;;;WD)` (World)
  = any user. No SDDL (`IoCreateDevice` without `Secure`) → default ACL from the device
  type, often permissive.

**Step 2 — Map the dispatch table.** In the initializer, find:
```
DriverObject->MajorFunction[0]  = CreateHandler;     // IRP_MJ_CREATE
DriverObject->MajorFunction[2]  = CloseHandler;      // IRP_MJ_CLOSE
DriverObject->MajorFunction[3]  = ReadHandler;       // IRP_MJ_READ
DriverObject->MajorFunction[4]  = WriteHandler;      // IRP_MJ_WRITE
DriverObject->MajorFunction[14] = DevCtrlHandler;    // IRP_MJ_DEVICE_CONTROL
DriverObject->MajorFunction[15] = IntDevCtrlHandler;  // IRP_MJ_INTERNAL_DEVICE_CONTROL
```
`decompile` the initializer; the assignments are `*(DriverObject + 0x70 + index*8) = handler`.
Index 14 (offset 0x70 + 0x70 = 0xE0) is DeviceIoControl, the primary attack surface. But
DO NOT ignore the others:

- **CREATE (0) / CLOSE (2):** often share state with IOCTL handlers (allocate/free tracking
  nodes, reference counting). Race conditions between CREATE/CLOSE and IOCTL are a major
  UAF source. Always map these.
- **READ (3) / WRITE (4):** alternative data paths. Some drivers process commands via
  `WriteFile` instead of `DeviceIoControl` (the `xhunter1.sys` pattern). The data comes
  from `Irp->AssociatedIrp.SystemBuffer` or `Irp->MdlAddress` → same attack surface as
  IOCTLs but with different size semantics.
- **INTERNAL_DEVICE_CONTROL (15):** reachable only from kernel mode — lower priority unless
  you're auditing the whole driver stack.

**Step 3 — Build the IOCTL map.** `decompile` the DeviceIoControl handler. It reads the
IOCTL code from the stack location:
```
IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode
```
In decompiler output: often `*(a2 + 0x18)` (IOCTL code), `*(a2 + 0x10)`
(InputBufferLength), `*(a2 + 0x08)` (OutputBufferLength).

The handler branches on the code — `switch`, if-ladder, or binary search. Map **every**
code to its handler function. For each code, decode the method:
```
IOCTL = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
Method = IOCTL & 3:
  0 = BUFFERED     → SystemBuffer (safe, kernel-copied)
  1 = IN_DIRECT    → MDL
  2 = OUT_DIRECT   → MDL
  3 = NEITHER      → Type3InputBuffer (raw user pointer — DANGEROUS)
```

METHOD_NEITHER IOCTLs are the highest-priority targets: the I/O manager does no validation,
the driver gets a raw user-mode pointer, and missing `ProbeForRead`/`ProbeForWrite` is a
direct vulnerability.

**IOCTL table format (record all of these):**
```
IOCTL 0xNNNNNNNN | METHOD_X | Handler @ 0xAddr | InSize check | OutSize check | Notes
```

### 1b. Registered kernel callbacks

Drivers that register callbacks process events triggered by external activity — these are
additional input paths that may not be obvious from the dispatch table.

- `PsSetCreateProcessNotifyRoutine` / `PsSetCreateProcessNotifyRoutineEx` — called on every
  process creation/termination. The callback receives `PPS_CREATE_NOTIFY_INFO` which
  contains user-influenced fields (`ImageFileName`, `CommandLine`).
- `PsSetCreateThreadNotifyRoutine` — called on thread creation. Less user-controllable.
- `PsSetLoadImageNotifyRoutine` — called when any image (DLL, EXE) is loaded. The
  `FullImageName` is user-influenced.
- `CmRegisterCallbackEx` — called on registry operations. The callback receives key paths
  and values that may be user-controlled.
- `ObRegisterCallbacks` — called on handle operations. The `PreOperation` callback can be
  attacked if it has parsing bugs on the object name.
- `FltRegisterFilter` (minifilter) — file system filter callbacks. Every file operation is
  an input path; the filename and content are user-controlled.

**idalib.** `imports_query` for each registration API; `xrefs_to`; `decompile` the callback
function. The callback's arguments are the "input buffer" — trace user-controllable fields
through the callback's logic.

### 1c. WMI and ETW providers

- `IoWMIRegistrationControl` → the driver exposes a WMI data/event provider. The WMI
  queries can be sent from user mode via `IWbemServices`. Input: the WMI method parameters.
- `EtwRegister` → ETW provider. Usually output-only (events), but some drivers use ETW
  write-and-read patterns.

**idalib.** `imports_query` for `IoWMIRegistrationControl`; `decompile` the WMI dispatch
routine (often set via `WMILIB_CONTEXT.QueryWmiDataBlock` / `SetWmiDataBlock` /
`ExecuteWmiMethod`).

---

## §2. Userland PE files (.exe / .dll)

### 2a. RPC interfaces

Remote Procedure Call interfaces are the primary inter-process attack surface on Windows.
A service that registers an RPC interface is reachable from any process that knows the
endpoint (usually a named pipe or ALPC port).

**Import signature.** `RpcServerRegisterIf`/`RpcServerRegisterIf2`/`RpcServerRegisterIf3` +
`RpcServerUseProtseqEp` (named pipe: `ncacn_np`, ALPC: `ncalrpc`, TCP: `ncacn_ip_tcp`).

**Finding the dispatch table.** The RPC runtime dispatches calls via an
`RPC_SERVER_INTERFACE` structure that points to a `MIDL_SERVER_INFO` → `DispatchTable` (array
of function pointers). The NDR interpreter (`NdrServerCall2`/`Ndr64AsyncServerCall`) uses
this table to find the server-side function for each method index.

**idalib.** `imports_query` for `RpcServerRegisterIf`; `xrefs_to` → the argument is a
pointer to `RPC_SERVER_INTERFACE`; `decompile` or `entity_query` to find the
`MIDL_SERVER_INFO` and its `DispatchTable`. Each entry in the dispatch table is a method the
attacker can call — `decompile` each. The method's parameters are the attack surface.

**Security callback.** `RpcServerRegisterIf2`/`If3` accept a security callback that can
restrict who calls. If `RpcServerRegisterIf` (the basic one) is used → **no security
callback** → any local user can call any method.

### 2b. Named pipes

**Import signature.** `CreateNamedPipeW`/`CreateNamedPipeA`.

**idalib.** `xrefs_to CreateNamedPipeW`; `get_string` on the pipe name argument
(`\\.\pipe\X`). Check:
- `nMaxInstances` — `PIPE_UNLIMITED_INSTANCES` allows multiple clients → can a low-priv
  client connect?
- `PIPE_ACCESS_INBOUND`/`OUTBOUND`/`DUPLEX` — who reads, who writes.
- Security descriptor argument — who can connect.

The pipe's read loop is the input handler. `decompile` the function that calls `ReadFile`/
`PeekNamedPipe` on the server side and processes the received data.

### 2c. COM interfaces

**Export signature (DLL).** Exports `DllGetClassObject`, `DllRegisterServer`. The DLL is a
COM server — it can be activated from another process (or remotely if registered for DCOM).

**idalib.** `list_funcs` → find `DllGetClassObject`; `decompile` it to find the
`IClassFactory::CreateInstance` implementation → the main object. The object's vtable methods
are the interface. Each method is an entry point an attacker can call via COM.

**Registry.** COM registration in `HKLM\SOFTWARE\Classes\CLSID\{GUID}` or
`HKCU\SOFTWARE\Classes\CLSID\{GUID}`. If registered in HKCU → a user can hijack it by
registering a replacement (COM hijacking). If the server runs as SYSTEM and the user can
create instances → cross-privilege boundary.

### 2d. Window messages

**Import signature.** `RegisterClassEx` + `CreateWindowEx` + `DefWindowProc` — the binary
creates a window. The window procedure (`lpfnWndProc`) processes `WM_COPYDATA` and custom
messages from any process on the same desktop.

**idalib.** `xrefs_to RegisterClassExW`; find the `WNDCLASSEX.lpfnWndProc`; `decompile` the
window procedure. Any `WM_COPYDATA` handler or custom message handler is an input boundary.

### 2e. Network listeners

**Import signature.** `bind` + `listen` (raw socket), `HttpAddUrl` (HTTP.sys), Winsock2
`WSARecv`. Also: `AcceptEx`, `WSAAcceptEx` for async servers.

**idalib.** `xrefs_to bind`; `decompile` the caller to find the port and protocol. Then find
the `recv`/`WSARecv` loop → the data processing function → the input handler.

### 2f. Exported functions (DLLs loaded by privileged processes)

Every exported function in a DLL is an input boundary if the DLL is loaded by a process
running at a higher privilege level. The attacker controls the arguments if they can
influence how the higher-privilege process calls the DLL (via config files, registry, etc.).

**idalib.** `survey_binary` → export table. For each export, `decompile` and assess: does it
take user-controllable arguments? Does it perform dangerous operations (file I/O, memory
allocation, code execution)?

---

## §3. Software bundles (multiple binaries)

### 3a. Privilege topology

Map every process in the bundle and its privilege level:
```
Process A (SYSTEM) ←→ [named pipe \\.\pipe\X] ←→ Process B (user)
Process A (SYSTEM) → [shared memory section] → Process C (admin)
Process D (admin) ← [COM activation] ← Process E (user)
```

Focus on **cross-privilege boundaries**: any IPC channel where a lower-privilege process
sends data to a higher-privilege process. These are the highest-value targets.

### 3b. IPC channel enumeration

For each binary in the bundle, apply §2 (RPC, pipes, COM, messages, network). Then
cross-reference: which pipe server is in which process? Which COM server is activated by
which client? Build the IPC graph.

Tools beyond idalib:
- `Procmon` — dynamic: filter by process, operation category = `IPC`, to see every named
  pipe, ALPC, section, mutex, event the processes create and connect to.
- `RPCView` — enumerate registered RPC interfaces at runtime, match to binary by PID.
- `OleView` — enumerate registered COM objects, their CLSIDs, and the server binaries.

### 3c. Shared files and registry keys

If Process A (SYSTEM) reads a file that Process B (user) can write, that file is a cross-
privilege input boundary — even if A and B don't communicate via IPC. Common patterns:
- Config files in `ProgramData` or user-writable directories.
- Log files that are parsed by a privileged cleanup process.
- DLL/EXE paths in registry keys that a user can modify → DLL hijacking / DLL side-loading.
- Installer temp directories → local privilege escalation via symlink race.

---

## Priority ranking heuristic

Score each boundary on three axes (1-3 each), multiply:

| Axis | 1 (low) | 2 (medium) | 3 (high) |
|------|---------|------------|----------|
| Reachability | Admin-only or kernel-only | Any local user | Network / unauthenticated |
| Impact | Info leak / DoS | Memory corruption (crash) | Code execution / LPE |
| Complexity | Simple handler, few paths | Medium logic | Complex parsing, multiple branches |

`Priority = Reachability × Impact × Complexity`. Higher = more likely to have bugs AND more
impactful if found. Typical priority ordering:

1. METHOD_NEITHER IOCTLs reachable from any user (R=2, I=3, C=2 → 12+)
2. RPC methods in SYSTEM services with no security callback (R=2, I=3, C=2 → 12+)
3. Named pipe handlers in SYSTEM services (R=2, I=3, C=2 → 12+)
4. METHOD_BUFFERED IOCTLs with complex parsing (R=2, I=2-3, C=3 → 12-18)
5. Kernel callbacks processing user-influenced data (R=2, I=2, C=2 → 8)
6. COM interfaces in privileged services (R=2, I=2, C=2 → 8)
7. Network listeners (R=3, I=3, C=2 → 18 — highest if network reachable)
8. Window message handlers (R=2, I=1-2, C=1 → 2-4)
