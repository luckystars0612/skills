# Bug classes — the vulnerability pattern catalog

Each entry: the **bug class**, the **import/code signature** to recognize it quickly, the
**decompiler pattern** to confirm it, the **idalib queries** to find it, the **consequence**,
and the **CWE**. Screen with imports first (seconds), then shallow decompile (minutes), then
deep data-flow trace (the confirmation step). Kill hypotheses early.

Short names map to `mcp__plugin_ida-pro-mcp_idalib__<name>`.

---

## 1. Memory corruption

### 1a. Stack buffer overflow (CWE-120)

**Signature.** A function copies user-controlled data into a stack-allocated buffer using a
length derived from the input, without capping it to the buffer size.

**Import signature.** `memcpy`/`RtlCopyMemory`/`memmove`/`RtlMoveMemory`/`strcpy`/
`wcscpy`/`sprintf`/`swprintf` — these don't bounds-check. `strncpy`/`wcsncpy`/`_snprintf`
are safer but still vulnerable if the size argument is user-controlled.

**Decompiler pattern.** Look for:
```c
char buf[256];                           // stack local, fixed size
memcpy(buf, user_input, user_length);    // user_length not checked against 256
```
Or the subtler variant:
```c
char buf[MAX_PATH];                      // 260 bytes
strcpy(buf, user_string);               // user_string can be > 260
```

In drivers, the input comes from the IRP system/type3 buffer. In userland, from RPC args,
pipe reads, file reads, network recv.

**idalib.** `imports_query` for `memcpy`/`RtlCopyMemory`; `xrefs_to` each; `decompile` the
caller; check if the third argument (size) traces back to user input without a cap. For
`strcpy`/`sprintf`, every call is suspicious — check if the source is user-controlled.
`trace_data_flow` from the IOCTL/RPC buffer argument to the `memcpy` size/source.

**Consequence.** Stack overflow → control of return address → code execution (userland) or
BSOD/code execution (kernel, if no stack cookies or cookies bypassed).

**Mitigations to check.** `/GS` (stack cookies) — present in most modern builds but can be
bypassed via SEH overwrite or if the cookie check is reachable only after the corruption is
useful. `__security_check_cookie` in imports → GS is on. Its *absence* is a high-value tell.

---

### 1b. Heap / pool buffer overflow (CWE-122)

**Signature.** Allocation size doesn't match copy size, or user-controlled length exceeds
the allocated size.

**Import signature (kernel).** `ExAllocatePoolWithTag`/`ExAllocatePool2` (allocation) +
`memcpy`/`RtlCopyMemory` (copy). The bug: alloc uses one size, copy uses another (or the
user-supplied size).

**Import signature (userland).** `HeapAlloc`/`malloc`/`VirtualAlloc`/`LocalAlloc` (alloc) +
`memcpy`/`ReadFile`/`recv` (fill).

**Decompiler pattern.** The classic:
```c
buf = ExAllocatePoolWithTag(NonPagedPool, header.size, 'Tag1');
// ... no check that header.data_length <= header.size ...
memcpy(buf, user_data, header.data_length);   // overflow if data_length > size
```
Or the variable-length struct:
```c
buf = ExAllocatePoolWithTag(NonPagedPool, sizeof(HEADER) + count * elem_size, 'Tag1');
// if count * elem_size wraps (see §1c), buf is too small
for (i = 0; i < count; i++)
    buf->entries[i] = user_entries[i];  // OOB write
```

**idalib.** `xrefs_to ExAllocatePoolWithTag`; for each call site, `decompile` and trace the
size argument — is it derived from user input? Then find the subsequent copy/fill and compare
sizes. `trace_data_flow` from the allocation return value to every write into the buffer.

**Consequence.** Pool/heap overflow → adjacent object corruption → arbitrary R/W or code
execution (pool spray to control the adjacent object). In kernel: pool corruption → BSOD or
controlled kernel write.

---

### 1c. Integer overflow / underflow (CWE-190 / CWE-191)

**Signature.** Arithmetic on user-supplied values before they're used as sizes for allocation
or bounds checks. The result wraps around the integer range, producing a small value from
large inputs.

**Decompiler pattern.** The multiplication overflow:
```c
size_t total = count * element_size;     // if count = 0x40000001, element_size = 4:
                                         // total = 0x100000004 → truncated to 4 on 32-bit
buf = malloc(total);                     // tiny allocation
for (i = 0; i < count; i++)             // writes 0x40000001 elements → massive overflow
    buf[i] = ...;
```
The addition overflow:
```c
alloc_size = user_size + HEADER_LEN;     // user_size = 0xFFFFFFFC, HEADER_LEN = 8
                                         // alloc_size = 4 (wraps on 32-bit)
buf = ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'Tag1');
memcpy(buf + HEADER_LEN, user_data, user_size);  // writes 0xFFFFFFFC bytes
```
The signed/unsigned confusion:
```c
int length = *(int*)user_buf;            // user sends -1 (0xFFFFFFFF)
if (length > MAX_LENGTH) return ERROR;   // -1 < MAX_LENGTH → passes the signed check
memcpy(dst, src, (size_t)length);        // cast to unsigned → copies 4 GB
```

**idalib.** Look for arithmetic on values derived from user input *before* an allocation or
copy. `decompile` the handler; search for `*` and `+` on variables that trace back to the
IRP buffer. Check the width: 32-bit arithmetic on a 64-bit platform is especially prone
(high 32 bits silently dropped in many patterns). `trace_data_flow` from user-input fields
to allocation size arguments.

**Consequence.** Small allocation + large copy → heap/pool overflow (see §1b). Or a bounds
check bypassed → out-of-bounds access.

**Key check.** Does the code use `safe_add` / `RtlSizeTMult` / `RtlSizeTAdd` / `ULongMult`?
These are Microsoft's safe-integer APIs — their presence means the developer was aware of
the risk (but may not have used them everywhere).

---

### 1d. Off-by-one (CWE-193)

**Signature.** A loop or size check is off by one unit: `<=` instead of `<`, or the
null terminator is not accounted for in a string copy.

**Decompiler pattern.**
```c
for (i = 0; i <= count; i++)    // processes count+1 elements
    buf[i] = src[i];            // last write is 1 past the end

char dest[16];
strncpy(dest, src, 16);         // if src >= 16 chars, dest is NOT null-terminated
dest[16] = '\0';                // off-by-one write past the buffer (index 16, size 16)
```

**idalib.** `decompile` loop bounds and string operations near user-controlled data. Check
`<=` vs `<` in `for`/`while` conditions. For `strncpy`, check if the code null-terminates
manually and whether the index is correct.

**Consequence.** Usually a single-byte overflow — in kernel pool, can corrupt the next pool
header → BSOD or controlled allocation. In heap, can corrupt metadata → heap exploitation.

---

### 1e. Use-after-free (CWE-416)

**Signature.** A memory block is freed in one code path while still referenced (via a
pointer, a list link, or a cached reference) from another. The most exploitable variant is
the **race condition UAF**: two IRP handlers access the same data structure concurrently
without synchronization.

**Import signature (kernel).** `ExAllocatePoolWithTag` + `ExFreePoolWithTag` + list ops
(`InsertTailList`/`RemoveEntryList`/manual FLINK/BLINK). The tell: inconsistent or absent
locking — `ExAcquireFastMutex`/`KeAcquireSpinLock` not present, or present on some paths
but not others.

**Import signature (userland).** `HeapAlloc`/`HeapFree` + object caching or a linked list
of client state. The tell: a reference is used after the object that holds it has been freed
on another thread.

**Decompiler pattern (driver race UAF).** Three IRP handlers access the same linked list:
```
IRP_MJ_CREATE → allocate node, append to global list (NO LOCK)
IRP_MJ_CLOSE  → walk list, find by PID, unlink, free    (NO LOCK)
IOCTL 0x...   → walk list, read fields, follow pointers (NO LOCK)
```
If CLOSE frees a node while the IOCTL handler is iterating the list, the IOCTL follows a
dangling `Next` pointer → reads freed memory → **UAF read**. If the CLOSE handler's unlink
writes a user-controlled value to a surviving node → **UAF write**.

**idalib.** `imports_query` for `ExAllocatePoolWithTag`; `xrefs_to` to find every allocation
site; `decompile` each to find the struct layout and the list it's added to. Then `xrefs_to
ExFreePoolWithTag` to find every free site. Cross-reference: is the same object freed in one
handler and accessed in another? Check for `ExAcquireFastMutex` / `KeAcquireSpinLock` — are
ALL access paths covered? A mutex on the IOCTL handler but not on CREATE/CLOSE is a gap.

**Consequence.** UAF → attacker reclaims the freed slot with controlled data (pool spray /
named pipe spray) → dangling pointer follows attacker-controlled data → arbitrary R/W or
code execution. In kernel: pool spray with `NpfsDataQueueEntry` or similar to reclaim the
exact slot. See byovd-killer `references/KILL_PRIMITIVES.md` §3h for the detailed
exploitation chain.

---

### 1f. Double free (CWE-415)

**Signature.** The same allocation is freed twice — usually in error handling. The first free
succeeds, the allocator marks the slot as available, and the second free corrupts the
freelist.

**Decompiler pattern.**
```c
buf = ExAllocatePoolWithTag(NonPagedPool, size, 'Tag1');
status = ProcessBuffer(buf);
if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(buf, 'Tag1');   // free on error
    return status;
}
// ... later, in the common cleanup path ...
ExFreePoolWithTag(buf, 'Tag1');       // freed again if error path was taken
```
The fix is usually setting `buf = NULL` after the first free, or restructuring the cleanup.

**idalib.** `xrefs_to ExFreePoolWithTag`; for each tag value, check if the same pointer is
freed more than once in the function's control flow (especially error paths). `decompile`
and trace the variable through all branches.

**Consequence.** Corrupted pool freelist → next allocation from that slot returns
overlapping memory → type confusion or controlled overwrite.

---

### 1g. NULL pointer dereference (CWE-476)

**Signature.** A function returns NULL on failure (memory allocation, object lookup, handle
resolution) and the caller doesn't check the return value before using it.

**Import signature (kernel).** `MmGetSystemAddressForMdlSafe` (returns NULL if MDL mapping
fails), `IoGetDeviceObjectPointer` (can fail), `MmMapIoSpace` (can fail),
`ExAllocatePoolWithTag` (returns NULL if no memory). Any call whose return value isn't
checked before dereference.

**Decompiler pattern.**
```c
va = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
// NO check for va == NULL
*(DWORD*)va = user_value;    // if va is NULL → BSOD at address 0x00000000
```

**idalib.** `xrefs_to MmGetSystemAddressForMdlSafe`; `decompile` each caller; check if the
return value is tested against NULL/zero before use. Same for other failable functions.

**Consequence.** On modern Windows (8+), the NULL page is unmapped in kernel mode → BSOD
(DoS), NOT code execution. On Windows 7 and earlier, or with specific configurations, the
NULL page could be mapped → code execution. Classify as DoS unless targeting legacy systems.

---

## 2. Information disclosure

### 2a. Uninitialized pool/heap leak (CWE-908)

**Signature.** An IOCTL handler allocates an output buffer, partially fills it, then copies
the entire allocation back to user mode — the uninitialized bytes are kernel pool residue
that may contain pointers, pool headers, or data from previously freed objects.

**Decompiler pattern (generic output-length bug).**
```c
// Shared dispatch epilogue:
Irp->IoStatus.Information = OutputBufferLength;   // copies THIS many bytes back
Irp->IoStatus.Status = STATUS_SUCCESS;
// ... but the IOCTL only wrote N bytes, and OutputBufferLength > N
// → bytes [N .. OutputBufferLength) are uninitialized pool content
```
The tell: `IoStatus.Information` is set to `OutputBufferLength` in a **common exit path**
that ALL IOCTLs reach, not per-IOCTL. If it's per-IOCTL with the correct byte count, there's
no leak.

**Decompiler pattern (struct padding leak).**
```c
MY_OUTPUT out;                  // stack struct, NOT memset to zero
out.field1 = value1;
out.field2 = value2;
// out has padding bytes between fields (alignment) → uninitialized
memcpy(SystemBuffer, &out, sizeof(out));  // leaks padding
```

**idalib.** `decompile` the dispatch handler's epilogue — look for
`Irp->IoStatus.Information` assignment. If it's `= OutputBufferLength` (not `= actual_written`),
flag every IOCTL that writes less than `OutputBufferLength`. For struct leaks, check if
the output struct is zeroed (`memset`/`RtlZeroMemory`) before filling.

**Consequence.** Kernel pointer leak → KASLR bypass. Pool metadata leak → heap layout
information. Prior object data leak → sensitive data disclosure. A KASLR bypass is a
**supporting primitive** — not a standalone vulnerability in most severity frameworks, but
critical as a building block for exploitation chains.

---

### 2b. Kernel address disclosure via error paths (CWE-209)

**Signature.** Error messages, status codes, or debug output that include kernel addresses.
Less common in drivers (no printf to user), more common in userland services that log
errors.

**Decompiler pattern (driver).** A failing IOCTL that copies an error struct to user mode,
where the struct contains a kernel pointer (e.g., the failed allocation address or the
object that caused the error).

**idalib.** `decompile` error-path handlers; check if any kernel-mode pointers are written
to the output buffer or `IoStatus.Information`.

---

## 3. Logic / validation bugs

### 3a. Missing or insufficient size validation (CWE-20)

**Signature.** An IOCTL handler reads fields from the input buffer without checking that the
buffer is large enough to contain those fields. Or the check exists but is wrong (checks the
wrong variable, uses `>` instead of `>=`, or checks the output size instead of the input
size).

**Decompiler pattern.**
```c
// No size check at all:
pid = *(DWORD*)(SystemBuffer + 4);    // reads at offset +4, but what if InputBufferLength < 8?

// Wrong check:
if (OutputBufferLength >= 0x18) {      // checks OUTPUT, not INPUT
    pid = *(DWORD*)(SystemBuffer);     // reads INPUT buffer — unvalidated
}

// Insufficient check:
if (InputBufferLength >= 4) {          // checks >= 4
    ptr = *(QWORD*)(SystemBuffer);     // reads 8 bytes — needs >= 8
}
```

**idalib.** `decompile` every IOCTL handler; for each buffer access (`SystemBuffer`,
`Type3InputBuffer`), trace backwards to find the size check. Note the exact comparison and
the exact offset/width accessed. Mismatch → vulnerability.

**Consequence.** OOB read from the IRP buffer itself (pool overflow read) → info leak or
crash. In METHOD_NEITHER with no `ProbeForRead` → arbitrary kernel read.

---

### 3b. Missing probe on METHOD_NEITHER (CWE-822)

**Signature.** An IOCTL uses METHOD_NEITHER (low 2 bits of IOCTL code = 3), meaning the I/O
manager does NOT copy or validate the buffer — the driver gets a raw user-mode pointer
(`Type3InputBuffer`). If the driver doesn't call `ProbeForRead`/`ProbeForWrite` before
dereferencing, the user can supply a **kernel-mode address** instead.

**Decompiler pattern.**
```c
// IOCTL code & 3 == 3 → METHOD_NEITHER
user_buf = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
// NO ProbeForRead(user_buf, size, alignment)
value = *(DWORD*)user_buf;    // if user_buf = 0xFFFFF80012345678 → reads kernel memory
```
The reverse — writing to `Irp->UserBuffer` without `ProbeForWrite` — gives arbitrary
kernel write.

**idalib.** Decode each IOCTL code's method (low 2 bits). For METHOD_NEITHER IOCTLs,
`decompile` the handler and search for `ProbeForRead`/`ProbeForWrite`. Their absence before
any dereference of `Type3InputBuffer` or `Irp->UserBuffer` is the bug.

**Consequence.** Arbitrary kernel read or write, depending on direction. Direct LPE.

---

### 3c. TOCTOU — double fetch from user memory (CWE-367)

**Signature.** A METHOD_NEITHER handler reads a value from user memory, checks it, then reads
the **same user address again** to use it. Between the check and the use, a second thread
can change the value.

**Decompiler pattern.**
```c
size = *(DWORD*)user_buf;               // first read (check)
if (size > MAX_SIZE) return ERROR;
// attacker thread changes *user_buf to 0xFFFFFFFF here
actual_size = *(DWORD*)user_buf;         // second read (use) — now 0xFFFFFFFF
memcpy(dst, src, actual_size);           // overflow
```
For METHOD_BUFFERED, this is not exploitable (the I/O manager copies to a kernel buffer, so
user-mode changes don't affect it). Only METHOD_NEITHER and METHOD_IN/OUT_DIRECT (on the
MDL-mapped buffer) are vulnerable.

**idalib.** For METHOD_NEITHER IOCTLs, `decompile` and look for two memory reads from the
same offset of `Type3InputBuffer`. `trace_data_flow` from the first read to the check, and
from the second read to the use. If they're different reads from the same address, it's a
TOCTOU.

**Consequence.** Bypasses the size/value check → enables the underlying bug (overflow, OOB
access, etc.).

---

### 3d. Missing requestor-mode check (CWE-284)

**Signature.** A driver performs a privileged operation (memory mapping, process handle
creation, registry access) without checking whether the caller is a kernel-mode or
user-mode thread. `ExGetPreviousMode()` returns `UserMode` (1) for a user-mode caller —
the driver should restrict operations for user-mode callers.

**Decompiler pattern.**
```c
// Dangerous: no previous-mode check
ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &oa, &cid);
// The Zw* routines set PreviousMode=KernelMode internally,
// bypassing security checks — so ANY caller gets PROCESS_ALL_ACCESS

// Safe:
if (ExGetPreviousMode() == UserMode) {
    // restrict access or return ACCESS_DENIED
}
```

**idalib.** `imports_query` for `ExGetPreviousMode`; `xrefs_to` to see where it's used.
Then check every `Zw*` call in the driver — if a `Zw*` call is reachable from a user-mode
IOCTL without a `ExGetPreviousMode` check, the driver gives user-mode callers kernel-mode
access to that API.

**Consequence.** Depends on the `Zw*` call: `ZwOpenProcess` → arbitrary process handle →
code execution. `ZwOpenKey` → arbitrary registry access. `ZwMapViewOfSection` → arbitrary
memory mapping. Generally: full privilege escalation.

---

### 3e. Path traversal / argument injection (CWE-22 / CWE-88)

**Signature.** A binary constructs a file path, registry key, or command line by
concatenating user-supplied strings without sanitization. The user supplies `..\..\` to
escape the intended directory, or injects shell metacharacters into a command line.

**Import signature.** `CreateFile`/`ZwCreateFile` + string concatenation (`wcscat`/`swprintf`
/`StringCbPrintf`) where part of the string is user-controlled. For command injection:
`CreateProcess`/`ShellExecute`/`system`/`_popen` with user-controlled arguments.

**idalib.** `xrefs_to CreateFileW`; `decompile` callers; trace the filename argument — is
any part user-controlled? Does the code canonicalize or reject `..`/`..\`? For command
injection: `xrefs_to CreateProcessW`/`ShellExecuteW`; trace `lpCommandLine`.

**Consequence.** Path traversal → read/write/delete arbitrary files. In a SYSTEM service →
arbitrary file write as SYSTEM → LPE. Command injection → code execution in the service
context.

---

## 4. Concurrency bugs

### 4a. Race condition — shared state without synchronization (CWE-362)

**Signature.** A global variable, device extension field, or linked list is accessed from
multiple IRP dispatch handlers (which can run concurrently on different processors) without
any synchronization primitive.

**Import signature.** The *absence* of `ExAcquireFastMutex`/`ExReleaseFastMutex`,
`KeAcquireSpinLock`/`KeReleaseSpinLock`, `ExAcquireResourceExclusiveLite`,
`KeWaitForSingleObject` (on a mutex/event) in a driver that has multi-handler shared state.

**idalib.** `imports_query` for locking primitives. If the driver has shared state (global
pointer, device extension list) but NO locking imports, every access is a candidate.
`decompile` each handler that touches the shared state; confirm the access is unprotected.

**Consequence.** Depends on what's shared:
- Linked list → UAF (see §1e)
- Reference counter → double-free or use-after-free
- State flag → logic bypass (e.g., skip auth check because another thread set the flag)
- Buffer pointer → dangling pointer after reallocation

---

### 4b. Race condition — TOCTOU on file/registry (CWE-367)

**Signature.** A privileged process checks a file's properties (existence, permissions,
content) and then operates on it, with a window between check and use. The attacker replaces
the file/directory with a symlink/junction in that window.

**Import signature (userland).** `GetFileAttributes`/`PathFileExists` followed by
`CreateFile`/`MoveFile`/`DeleteFile`/`CopyFile` on the same path — with a gap between them.
`FindFirstFile` + `DeleteFile` loops (the `FindNextFile` → `DeleteFile` window is raceable).

**idalib.** `xrefs_to GetFileAttributesW`; `decompile` callers; find the subsequent
`CreateFileW`/`MoveFileW`/`DeleteFileW` on the same path variable. The gap between the
attribute check and the file operation is the race window. For the LPE-focused analysis,
hand off to `win-lpe-hunt`.

**Consequence.** Arbitrary file write/delete/read as the privileged process. In a SYSTEM
service → LPE.

---

## 5. Denial of service (kernel-specific)

### 5a. Unvalidated IOCTL causing BSOD (CWE-20)

**Signature.** Any IOCTL that can be triggered from user mode and causes a kernel crash
(NULL deref, pool corruption, invalid memory access) is a DoS vulnerability — even if it
doesn't lead to code execution.

**Priority.** Lower severity than code execution (typically CVSS 5.5-6.5 for local DoS) but
still a valid CVE, especially for drivers that load automatically (class drivers, filter
drivers, device-specific). A driver that a local user can crash at will = a local DoS
against the machine.

---

## Quick reference: import → bug class mapping

| Import | Bug class to investigate |
|---|---|
| `memcpy`/`RtlCopyMemory` | Buffer overflow (§1a, §1b) |
| `strcpy`/`wcscpy`/`sprintf` | Stack overflow (§1a) |
| `ExAllocatePoolWithTag` + `ExFreePoolWithTag` | UAF (§1e), double free (§1f) |
| `MmGetSystemAddressForMdlSafe` | NULL deref (§1g) |
| `ProbeForRead`/`ProbeForWrite` (absent on NEITHER) | Missing probe (§3b) |
| `ExGetPreviousMode` (absent near Zw* calls) | Missing mode check (§3d) |
| `IoCreateDevice` without `Secure` | No SDDL → any user can open (§3a) |
| `CreateProcessW`/`ShellExecuteW` | Command injection (§3e) |
| `GetFileAttributesW` before `CreateFileW` | TOCTOU (§4b) |
| No locking imports + global list | Race condition (§4a) |
| `IoStatus.Information = OutputBufferLength` | Info leak (§2a) |
