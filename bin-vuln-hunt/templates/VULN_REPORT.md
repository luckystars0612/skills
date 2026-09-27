# Vulnerability report — <BINARY_NAME> — <SHORT_TITLE>

Fill during Phase 3–5. Every claim is VERIFIED (seen in the binary / observed dynamically) or
INFERRED (predicted, needs confirmation). This template is suitable for vendor submission
after the researcher reviews and approves it.

---

## Summary

| Field | Value |
|-------|-------|
| Binary | `<filename>` (`<type: .sys / .exe / .dll>`) |
| SHA256 | `<hash>` |
| Vendor | `<vendor name>` |
| Signer | `<digital signature subject>` |
| Version | `<file version from resources>` |
| Tested OS | `<e.g. Win11 24H2 Build 26100, HVCI on/off>` |
| Bug class | `<e.g. Stack Buffer Overflow>` |
| CWE | `<CWE-NNN: Title>` |
| CVSS v3.1 | `<score>` (`<vector string>`) |
| Impact | `<e.g. Local DoS (BSOD), LPE to SYSTEM, KASLR bypass>` |
| Requires | `<e.g. local user, admin, network access>` |
| Authorization | `<own VM / research / in-scope engagement>` |

## Affected component

`<Describe which component / subsystem of the product is affected. For drivers: the IOCTL
handler. For services: the RPC method / named pipe handler. For DLLs: the exported
function.>`

## Root cause

`<One paragraph explaining WHY the code is wrong. Not just "there's a buffer overflow" but
"the IOCTL handler at 0x140001234 reads InputBufferLength from the IO_STACK_LOCATION but
does not validate that it is <= the destination buffer size (256 bytes) before calling
RtlCopyMemory. An attacker can send an IOCTL with InputBufferLength > 256 to overflow the
stack buffer, corrupting the return address.">`

Evidence level: **VERIFIED** / **INFERRED**

## Vulnerable code path

```
Entry point:    <DriverEntry / main / DllGetClassObject> @ 0x<addr>
  → Init:       <init function> @ 0x<addr>
  → Dispatch:   <MajorFunction[14] / RPC method N / pipe handler> @ 0x<addr>
  → Handler:    <IOCTL 0xNNNN handler / method handler> @ 0x<addr>
  → Sink:       <dangerous operation> @ 0x<addr>
```

### Decompiled sink (relevant snippet)

```c
// From <function_name> @ 0x<addr>
// <paste the relevant decompiled code, annotated with comments>
<decompiled code>
```

### Data flow

```
User input → <boundary> → <transform 1> → <transform 2> → <sink>
```

`<Describe how user-controlled data flows from the input boundary to the dangerous
operation, including any transformations, checks, or copies along the way. Note which
checks are present and which are missing.>`

## Reproduction

### Prerequisites
- `<OS version and configuration>`
- `<Driver loaded via sc create / product installed / etc.>`
- `<Tools: WinDbg attached, page heap enabled, etc.>`

### Steps
1. `<Step 1: e.g. Load the driver: sc create vuln type= kernel binPath= C:\path\vuln.sys>`
2. `<Step 2: e.g. Start the driver: sc start vuln>`
3. `<Step 3: e.g. Send malformed IOCTL:>`
   ```
   <code snippet, command, or PoC description>
   ```
4. `<Step 4: e.g. Observe BSOD with bugcheck 0x...>`

### Expected result
`<What happens: BSOD, crash, info leak output, etc.>`

### Actual result
`<What was observed: BSOD code, crash address, leaked data, etc.>`

Evidence level: **VERIFIED (dynamic)** / **VERIFIED (static only)** / **INFERRED**

## Impact assessment

### CVSS v3.1 breakdown
| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector (AV) | `<Local/Adjacent/Network>` | `<why>` |
| Attack Complexity (AC) | `<Low/High>` | `<why>` |
| Privileges Required (PR) | `<None/Low/High>` | `<why>` |
| User Interaction (UI) | `<None/Required>` | `<why>` |
| Scope (S) | `<Unchanged/Changed>` | `<why>` |
| Confidentiality (C) | `<None/Low/High>` | `<why>` |
| Integrity (I) | `<None/Low/High>` | `<why>` |
| Availability (A) | `<None/Low/High>` | `<why>` |

### Mitigations in place
- `/GS (stack cookies)`: `<present/absent>` — `<effect on exploitability>`
- `ASLR`: `<present/absent>`
- `DEP/NX`: `<present/absent>`
- `CFG`: `<present/absent>`
- `HVCI/VBS (kernel)`: `<on/off>` — `<effect>`
- `SDDL / access control`: `<restrictive/permissive/none>`

### Exploitability beyond DoS
`<Can the bug be escalated beyond a crash? E.g., "With a controlled heap layout, the
overflow could overwrite an adjacent object's function pointer, leading to code execution.
This would require [conditions]. This is INFERRED — no working exploit has been built.">`

## Suggested fix

`<What the vendor should change. Be specific:>`
- `<e.g. "Add a size check: if (InputBufferLength < sizeof(MY_STRUCT)) return STATUS_BUFFER_TOO_SMALL;">`
- `<e.g. "Add ProbeForRead(Type3InputBuffer, InputBufferLength, 1) before dereferencing.">`
- `<e.g. "Acquire FastMutex before accessing the tracking list in the IOCTL handler.">`
- `<e.g. "Use RtlStringCbCopyW instead of wcscpy for bounded string copy.">`

## Variant analysis

`<Were other IOCTLs / handlers / versions checked for the same pattern?>`
- Other IOCTLs in the same driver: `<checked/not checked — findings>`
- Other versions of the binary: `<checked/not checked — findings>`
- Other binaries from the same vendor: `<checked/not checked — findings>`

## Timeline

| Date | Event |
|------|-------|
| `<YYYY-MM-DD>` | Vulnerability discovered |
| `<YYYY-MM-DD>` | Report submitted to vendor via `<channel>` |
| `<YYYY-MM-DD>` | Vendor acknowledged receipt |
| `<YYYY-MM-DD>` | Vendor confirmed / disputed |
| `<YYYY-MM-DD>` | Fix released in version `<X.Y.Z>` |
| `<YYYY-MM-DD>` | CVE assigned: `<CVE-YYYY-NNNNN>` |
| `<YYYY-MM-DD>` | Public disclosure |

## Status

**OPEN** / **REPORTED** / **CONFIRMED** / **FIXED** / **DISPUTED**
