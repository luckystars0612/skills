# Reverse Engineering

Deep reverse engineering techniques for firmware binaries. Covers disassembly, decompilation, dynamic analysis, symbolic execution, emulation, anti-analysis bypass, and cross-architecture RE.

---

## Static RE with radare2

### Project Setup and Analysis

```bash
# Open with full analysis (auto-detect arch)
r2 -A <binary>

# Open with specific architecture
r2 -a arm -b 32 <binary>        # ARM 32-bit
r2 -a arm -b 16 <binary>        # ARM Thumb
r2 -a arm -b 64 <binary>        # AArch64
r2 -a mips -b 32 <binary>       # MIPS 32-bit
r2 -a x86 -b 32 <binary>        # x86
r2 -a x86 -b 64 <binary>        # x86_64
r2 -a riscv -b 32 <binary>      # RISC-V

# Open raw firmware at load address
r2 -a arm -b 32 -m 0x08000000 <firmware.bin>

# Save/load analysis project
r2 -A <binary>
# In r2: Ps <project_name>     # Save project
# r2 -p <project_name>          # Load project
```

### Essential r2 Commands

```
# Navigation
s <addr>          # Seek to address
s main            # Seek to main function
sf <func_name>    # Seek to function

# Analysis
aaa               # Full analysis (functions, xrefs, strings)
afl               # List functions
afn <name> <addr> # Rename function
axt <addr>        # Cross-references TO address
axf <addr>        # Cross-references FROM address

# Disassembly
pd 20             # Disassemble 20 instructions
pdf               # Disassemble current function
pdf @ main        # Disassemble main
pdr               # Recursive disassembly

# Decompilation (r2ghidra plugin)
pdg               # Decompile current function
pdg @ main        # Decompile main

# Strings
iz                # Strings in data sections
izz               # All strings in binary
iz~password       # Filter strings

# Search
/ password        # Search for string
/x 41414141       # Search hex pattern
/a jmp esp        # Search for assembly instruction
/R pop rdi        # Search ROP gadgets

# Data
px 64             # Hex dump 64 bytes
ps                # Print string at current address
pf x              # Print as 32-bit hex value
pf xx             # Print two 32-bit values

# Visual mode
V                 # Visual mode
VV                # Graph mode (function call graph)
p/P               # Cycle views in visual mode
```

### r2 Scripting (r2pipe)

```python
#!/usr/bin/env python3
"""r2pipe script for automated binary analysis."""
import r2pipe
import json

r2 = r2pipe.open('<binary>')
r2.cmd('aaa')

# Get all functions
functions = r2.cmdj('aflj')
print(f"Total functions: {len(functions)}")

# Find dangerous function calls
dangerous = ['gets', 'strcpy', 'sprintf', 'system', 'popen', 'execve']
for func_name in dangerous:
    xrefs = r2.cmdj(f'axtj @ sym.imp.{func_name}')
    if xrefs:
        print(f"\n{func_name} called from:")
        for xref in xrefs:
            print(f"  0x{xref['from']:08x} in {xref.get('fcn_name', 'unknown')}")

# Analyze strings for credentials
strings = r2.cmdj('izzj')
for s in strings:
    content = s.get('string', '')
    if any(kw in content.lower() for kw in ['password', 'secret', 'key', 'token']):
        print(f"  0x{s['vaddr']:08x}: {content[:80]}")

r2.quit()
```

---

## Static RE with Ghidra (Headless)

If Ghidra is installed (`/opt/ghidra` or similar):

```bash
# Headless analysis — create project and analyze
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects MyProject \
  -import <binary> \
  -postScript ExportDecompilation.java /tmp/decompiled_output \
  -deleteProject

# With specific processor
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects MyProject \
  -import <binary> \
  -processor ARM:LE:32:v7 \
  -postScript ExportFunctions.java /tmp/functions_output

# List available processors
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects MyProject -help
```

**Note:** Ghidra may not be installed. Install from: https://ghidra-sre.org/

---

## Dynamic Analysis with GDB

### Remote Debugging Setup

```bash
# For cross-architecture debugging
gdb-multiarch <binary>

# Connect to remote target (QEMU, hardware debugger, OpenOCD)
# In GDB:
# target remote <host>:<port>
# target remote localhost:1234

# QEMU user-mode emulation with GDB stub
qemu-arm -g 1234 <arm_binary> &
gdb-multiarch -ex "target remote localhost:1234" -ex "file <arm_binary>"

# QEMU system emulation with GDB
qemu-system-arm -M versatilepb -kernel <kernel> -append "root=/dev/sda" \
  -drive file=<rootfs>,format=raw -s -S &
gdb-multiarch -ex "target remote localhost:1234"
```

### GDB Essential Commands

```
# Breakpoints
break *0x08001234          # Break at address
break main                 # Break at function
break *0x08001234 if $r0==0  # Conditional breakpoint
watch *0x20000100          # Hardware watchpoint (data write)
rwatch *0x20000100         # Read watchpoint
awatch *0x20000100         # Access watchpoint (read or write)
info breakpoints           # List breakpoints

# Execution
run                        # Start execution
continue                   # Continue after break
stepi                      # Step one instruction
nexti                      # Step over call
finish                     # Run until function return
until *0x08001300          # Run until address

# Registers
info registers             # All registers
info registers pc sp lr    # Specific registers (ARM)
set $pc = 0x08001234       # Modify register

# Memory
x/20wx $sp                 # 20 words at stack pointer
x/s 0x08002000             # String at address
x/10i $pc                  # 10 instructions at PC
dump memory /tmp/mem.bin 0x20000000 0x20010000  # Dump memory region

# Stack
bt                         # Backtrace
frame 2                    # Switch to frame 2
info frame                 # Frame details

# Search
find 0x20000000, 0x20010000, "password"  # Search memory for string
find 0x20000000, +0x10000, 0x41414141    # Search for pattern
```

### GDB Python Scripting

```python
# gdb_script.py — save and source in GDB with: source gdb_script.py
import gdb

class DumpMemoryRegions(gdb.Command):
    """Dump all mapped memory regions to files."""
    def __init__(self):
        super().__init__("dump-regions", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        mappings = gdb.execute("info proc mappings", to_string=True)
        for line in mappings.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].startswith('0x'):
                start = int(parts[0], 16)
                end = int(parts[1], 16)
                size = end - start
                fname = f"/tmp/mem_{start:08x}_{end:08x}.bin"
                try:
                    gdb.execute(f"dump memory {fname} {start} {end}")
                    print(f"Dumped {fname} ({size} bytes)")
                except:
                    pass

DumpMemoryRegions()

class FindCredentials(gdb.Command):
    """Search memory for credential patterns."""
    def __init__(self):
        super().__init__("find-creds", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        patterns = [b"password", b"secret", b"token", b"api_key", b"admin"]
        for pattern in patterns:
            try:
                result = gdb.execute(
                    f'find 0x00000000, 0x7fffffff, "{pattern.decode()}"',
                    to_string=True
                )
                if "found" in result:
                    print(f"\n=== {pattern.decode()} ===")
                    print(result)
            except:
                pass

FindCredentials()
```

### strace / ltrace

```bash
# Trace system calls
strace -f -o /tmp/strace.log <binary>

# Trace specific syscalls
strace -e trace=open,read,write,connect,socket <binary>

# Trace library calls
ltrace -o /tmp/ltrace.log <binary>

# Cross-architecture (via QEMU user mode)
qemu-arm -strace <arm_binary> 2>/tmp/strace.log
```

---

## Frida Dynamic Instrumentation

### Basic Frida Usage

```bash
# Attach to running process
frida -p <pid> -l script.js

# Spawn and attach
frida -f <binary> -l script.js --no-pause

# Remote device (e.g., connected robot)
frida -H <ip>:<port> -f <binary> -l script.js
```

### Frida Scripts for Firmware Analysis

```javascript
// hook_dangerous_functions.js — Hook dangerous C functions
const dangerous_funcs = ['system', 'popen', 'execve', 'strcpy', 'sprintf', 'gets'];

dangerous_funcs.forEach(func => {
    try {
        Interceptor.attach(Module.findExportByName(null, func), {
            onEnter: function(args) {
                console.log(`[${func}] called from ${this.returnAddress}`);
                if (func === 'system' || func === 'popen') {
                    console.log(`  cmd: ${args[0].readCString()}`);
                } else if (func === 'strcpy' || func === 'sprintf') {
                    console.log(`  dst: ${args[0]}`);
                    if (func === 'sprintf') {
                        console.log(`  fmt: ${args[1].readCString()}`);
                    }
                }
                console.log(`  backtrace:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    ')}`);
            }
        });
    } catch(e) {
        // Function not found
    }
});
```

```javascript
// hook_auth.js — Intercept authentication
// Hook common auth patterns
['authenticate', 'verify_password', 'check_auth', 'login', 'validate_token'].forEach(name => {
    const matches = Module.enumerateExports('').filter(e => e.name.toLowerCase().includes(name));
    matches.forEach(match => {
        Interceptor.attach(match.address, {
            onEnter: function(args) {
                console.log(`[AUTH] ${match.name} called`);
                // Try to read string arguments
                for (let i = 0; i < 4; i++) {
                    try {
                        const str = args[i].readCString();
                        if (str && str.length > 0 && str.length < 256) {
                            console.log(`  arg${i}: ${str}`);
                        }
                    } catch(e) {}
                }
            },
            onLeave: function(retval) {
                console.log(`  return: ${retval}`);
                // Optionally bypass: retval.replace(ptr(1));
            }
        });
    });
});
```

```javascript
// memory_scan.js — Scan process memory for patterns
Process.enumerateRanges('r--').forEach(range => {
    // Search for password strings
    Memory.scan(range.base, range.size, "70 61 73 73 77 6f 72 64", {  // "password"
        onMatch: function(address, size) {
            console.log(`Found 'password' at ${address}: ${address.readCString()}`);
        },
        onComplete: function() {}
    });
});
```

---

## angr Symbolic Execution

### Basic angr Analysis

```python
#!/usr/bin/env python3
"""angr analysis for firmware binary."""
import angr
import claripy

# Load binary
proj = angr.Project('<binary>', auto_load_libs=False)

# CFG recovery
cfg = proj.analyses.CFGFast()
print(f"Functions found: {len(cfg.functions)}")
print(f"Basic blocks: {len(cfg.graph.nodes())}")

# Find function by name
for addr, func in cfg.functions.items():
    if 'auth' in func.name.lower() or 'login' in func.name.lower():
        print(f"Auth function: {func.name} @ 0x{addr:08x}")
```

### Automated Input Generation

```python
#!/usr/bin/env python3
"""Find input that reaches target address (e.g., auth bypass)."""
import angr
import claripy

proj = angr.Project('<binary>', auto_load_libs=False)

# Create symbolic input (e.g., 32 bytes)
sym_input = claripy.BVS('input', 32 * 8)

# Set up initial state
state = proj.factory.entry_state(stdin=angr.SimFile('/dev/stdin', content=sym_input))

# Create simulation manager
simgr = proj.factory.simulation_manager(state)

# Explore: find path to target, avoid failure
target_addr = 0x08001234    # "Access granted" or success path
avoid_addr = 0x08001300     # "Access denied" or failure path

simgr.explore(find=target_addr, avoid=avoid_addr)

if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(sym_input, cast_to=bytes)
    print(f"Input to reach target: {solution}")
    print(f"Hex: {solution.hex()}")
else:
    print("No path found")
```

### Path Exploration for Vulnerability Discovery

```python
#!/usr/bin/env python3
"""Explore paths through a function to find exploitable conditions."""
import angr

proj = angr.Project('<binary>', auto_load_libs=False)
cfg = proj.analyses.CFGFast()

# Find calls to dangerous functions
dangerous = ['system', 'popen', 'execve', 'strcpy', 'gets']
for func_name in dangerous:
    sym = proj.loader.find_symbol(func_name)
    if sym:
        # Find callers
        node = cfg.model.get_any_node(sym.rebased_addr)
        if node:
            predecessors = list(cfg.graph.predecessors(node))
            print(f"\n{func_name} called from {len(predecessors)} locations:")
            for pred in predecessors[:10]:
                func = cfg.functions.get(pred.function_address)
                fname = func.name if func else "unknown"
                print(f"  0x{pred.addr:08x} in {fname}")
```

---

## Unicorn Engine Emulation

### Function-Level Emulation

```python
#!/usr/bin/env python3
"""Emulate a specific firmware function with Unicorn."""
from unicorn import *
from unicorn.arm_const import *
import struct

# ARM emulation example
mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

# Map memory regions
CODE_ADDR = 0x08000000
CODE_SIZE = 0x100000
STACK_ADDR = 0x20000000
STACK_SIZE = 0x10000

mu.mem_map(CODE_ADDR, CODE_SIZE)
mu.mem_map(STACK_ADDR, STACK_SIZE)

# Load firmware code
with open('<firmware.bin>', 'rb') as f:
    code = f.read()
mu.mem_write(CODE_ADDR, code)

# Set up stack
mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE - 0x100)

# Set up function arguments (ARM calling convention)
mu.reg_write(UC_ARM_REG_R0, 0x08010000)  # arg0
mu.reg_write(UC_ARM_REG_R1, 0x08020000)  # arg1

# Hook to trace execution
def hook_code(uc, address, size, user_data):
    print(f"  0x{address:08x}: executing {size} bytes")

mu.hook_add(UC_HOOK_CODE, hook_code)

# Hook memory access
def hook_mem(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(f"  Write 0x{value:x} to 0x{address:08x}")
    elif access == UC_MEM_READ:
        print(f"  Read from 0x{address:08x}")

mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

# Emulate function
FUNC_START = 0x08001000  # Function entry (Thumb: set bit 0)
FUNC_END = 0x08001100    # Function return address

try:
    mu.emu_start(FUNC_START | 1, FUNC_END)  # | 1 for Thumb mode
    r0 = mu.reg_read(UC_ARM_REG_R0)
    print(f"Return value (R0): 0x{r0:08x}")
except UcError as e:
    print(f"Emulation error: {e}")
```

### Cross-Architecture Emulation

```python
# MIPS emulation
from unicorn.mips_const import *
mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)

# x86 emulation
from unicorn.x86_const import *
mu = Uc(UC_ARCH_X86, UC_MODE_32)

# RISC-V emulation
# Note: Unicorn RISC-V support may be limited
# Consider using QEMU user-mode instead
```

---

## Anti-Analysis Bypass

### Common Anti-Analysis Techniques in Firmware

| Technique | Detection | Bypass |
|-----------|-----------|--------|
| ptrace detection | `ptrace(PTRACE_TRACEME)` returns -1 if debugged | Patch ptrace call, use `LD_PRELOAD` |
| Timing checks | `gettimeofday()` / `clock_gettime()` deltas | Hook time functions, patch comparison |
| Integrity checks | CRC/hash of code sections | Patch check or fix hash after modification |
| Debugger detection | `/proc/self/status` TracerPid check | Patch file read or comparison |
| Environment checks | Check for `/tmp/ida`, GDB env vars | Clean environment |
| Watchdog reset | Hardware watchdog resets if not fed | Patch watchdog feed, disable in DTB |

### ptrace Anti-Debug Bypass

```bash
# Detect ptrace anti-debug
strings <binary> | grep -i ptrace
objdump -d <binary> | grep -B5 -A5 'ptrace'

# LD_PRELOAD bypass
cat > /tmp/anti_ptrace.c << 'EOF'
#include <sys/types.h>
long ptrace(int request, ...) {
    return 0;
}
EOF
gcc -shared -o /tmp/anti_ptrace.so /tmp/anti_ptrace.c
LD_PRELOAD=/tmp/anti_ptrace.so ./<binary>
```

### Binary Patching

```bash
# NOP out a check using r2
r2 -w <binary>
# In r2:
# s <check_address>
# wa nop              # ARM: 0x00bf (Thumb), 0xe1a00000 (ARM)
# wa nop; nop         # x86: 0x90 0x90

# Modify branch condition
# s <branch_address>
# wa b <target>       # Unconditional branch (ARM)
# wa jmp <target>     # Unconditional jump (x86)

# Using LIEF for programmatic patching
python3 -c "
import lief
binary = lief.parse('<binary>')
# Patch bytes at virtual address
text = binary.get_section('.text')
# ... modify section content ...
binary.write('<binary_patched>')
"
```

### Integrity Check Bypass

```bash
# Find integrity checks
strings <binary> | grep -iE '(crc|checksum|hash|integrity|verify|signature)'
objdump -d <binary> | grep -B5 'crc\|checksum'

# Common patterns:
# 1. CRC32 check of firmware region → patch CRC value or NOP check
# 2. SHA256 verification → replace expected hash or bypass comparison
# 3. RSA signature check → patch verification result
```

---

## RTOS-Specific RE

### VxWorks RE

```bash
# VxWorks has a symbol table — goldmine for RE
strings <firmware> | grep -E '^[a-zA-Z_][a-zA-Z0-9_]{3,}$' | head -50

# Find VxWorks symbol table
# Symbol table entries: name pointer + value + type
python3 -c "
import struct
with open('<firmware>', 'rb') as f:
    data = f.read()
# Look for symbol table structure
# VxWorks symbol table is typically at a fixed location
# Each entry: name_ptr(4) + value(4) + type(1) + padding(3)
"

# WDB agent (remote debug service, port 17185 UDP)
# If WDB is enabled, full remote control is possible
strings <firmware> | grep -i wdb
```

### FreeRTOS RE

```bash
# FreeRTOS task identification
strings <firmware> | grep -E '(xTaskCreate|vTaskDelete|xQueue|xSemaphore|xTimer)' | head -20

# Task names (passed to xTaskCreate)
strings -n 4 <firmware> | grep -E '^[A-Z][a-z]+[A-Z]' | head -20  # CamelCase task names

# Find task creation calls
r2 -A <firmware> -q -c 'axt @ sym.xTaskCreate' 2>/dev/null | head -10
```

### QNX RE

```bash
# QNX binary identification
file <binary>  # "QNX6" or ELF for Neutrino

# QNX IPC channels
strings <binary> | grep -E '(channel|pulse|msg_send|msg_receive)' | head -20

# QNX resource managers
strings <binary> | grep -E '^/dev/' | head -20
```

### Zephyr RE

```bash
# Zephyr kernel objects
strings <firmware> | grep -E '(k_thread|k_sem|k_mutex|k_msgq|k_pipe|k_timer|k_work)' | head -20

# Zephyr config (often embedded)
strings <firmware> | grep 'CONFIG_' | head -30
```

---

## Cross-Architecture RE Notes

### ARM (32-bit)

- **Thumb vs ARM mode:** Thumb = 16-bit instructions (bit 0 of address set), ARM = 32-bit
- **Cortex-M:** Always Thumb mode, vector table at 0x0
- **Function prologue:** `PUSH {r4-r11, lr}` / `STMFD sp!, {r4-r11, lr}`
- **Function epilogue:** `POP {r4-r11, pc}` / `LDMFD sp!, {r4-r11, pc}`
- **Calling convention:** r0-r3 = args, r0 = return, r4-r11 = callee-saved, lr = return address

### ARM64 (AArch64)

- **Fixed 4-byte instructions** (no Thumb equivalent)
- **Function prologue:** `STP x29, x30, [sp, #-N]!` / `MOV x29, sp`
- **Calling convention:** x0-x7 = args, x0 = return, x19-x28 = callee-saved, x30 (lr) = return address

### MIPS

- **Branch delay slots:** Instruction after branch always executes
- **GP-relative addressing:** Global pointer (gp/$28) used for data access
- **Function prologue:** `addiu $sp, $sp, -N` / `sw $ra, N($sp)`
- **Calling convention:** $a0-$a3 = args, $v0-$v1 = return, $s0-$s7 = callee-saved

### RISC-V

- **Compressed extension (RVC):** 16-bit instructions intermixed with 32-bit
- **Function prologue:** `addi sp, sp, -N` / `sd ra, N(sp)`
- **Calling convention:** a0-a7 = args, a0-a1 = return, s0-s11 = callee-saved

### PowerPC

- **Function prologue:** `stwu r1, -N(r1)` / `mflr r0` / `stw r0, N+4(r1)`
- **Calling convention:** r3-r10 = args, r3 = return, r14-r31 = callee-saved

---

## Firmware Function Identification

Common embedded firmware patterns to look for during RE:

### ISR (Interrupt Service Handler) Patterns

```
# ARM Cortex-M ISR: function in vector table, often short
# Look for: read peripheral status register, clear flag, minimal processing
# ISRs typically don't use stack frame setup

# Identify ISR table from vector table (first N words of firmware)
```

### Main Loop Pattern

```
# Embedded main loop: init → while(1) { process; }
# Look for: initialization sequence followed by unconditional backward branch
# Often calls watchdog_feed() / kick_watchdog() in the loop
```

### Peripheral Setup Pattern

```
# GPIO/UART/SPI/I2C initialization:
# 1. Enable clock to peripheral (write to RCC/clock controller)
# 2. Configure pins (write to GPIO registers)
# 3. Configure peripheral registers
# 4. Enable peripheral

# These produce distinctive patterns of writes to fixed addresses
```

### Safety Function Patterns

```
# Safety-critical code patterns:
# - Redundant checks (same condition checked twice)
# - Watchdog feed with specific sequence
# - Range checking on motor/actuator commands
# - Emergency stop logic (reads e-stop pin, disables outputs)
# - Heartbeat/alive signals
```
