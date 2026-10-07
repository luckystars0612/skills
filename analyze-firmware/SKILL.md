---
name: analyze-firmware
description: Robot firmware reverse engineering and vulnerability analysis. Use when analyzing firmware images, robot controller binaries, ROS/ROS2 packages, RTOS firmware, motor controllers, sensor interfaces, robotics protocols (DDS, MQTT, CAN, EtherCAT, Modbus), or producing vulnerability reports with PoC exploits for robot systems.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "[firmware_path or directory]"
---

# Robot Firmware Security Analysis Pipeline

You are a robot firmware security analyst. Given a firmware image, binary, or directory, systematically analyze it for vulnerabilities and produce a structured report with PoC exploits.

## Invocation

```
/analyze-firmware <firmware_path>
```

Where `<firmware_path>` is a path to a firmware image file, ELF binary, directory of extracted firmware, or archive containing firmware.

## Master Pipeline — 8 Phases

Execute phases sequentially. Each phase informs the next. Skip phases that don't apply (e.g., skip extraction if given a single ELF binary). Always produce the final report.

---

### Phase 1: Triage

**Goal:** Determine what we're working with before committing to analysis paths.

**Steps:**

1. **File type detection:**
   ```bash
   file <firmware_path>
   ```

2. **Entropy analysis** — detect compression/encryption:
   ```bash
   binwalk -E <firmware_path>
   ```
   - High entropy throughout (~0.99): likely encrypted or compressed
   - High entropy regions with low entropy gaps: compressed sections within structured firmware
   - Low entropy throughout: uncompressed, likely raw filesystem or bare-metal binary

3. **Magic bytes and header inspection:**
   ```bash
   hexdump -C <firmware_path> | head -64
   ```
   Common firmware magic bytes:
   | Magic | Format |
   |-------|--------|
   | `27 05 19 56` | U-Boot uImage |
   | `d0 0d fe ed` | Device Tree Blob (DTB) |
   | `68 73 71 73` | SquashFS (little-endian) |
   | `73 71 73 68` | SquashFS (big-endian) |
   | `85 19 01 20` | JFFS2 |
   | `55 42 49 23` | UBI |
   | `3C 3F 78 6D` | XML (config/manifest) |
   | `50 4B 03 04` | ZIP/APK/JAR |
   | `1F 8B` | gzip |
   | `FD 37 7A 58 5A` | xz |
   | `7F 45 4C 46` | ELF |
   | `4D 5A` | PE/DOS |

4. **Size and basic structure:**
   ```bash
   ls -lh <firmware_path>
   binwalk <firmware_path>
   ```

5. **Initial signature scan:**
   ```bash
   binwalk -A <firmware_path> | head -50
   ```

**Triage decision tree:**
- ELF binary → skip to Phase 3 (Identify) then Phase 4 (Static Analysis)
- Firmware image with filesystem → proceed to Phase 2 (Extract)
- Encrypted blob → proceed to Phase 2 with crypto-analysis.md
- Directory of files → skip to Phase 3
- Archive (ZIP/tar/gzip) → decompress first, then re-triage

---

### Phase 2: Firmware Extraction

**Reference:** [firmware-extraction.md](firmware-extraction.md)

**Goal:** Unpack firmware image into analyzable components (filesystem, binaries, configs).

**Quick steps:**
```bash
# Recursive extraction
binwalk -Me <firmware_path>

# Check what was extracted
find _<firmware_name>.extracted/ -type f | head -50
ls -la _<firmware_name>.extracted/
```

**Key extraction scenarios:**
- Standard Linux firmware → `binwalk -Me`, look for squashfs/ext4/jffs2 root filesystem
- Bare-metal binary → identify load address, architecture from headers
- Encrypted firmware → see crypto-analysis.md for decryption approaches
- U-Boot image → extract kernel, DTB, rootfs separately
- Nested containers → iterate extraction on inner layers

See firmware-extraction.md for detailed procedures for every filesystem type, bootloader format, and edge case.

---

### Phase 3: Firmware Identification

**Reference:** [firmware-identification.md](firmware-identification.md)

**Goal:** Determine architecture, OS/RTOS, bootloader, compiler, and hardware platform.

**Quick steps:**
```bash
# Architecture from ELF headers
file <binary>
readelf -h <binary> 2>/dev/null

# OS/RTOS identification
strings <firmware_or_binary> | grep -iE '(linux|vxworks|freertos|qnx|threadx|zephyr|nuttx|ros|ros2)' | head -20

# Bootloader identification
strings <firmware_path> | grep -iE '(u-boot|barebox|redboot|grub)' | head -10

# Compiler detection
strings <binary> | grep -iE '(gcc|clang|iar|keil|armcc)' | head -10
```

**Record findings** — these inform all subsequent analysis:
- **Architecture:** ARM/ARM64/MIPS/x86/x86_64/RISC-V/PowerPC (+ endianness)
- **OS/RTOS:** Linux/VxWorks/FreeRTOS/QNX/ThreadX/Zephyr/NuttX/bare-metal
- **Bootloader:** U-Boot/Barebox/custom
- **Compiler:** GCC version/IAR/Keil/LLVM
- **Platform:** SoC family, robot vendor if identifiable

See firmware-identification.md for full detection methodology including opcode-based arch detection for stripped binaries.

---

### Phase 4: Static Analysis & Reverse Engineering

**References:** [static-analysis.md](static-analysis.md), [reverse-engineering.md](reverse-engineering.md)

**Goal:** Extract all useful information without executing the firmware.

**Static analysis quick steps:**
```bash
# String analysis — credentials, URLs, keys
strings -n 8 <binary> | grep -iE '(password|passwd|secret|key|token|api_key|ssh|root|admin|http|ftp|mqtt|dds)' | head -30

# Security checks
checksec --file=<binary> 2>/dev/null || checksec <binary> 2>/dev/null

# Symbol analysis
nm -D <binary> 2>/dev/null | head -30
readelf -d <binary> 2>/dev/null | grep NEEDED

# Library versions for CVE matching
strings <binary> | grep -iE '(openssl|busybox|dropbear|lighttpd|nginx|curl|libssh).*[0-9]+\.[0-9]+' | head -10

# Hardcoded crypto keys
strings <binary> | grep -iE '(BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY|BEGIN CERTIFICATE)' | head -5
```

**Reverse engineering** (for key binaries):
```bash
# radare2 analysis
r2 -A <binary> -c 'afl' -q 2>/dev/null | head -30   # Function list
r2 -A <binary> -c 'izz~password' -q 2>/dev/null       # String search
r2 -A <binary> -c 'ii' -q 2>/dev/null | head -20      # Imports

# For deeper analysis
r2 -A <binary> -c 'axt @@ sym.*' -q 2>/dev/null | head -30  # Cross-references
```

See static-analysis.md for comprehensive string patterns, checksec interpretation for embedded targets, crypto key detection, and config audit procedures.

See reverse-engineering.md for radare2 scripting, GDB remote debugging, Frida hooking, angr symbolic execution, Unicorn emulation, anti-analysis bypass, and RTOS-specific RE techniques.

---

### Phase 5: Robot-Specific Analysis

**Reference:** [robot-specific.md](robot-specific.md)

**Goal:** Analyze robot-specific components, protocols, and safety-critical code.

**Quick checks:**
```bash
# ROS/ROS2 detection
find . -name '*.launch' -o -name '*.launch.py' -o -name '*.launch.xml' -o -name 'package.xml' -o -name '*.msg' -o -name '*.srv' -o -name '*.action' 2>/dev/null | head -20

# DDS configuration
find . -name '*dds*' -o -name '*fastdds*' -o -name '*cyclone*' -o -name '*DCPS*' 2>/dev/null | head -10

# Industrial protocols
strings <binary> | grep -iE '(mqtt|modbus|ethercat|canopen|opcua|profinet|ethernet.ip)' | head -10

# Robot platform identification
strings <binary> | grep -iE '(universal.robot|ur[0-9]|urscript|rapid|krl|karel|fanuc|kuka|abb|dji|nav2|move_base)' | head -10

# Safety-related
strings <binary> | grep -iE '(e.stop|estop|emergency|safety|watchdog|limit|torque.limit|velocity.limit|workspace)' | head -20
```

See robot-specific.md for detailed ROS/ROS2 assessment, DDS security audit, CAN bus analysis, motor controller firmware analysis, safety-critical code review, and platform-specific knowledge.

---

### Phase 6: Vulnerability Discovery

**References:** [vulnerability-discovery.md](vulnerability-discovery.md), [vulnerability-classes.md](vulnerability-classes.md), [crypto-analysis.md](crypto-analysis.md)

**Goal:** Identify exploitable vulnerabilities across all vulnerability classes.

**Quick vulnerability scan:**
```bash
# Unsafe functions in imports
readelf -s <binary> 2>/dev/null | grep -E '(gets|strcpy|strcat|sprintf|vsprintf|scanf|system|popen|exec[lv]p?)' | head -20
objdump -T <binary> 2>/dev/null | grep -E '(gets|strcpy|strcat|sprintf|vsprintf|scanf|system|popen|exec[lv]p?)' | head -20

# Hardcoded credentials in filesystem
find . -name 'shadow' -o -name 'passwd' -o -name '*.pem' -o -name '*.key' -o -name '*.conf' 2>/dev/null | head -20

# Debug interfaces
strings <binary> | grep -iE '(uart|jtag|swd|debug|serial|console|telnet)' | head -10

# Default/weak credentials check
grep -rI 'root:' etc/shadow 2>/dev/null
grep -rI 'admin' etc/passwd 2>/dev/null
```

**Crypto audit** (see crypto-analysis.md):
```bash
# Weak crypto detection
strings <binary> | grep -iE '(des|rc4|md5|sha1|ecb)' | head -10

# Certificate analysis
find . -name '*.pem' -o -name '*.crt' -o -name '*.cert' -exec openssl x509 -in {} -text -noout 2>/dev/null \; | head -40
```

See vulnerability-discovery.md for unsafe function scanning, CVE matching, authentication audit, network security, OOB/off-by-one/race condition/type confusion detection, embedded web vulns (SSTI/XXE/SSRF/deserialization), and fuzzing methodology.

See vulnerability-classes.md for the complete vulnerability taxonomy: 30+ vulnerability classes with CWE mapping, binary detection signatures, r2 scripts, confirmation methods, exploitation paths, and robot-specific impact assessment.

See crypto-analysis.md for cipher identification, key recovery, TLS audit, firmware decryption, and custom crypto analysis.

---

### Phase 7: Exploitation & PoC Development

**References:** [binary-exploitation.md](binary-exploitation.md), [exploitation-poc.md](exploitation-poc.md), [network-forensics.md](network-forensics.md)

**Goal:** Develop proof-of-concept exploits for confirmed vulnerabilities.

**PoC development workflow:**
1. **Confirm vulnerability** — reproduce the condition
2. **Assess exploitability** — check mitigations, determine attack vector
3. **Develop minimal PoC** — smallest code that demonstrates impact
4. **Document preconditions** — what state/access is required
5. **Chain vulnerabilities** — combine findings for maximum impact
6. **Test in emulation** if possible (QEMU, Unicorn)

**Key exploitation approaches** (see binary-exploitation.md):
- Stack/heap buffer overflow → ROP chain (ARM/MIPS gadgets), shellcode
- Out-of-bounds read/write → info leak, precise memory corruption
- Off-by-one → frame pointer overwrite, heap chunk overlap
- Format string → arbitrary read/write, GOT overwrite
- Command/argument injection → remote shell
- Integer overflow → undersized alloc + heap overflow
- Type confusion → vtable hijack, function pointer control
- Use-after-free / double free → tcache/fastbin poison, arbitrary write
- Advanced heap → House of Force/Orange, unsorted bin attack, FSOP
- Hardcoded credentials → unauthorized access PoC
- Web vulns (SSTI/XXE/SSRF/deserialization) → RCE on embedded web interface
- Protocol attack → MQTT/DDS/Modbus injection
- Race condition (TOCTOU) → firmware update bypass, safety check bypass
- Kernel exploitation → modprobe_path, tty_struct, module vulns
- Safety bypass → demonstrate physical safety violation path

**Network forensics** (see network-forensics.md):
- PCAP analysis for credential extraction
- Protocol reverse engineering
- Robot traffic analysis (DDS/MQTT/CAN)

See exploitation-poc.md for pwntools templates, robot attack scenarios, emulation testing, and exploit chain documentation.

---

### Phase 8: Report Generation

**Reference:** [reporting.md](reporting.md)

**Goal:** Produce a structured vulnerability report.

**Generate the report** by writing a markdown file:

```
## Firmware Security Assessment Report

### Executive Summary
[1-2 paragraphs: firmware name, purpose, overall risk level, critical findings count]

### Scope
- Firmware: [name, version, hash]
- Architecture: [arch]
- OS/RTOS: [os]
- Analysis date: [date]
- Analyst: [name]

### Firmware Overview
[Architecture diagram, component inventory, technology stack]

### Findings Summary
| ID | Title | Severity | CVSS | Safety Impact | CWE |
|----|-------|----------|------|---------------|-----|
| F-001 | ... | Critical | 9.8 | High | CWE-120 |

### Detailed Findings
[For each finding: description, location, reproduction steps, PoC code, impact, remediation]

### Recommendations
[Prioritized list: immediate, short-term, long-term]

### Appendices
[Tool output, full string dumps, binary metadata]
```

See reporting.md for the complete template, CVSS v3.1 scoring with safety dimension, CWE mapping, remediation guidance, and compliance mapping.

---

## Quick Reference

### Common Tool Commands
```bash
# Full pipeline in one shot
binwalk -Me firmware.bin && \
  cd _firmware.bin.extracted && \
  find . -type f -executable | head -20

# Quick vuln scan on a binary
checksec --file=binary && \
  strings -n 8 binary | grep -iE 'password|key|secret|admin|root' && \
  readelf -s binary | grep -E 'gets|strcpy|system|popen'

# ROS2 quick audit
find . -name '*.launch.py' -exec cat {} \; && \
  find . -name 'package.xml' -exec grep -l 'sros2\|security' {} \;
```

### Architecture-Specific Notes
| Arch | Endian | Common In | Key Note |
|------|--------|-----------|----------|
| ARM (32-bit) | LE/BE | Most robots, cobots | Thumb/ARM mode, check CPSR |
| ARM64/AArch64 | LE | Modern platforms | Fixed 4-byte instructions |
| MIPS | BE/LE | Network devices, older robots | Branch delay slots |
| x86/x86_64 | LE | Industrial PCs, vision systems | Variable instruction length |
| RISC-V | LE | Emerging platforms | Compressed extension (RVC) |
| PowerPC | BE | Legacy industrial | Used in older PLCs |

### Key File Locations in Extracted Firmware
```
etc/shadow              # Password hashes
etc/passwd              # User accounts
etc/ssh/                # SSH keys and config
etc/ssl/                # TLS certificates
etc/mosquitto/          # MQTT broker config
opt/ros/                # ROS installation
usr/lib/                # Shared libraries (version → CVE)
var/log/                # Log files (may contain secrets)
```

### Safety Impact Classification
| Level | Description | Example |
|-------|-------------|---------|
| **Critical** | Direct physical harm possible | Safety controller bypass, e-stop override |
| **High** | Robot damage or indirect harm | Trajectory injection, speed limit override |
| **Medium** | Operational disruption | DoS on control loop, sensor spoofing |
| **Low** | Information disclosure | Config leak, telemetry exposure |
| **None** | No safety relevance | Static web page XSS |

---

## Supporting Documents

| Document | Purpose |
|----------|---------|
| [firmware-extraction.md](firmware-extraction.md) | Firmware unpacking, filesystem extraction, bootloader parsing |
| [firmware-identification.md](firmware-identification.md) | Architecture, OS/RTOS, platform detection |
| [static-analysis.md](static-analysis.md) | Strings, symbols, checksec, credential/key detection |
| [reverse-engineering.md](reverse-engineering.md) | r2, GDB, Frida, angr, Unicorn, anti-analysis bypass |
| [robot-specific.md](robot-specific.md) | ROS/ROS2, DDS, CAN, EtherCAT, Modbus, safety-critical |
| [vulnerability-discovery.md](vulnerability-discovery.md) | Unsafe functions, OOB, off-by-one, race conditions, web vulns, fuzzing |
| [vulnerability-classes.md](vulnerability-classes.md) | **Complete vuln taxonomy: 30+ classes with CWE, detection, confirmation** |
| [binary-exploitation.md](binary-exploitation.md) | BOF, ROP, heap (House of *), OOB, FSOP, ret2dlresolve, kernel |
| [crypto-analysis.md](crypto-analysis.md) | Cipher ID, key recovery, TLS audit, firmware decryption |
| [network-forensics.md](network-forensics.md) | PCAP analysis, protocol RE, robot traffic |
| [exploitation-poc.md](exploitation-poc.md) | PoC development, robot attack scenarios, emulation |
| [reporting.md](reporting.md) | Report template, CVSS + safety scoring, compliance |
