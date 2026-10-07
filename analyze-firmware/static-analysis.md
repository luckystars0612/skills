# Static Analysis

Techniques for extracting security-relevant information from firmware binaries without execution. Covers string analysis, symbol analysis, binary security checks, credential/key detection, config auditing, and radare2 cross-reference analysis.

---

## String Analysis

### Basic String Extraction

```bash
# ASCII strings (minimum 8 characters for less noise)
strings -n 8 <binary> > /tmp/strings_ascii.txt

# UTF-16 strings (Windows, some embedded)
strings -n 8 -e l <binary> > /tmp/strings_utf16.txt

# All encodings
strings -n 6 -a <binary> > /tmp/strings_all.txt

# Count and preview
wc -l /tmp/strings_ascii.txt
head -50 /tmp/strings_ascii.txt
```

### Credential and Secret Patterns

```bash
# Passwords and credentials
strings -n 6 <binary> | grep -iE \
  '(password|passwd|pass[_=:]|pwd[_=:]|credential|secret|token|api[_-]?key|
    auth[_-]?key|access[_-]?key|private[_-]?key|master[_-]?key|
    login|username|user[_=:]|admin|root)' | head -30

# Default/hardcoded passwords (common in embedded)
strings -n 4 <binary> | grep -iE \
  '(admin:admin|root:root|admin:password|admin:1234|root:toor|
    default|factory|service|test1234|changeme|123456)' | head -20

# SSH keys
strings <binary> | grep -E '(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2)' | head -5

# Private keys
strings <binary> | grep -E 'BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE)' | head -5

# Certificates
strings <binary> | grep 'BEGIN CERTIFICATE' | head -5
```

### URL and Network Patterns

```bash
# URLs and endpoints
strings -n 8 <binary> | grep -iE '(https?://|ftp://|mqtt://|amqp://|ws://|wss://)' | head -20

# IP addresses
strings <binary> | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | head -20

# Domain names
strings <binary> | grep -oE '[a-zA-Z0-9][-a-zA-Z0-9]*\.(com|org|net|io|local|lan|internal)' | sort -u | head -20

# Port numbers in context
strings <binary> | grep -iE '(port|listen|bind|connect).*[0-9]{2,5}' | head -10

# MQTT topics
strings <binary> | grep -E '^[a-zA-Z0-9_/]+(/[a-zA-Z0-9_/#]+)+$' | head -20

# ROS topics
strings <binary> | grep -E '^/[a-z_]+(/[a-z_]+)*$' | head -20
```

### Debug and Development Artifacts

```bash
# Debug messages, log formats
strings <binary> | grep -iE '(debug|trace|error|warning|fatal|assert|abort|panic|oops)' | head -20

# File paths (reveals build environment)
strings <binary> | grep -E '^(/home|/opt|/usr|/root|/build|/workspace|/src|C:\\)' | head -20

# TODO/FIXME/HACK comments compiled in
strings <binary> | grep -iE '(todo|fixme|hack|xxx|bug|workaround|temporary)' | head -10

# Version strings
strings <binary> | grep -iE '(version|ver|release|build|rev)[_: ]*[0-9]' | head -10
```

---

## Symbol and Library Analysis

### Symbol Table Analysis

```bash
# Dynamic symbols (most useful for shared libs)
nm -D <binary> 2>/dev/null | head -50

# All symbols (if not stripped)
nm <binary> 2>/dev/null | head -50

# Check if stripped
file <binary> | grep -q 'not stripped' && echo "NOT STRIPPED - full symbols available" || echo "STRIPPED"

# Function symbols only
nm -D <binary> 2>/dev/null | grep ' T \| t ' | head -30

# Undefined symbols (external dependencies)
nm -D <binary> 2>/dev/null | grep ' U ' | head -30
```

### Shared Library Dependencies

```bash
# List required libraries
readelf -d <binary> 2>/dev/null | grep NEEDED

# Library search paths
readelf -d <binary> 2>/dev/null | grep -E 'RPATH|RUNPATH'

# Find actual library files in extracted firmware
find . -name '*.so*' | head -30

# Library version extraction for CVE matching
for lib in $(find . -name '*.so*' -type f 2>/dev/null); do
    version=$(strings "$lib" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$version" ] && echo "$lib: $version"
done | head -20
```

### Critical Library Version Detection

```bash
# OpenSSL version
strings <binary_or_libs> | grep -oE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]?' | head -1

# BusyBox version
strings <binary> | grep 'BusyBox v' | head -1

# Dropbear SSH version
strings <binary_or_libs> | grep -oE 'dropbear[_ ][0-9]+\.[0-9]+' | head -1

# lighttpd version
strings <binary_or_libs> | grep -oE 'lighttpd/[0-9]+\.[0-9]+\.[0-9]+' | head -1

# curl version
strings <binary_or_libs> | grep -oE 'curl/[0-9]+\.[0-9]+\.[0-9]+' | head -1

# Linux kernel version
strings <binary_or_firmware> | grep -oE 'Linux version [0-9]+\.[0-9]+\.[0-9]+' | head -1

# D-Bus version
strings <binary_or_libs> | grep -oE 'dbus-[0-9]+\.[0-9]+\.[0-9]+' | head -1

# glibc version
strings <binary_or_libs> | grep -oE 'glibc [0-9]+\.[0-9]+' | head -1
find . -name 'libc.so*' -exec strings {} \; 2>/dev/null | grep -oE 'GNU C Library.*release version [0-9]+\.[0-9]+' | head -1
```

---

## Binary Security Checks

### checksec Analysis

```bash
# Run checksec
checksec --file=<binary> 2>/dev/null || checksec <binary> 2>/dev/null

# Manual checks if checksec not available
readelf -l <binary> 2>/dev/null | grep GNU_STACK   # NX (look for RW, not RWE)
readelf -d <binary> 2>/dev/null | grep BIND_NOW    # Full RELRO
readelf -d <binary> 2>/dev/null | grep FLAGS       # RELRO flags
readelf -h <binary> 2>/dev/null | grep Type        # PIE (DYN = PIE)
readelf -s <binary> 2>/dev/null | grep __stack_chk # Stack canary
```

### Interpreting checksec for Embedded Targets

Embedded firmware has different security expectations than desktop applications:

| Check | Desktop Expectation | Embedded Reality | Security Implication |
|-------|-------------------|-----------------|---------------------|
| **NX** | Present | Often absent on bare-metal MCUs | Direct shellcode execution on stack/heap |
| **ASLR** | Enabled | Usually absent (fixed addresses) | Predictable memory layout, reliable ROP |
| **Stack Canary** | Present | Often absent | Stack buffer overflows directly exploitable |
| **PIE** | Present | Rare on embedded | Fixed code addresses, simpler exploitation |
| **RELRO** | Full | Partial or none | GOT overwrite attacks possible |
| **Fortify** | Present | Rare | No compile-time buffer overflow protection |

**Key findings to flag:**
- NX absent on Linux-based firmware = **High** (unexpected, should be enabled)
- NX absent on bare-metal MCU = **Informational** (expected, no MMU)
- Stack canary absent on network-facing binary = **High**
- Stack canary absent on safety-critical binary = **Critical** (safety + security)
- ASLR absent on embedded Linux = **Medium** (often expected but still a weakness)

```bash
# Check all executables in extracted firmware
find . -type f -executable -exec sh -c '
    for f; do
        result=$(checksec --file="$f" 2>/dev/null | tail -1)
        [ -n "$result" ] && echo "$f: $result"
    done
' sh {} + 2>/dev/null | head -20
```

---

## Hardcoded Credentials Detection

### Certificate and Key Discovery

```bash
# Find certificate and key files
find . -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.cert' \
       -o -name '*.p12' -o -name '*.pfx' -o -name '*.jks' \
       -o -name '*.der' -o -name '*.pub' 2>/dev/null | head -20

# Analyze found certificates
for cert in $(find . -name '*.pem' -o -name '*.crt' 2>/dev/null); do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -text -noout 2>/dev/null | grep -E '(Subject:|Issuer:|Not After|Public-Key|Signature Algorithm)' | head -10
done

# Check for private keys embedded in binaries
strings <binary> | grep -A 20 'BEGIN.*PRIVATE KEY'

# Find SSH authorized_keys and known_hosts
find . -name 'authorized_keys' -o -name 'known_hosts' -o -name 'id_rsa' \
       -o -name 'id_ed25519' -o -name 'id_dsa' 2>/dev/null

# SSH host keys (persistent identity)
find . -path '*/ssh/ssh_host_*' 2>/dev/null
```

### Password Hash Extraction

```bash
# Shadow file
find . -name 'shadow' -exec cat {} \; 2>/dev/null

# Analyze password hashes
# $1$ = MD5, $5$ = SHA-256, $6$ = SHA-512, $y$ = yescrypt
# Empty second field = no password!
# * or ! = disabled account

# Password in environment or config
grep -rI 'PASSWORD\|PASSWD\|PASS=' etc/ 2>/dev/null | head -10
grep -rI 'password\|passwd' etc/ var/ 2>/dev/null | grep -v '#' | head -20
```

### WiFi and Network Credentials

```bash
# WiFi configurations
find . -name 'wpa_supplicant*' -exec cat {} \; 2>/dev/null
find . -name '*.nmconnection' -exec cat {} \; 2>/dev/null
grep -rI 'psk\|passphrase\|wep_key\|ssid' etc/ 2>/dev/null | head -10

# Cloud/API credentials
grep -rI 'aws_access_key\|aws_secret\|azure\|gcp\|google_cloud' etc/ home/ 2>/dev/null | head -10

# Database credentials
grep -rI 'mysql\|postgres\|mongo\|redis\|sqlite.*password' etc/ 2>/dev/null | head -10
```

---

## Crypto Key Discovery

### AES Key Detection

```bash
# AES S-box constant (first 4 bytes: 0x637c777b)
# Finding this in a binary indicates AES implementation
python3 -c "
import struct
aes_sbox_start = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
with open('<binary>', 'rb') as f:
    data = f.read()
    offset = data.find(aes_sbox_start)
    while offset != -1:
        print(f'  AES S-box found at offset 0x{offset:08x}')
        # Check for key material near S-box
        for key_offset in range(max(0, offset-256), offset):
            # 16/24/32 byte aligned potential keys
            pass
        offset = data.find(aes_sbox_start, offset + 1)
" 2>/dev/null
```

### RSA Key Detection

```bash
# RSA public key modulus patterns
strings <binary> | grep -E 'BEGIN.*PUBLIC.*KEY' | head -5

# Extract and analyze RSA keys
for key in $(find . -name '*.pem' -o -name '*.pub' 2>/dev/null); do
    echo "=== $key ==="
    openssl rsa -in "$key" -text -noout 2>/dev/null | grep -E '(Private-Key|Public-Key|Modulus)' | head -3
done

# Check for weak key sizes
# RSA < 2048 bits is weak
# RSA < 1024 bits is critically weak
```

### Weak/Test Key Patterns

```bash
# Known weak/test keys
strings <binary> | grep -iE '(test.key|debug.key|dev.key|sample|example|demo)' | head -5

# Hardcoded symmetric keys (hex patterns)
strings <binary> | grep -oE '[0-9a-fA-F]{32,64}' | head -20

# Base64-encoded keys
strings <binary> | grep -oE '[A-Za-z0-9+/]{32,}={0,2}' | head -20
```

---

## Configuration File Audit

### Robot Configuration Files

```bash
# Robot-specific configs
find . -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.xml' \
       -o -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.toml' \
       2>/dev/null | head -30

# ROS/ROS2 configuration
find . -name '*.launch' -o -name '*.launch.py' -o -name '*.launch.xml' \
       -o -name 'package.xml' -o -name '*.param' -o -name '*.yaml' -path '*/config/*' \
       2>/dev/null | head -20

# Network configuration
cat etc/network/interfaces 2>/dev/null
cat etc/hostname 2>/dev/null
cat etc/hosts 2>/dev/null
cat etc/resolv.conf 2>/dev/null
ls etc/iptables* etc/nftables* 2>/dev/null  # Firewall rules
```

### Service and Daemon Configuration

```bash
# systemd services
find . -name '*.service' -path '*/systemd/*' 2>/dev/null | head -20
for svc in $(find . -name '*.service' -path '*/systemd/*' 2>/dev/null); do
    echo "=== $svc ==="
    grep -E '(ExecStart|User|Group|CapabilityBound|NoNewPrivileges|ProtectSystem)' "$svc" 2>/dev/null
done

# Init scripts
ls etc/init.d/ 2>/dev/null
ls etc/rc*.d/ 2>/dev/null

# crontab entries
find . -name 'crontab' -o -path '*/cron.d/*' -o -path '*/cron.daily/*' 2>/dev/null | head -10
cat etc/crontab 2>/dev/null

# MQTT broker configuration
find . -name 'mosquitto.conf' -o -name '*mqtt*.conf' 2>/dev/null -exec cat {} \;
```

### Build Artifacts

```bash
# Build system artifacts that shouldn't be in production
find . -name 'Makefile' -o -name 'CMakeLists.txt' -o -name '*.o' \
       -o -name '*.d' -o -name '.git' -o -name '.svn' \
       -o -name '*.debug' -o -name '*.map' -o -name '*.elf' \
       2>/dev/null | head -20

# Compiler/linker map files (reveal memory layout)
find . -name '*.map' -exec head -20 {} \; 2>/dev/null
```

---

## radare2 Cross-Reference Analysis

### Basic r2 Analysis

```bash
# Open binary with full analysis
r2 -A <binary> -q -c '
  afl~[0,3]              # List all functions with addresses
' 2>/dev/null | head -40

# Function count and size distribution
r2 -A <binary> -q -c 'afl | wc -l' 2>/dev/null

# Imports (external function calls)
r2 -A <binary> -q -c 'ii' 2>/dev/null | head -30

# Exports
r2 -A <binary> -q -c 'iE' 2>/dev/null | head -30

# Sections
r2 -A <binary> -q -c 'iS' 2>/dev/null

# Entry points
r2 -A <binary> -q -c 'ie' 2>/dev/null
```

### String Search and Cross-References

```bash
# Search for strings containing keywords
r2 -A <binary> -q -c 'izz~password' 2>/dev/null | head -10
r2 -A <binary> -q -c 'izz~admin' 2>/dev/null | head -10
r2 -A <binary> -q -c 'izz~key' 2>/dev/null | head -10

# Find cross-references to a string
# First find the string address, then find xrefs
r2 -A <binary> -q -c '
  izz~password
' 2>/dev/null

# Cross-references to specific function
r2 -A <binary> -q -c 'axt @ sym.imp.system' 2>/dev/null | head -10
r2 -A <binary> -q -c 'axt @ sym.imp.strcpy' 2>/dev/null | head -10
```

### Pattern and Signature Search

```bash
# Search for byte patterns
r2 -A <binary> -q -c '/x 637c777b' 2>/dev/null  # AES S-box
r2 -A <binary> -q -c '/x d00dfeed' 2>/dev/null  # DTB magic

# Search for string patterns
r2 -A <binary> -q -c '/ password' 2>/dev/null | head -10

# Find all calls to dangerous functions
for func in gets strcpy sprintf system popen execve; do
    refs=$(r2 -A <binary> -q -c "axt @ sym.imp.$func" 2>/dev/null | wc -l)
    [ "$refs" -gt 0 ] && echo "$func: $refs references"
done
```

### Function Analysis

```bash
# Disassemble a specific function
r2 -A <binary> -q -c 'pdf @ main' 2>/dev/null | head -60

# List largest functions (complex = more bugs)
r2 -A <binary> -q -c 'afl | sort -k 3 -n -r' 2>/dev/null | head -20

# Find functions that call system()
r2 -A <binary> -q -c '
  afl
  axt @ sym.imp.system
' 2>/dev/null | head -20

# Decompile function (if r2ghidra plugin available)
r2 -A <binary> -q -c 'pdg @ main' 2>/dev/null | head -60
```

---

## Automated Static Analysis Script

Use this comprehensive one-liner to get a quick security overview:

```bash
# Quick security scan of a binary
echo "=== File Info ===" && file <binary> && \
echo -e "\n=== Security Checks ===" && checksec --file=<binary> 2>/dev/null && \
echo -e "\n=== Dangerous Imports ===" && \
  (readelf -s <binary> 2>/dev/null || nm -D <binary> 2>/dev/null) | \
  grep -E '(gets|strcpy|strcat|sprintf|vsprintf|scanf|system|popen|exec[lv]p?|dlopen)' && \
echo -e "\n=== Credentials ===" && \
  strings -n 6 <binary> | grep -iE '(password|passwd|secret|key|token|admin|root)' | head -10 && \
echo -e "\n=== URLs ===" && \
  strings -n 8 <binary> | grep -iE '(https?://|mqtt://|ftp://)' | head -10 && \
echo -e "\n=== Versions ===" && \
  strings <binary> | grep -iE '(openssl|busybox|dropbear|linux version|gcc).*[0-9]' | head -5
```

For a directory of extracted firmware:

```bash
# Scan all executables in extracted firmware
find <extracted_dir> -type f -executable | while read binary; do
    dangerous=$(readelf -s "$binary" 2>/dev/null | grep -cE '(gets|strcpy|sprintf|system|popen)')
    if [ "$dangerous" -gt 0 ]; then
        echo "$binary: $dangerous dangerous function imports"
    fi
done | sort -t: -k2 -n -r | head -20
```
