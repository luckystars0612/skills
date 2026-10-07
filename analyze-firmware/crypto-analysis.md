# Cryptographic Analysis

Techniques for identifying and attacking cryptographic implementations in firmware. Covers cipher identification, weak crypto detection, key recovery, TLS/SSL audit, firmware decryption, custom crypto analysis, and robot-specific crypto.

---

## Cipher Identification

### Identifying Algorithms from Binary Patterns

```bash
# AES detection — S-box constant (0x637c777b...)
python3 -c "
aes_sbox = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
])
with open('<binary>', 'rb') as f:
    data = f.read()
    idx = data.find(aes_sbox)
    while idx != -1:
        print(f'AES S-box found at offset 0x{idx:08x}')
        idx = data.find(aes_sbox, idx + 1)
" 2>/dev/null

# DES detection — initial permutation table or S-boxes
python3 -c "
des_ip = bytes([58, 50, 42, 34, 26, 18, 10, 2])  # First 8 bytes of IP table
with open('<binary>', 'rb') as f:
    data = f.read()
    idx = data.find(des_ip)
    if idx != -1:
        print(f'DES IP table found at offset 0x{idx:08x}')
" 2>/dev/null

# SHA-256 detection — initial hash values (H0-H7)
python3 -c "
import struct
sha256_h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a]
pattern = struct.pack('>4I', *sha256_h)
with open('<binary>', 'rb') as f:
    data = f.read()
    # Check big-endian
    idx = data.find(pattern)
    if idx != -1:
        print(f'SHA-256 constants (BE) at 0x{idx:08x}')
    # Check little-endian
    pattern_le = struct.pack('<4I', *sha256_h)
    idx = data.find(pattern_le)
    if idx != -1:
        print(f'SHA-256 constants (LE) at 0x{idx:08x}')
" 2>/dev/null

# MD5 detection — initial values
python3 -c "
import struct
md5_init = struct.pack('<4I', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
with open('<binary>', 'rb') as f:
    data = f.read()
    idx = data.find(md5_init)
    if idx != -1:
        print(f'MD5 init values at 0x{idx:08x}')
" 2>/dev/null

# RC4 detection — key scheduling algorithm pattern
# RC4 uses a 256-byte state array initialized as identity permutation
# Look for initialization loop writing 0,1,2,...,255 to array
```

### Crypto Library Detection

```bash
# OpenSSL
strings <binary> | grep -oE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]?' | head -1

# mbedTLS (formerly PolarSSL)
strings <binary> | grep -iE '(mbed.?tls|polar.?ssl)' | head -5

# wolfSSL (formerly CyaSSL)
strings <binary> | grep -iE '(wolfssl|cyassl)' | head -5

# BearSSL
strings <binary> | grep -i 'bearssl' | head -5

# Libsodium / NaCl
strings <binary> | grep -iE '(libsodium|nacl|crypto_box|crypto_sign)' | head -5

# Crypto++ / Botan
strings <binary> | grep -iE '(cryptopp|crypto\+\+|botan)' | head -5

# Hardware crypto (ARM TrustZone, STM32 crypto accelerator)
strings <binary> | grep -iE '(trustzone|tee|secure.world|cryp_|hash_|rng_)' | head -5
```

### r2 Crypto Detection

```bash
# radare2 crypto identification
r2 -A <binary> -q -c '
/x 637c777bf26b6fc5   # AES S-box
/x 6a09e667bb67ae85   # SHA-256 H0-H1
/x 67452301efcdab89   # MD5 init
' 2>/dev/null
```

---

## Weak Crypto Detection

### Insecure Algorithms

```bash
# DES (56-bit key — broken)
strings <binary> | grep -iE '(des_|DES_|des_cbc|des_ecb|triple.?des|3des)' | head -5

# RC4 (biased output — broken for TLS)
strings <binary> | grep -iE '(rc4|arcfour|ARC4)' | head -5

# MD5 for authentication (collision attacks)
strings <binary> | grep -iE '(md5|MD5_)' | head -5

# SHA-1 for signatures (collision attacks)
strings <binary> | grep -iE '(sha1|SHA1|sha_1)' | head -5

# ECB mode (pattern preservation)
strings <binary> | grep -iE '(ecb|ECB_MODE|aes.?ecb)' | head -5

# Hardcoded IVs/nonces
strings <binary> | grep -iE '(iv[_= ]|nonce[_= ]|initial.?vector)' | head -5
# Static IV = nonce reuse → complete loss of confidentiality for CTR/GCM

# Null/empty keys
strings <binary> | grep -iE '(key[_= ]*"\"|key[_= ]*0x0000|null.?key)' | head -5
```

### Weak Key Sizes

```bash
# RSA key size check
for key in $(find . -name '*.pem' -o -name '*.key' -o -name '*.pub' 2>/dev/null); do
    bits=$(openssl rsa -in "$key" -text -noout 2>/dev/null | grep 'Private-Key\|Public-Key' | grep -oE '[0-9]+')
    if [ -n "$bits" ]; then
        severity="OK"
        [ "$bits" -lt 2048 ] && severity="WEAK"
        [ "$bits" -lt 1024 ] && severity="CRITICAL"
        echo "$key: $bits bits ($severity)"
    fi
done

# ECC key size check
for key in $(find . -name '*.pem' -o -name '*.key' 2>/dev/null); do
    curve=$(openssl ec -in "$key" -text -noout 2>/dev/null | grep 'ASN1 OID\|NIST CURVE')
    if [ -n "$curve" ]; then
        echo "$key: $curve"
        # P-256 (prime256v1) or higher = OK
        # P-192 = WEAK
        # P-160 or less = CRITICAL
    fi
done

# Symmetric key sizes in code
strings <binary> | grep -iE '(key.?size|key.?len|key.?length).*[0-9]' | head -5
# AES-128 = acceptable, AES-256 = recommended
# DES (56-bit) = broken
# 3DES (112/168-bit) = deprecated
```

### Weak PRNG Usage

```bash
# rand()/srand() for security-sensitive operations
readelf -s <binary> 2>/dev/null | grep -E ' (rand|srand|random|srandom)$'

# Time-based seeding
strings <binary> | grep -iE '(srand.*time|seed.*time|time.*seed)' | head -5

# Predictable seeds
strings <binary> | grep -iE '(srand\(0\)|srand\(1\)|seed.*=.*0|seed.*=.*1234)' | head -5
```

---

## Key Recovery

### Extracting Keys from Binary/Memory

```bash
# Find PEM-encoded keys
strings <binary> | grep -A 30 'BEGIN.*KEY' | head -40

# Find raw key material (high-entropy regions near crypto code)
python3 -c "
import struct, math

def entropy(data):
    if not data: return 0
    freq = [0] * 256
    for b in data: freq[b] += 1
    return -sum(f/len(data) * math.log2(f/len(data)) for f in freq if f)

with open('<binary>', 'rb') as f:
    data = f.read()

# Scan for high-entropy 16/32-byte blocks (potential AES keys)
for offset in range(0, len(data) - 32, 16):
    block = data[offset:offset+32]
    e = entropy(block)
    if e > 7.5:  # Very high entropy
        # Check if near AES S-box or crypto functions
        print(f'  High-entropy block at 0x{offset:08x} (entropy={e:.2f}): {block[:16].hex()}')
" 2>/dev/null | head -20

# Extract keys from process memory (runtime)
# In GDB: dump memory /tmp/heap.bin <start> <end>
# Then search dump for key patterns
```

### Key Derivation Function Analysis

```bash
# KDF identification
strings <binary> | grep -iE '(pbkdf2|scrypt|bcrypt|argon2|hkdf|kdf)' | head -5

# Weak KDF parameters
# PBKDF2 with low iteration count (< 100,000 for 2024)
strings <binary> | grep -iE '(iteration|round|count).*[0-9]' | head -5

# Hardcoded salt
strings <binary> | grep -iE '(salt[_= ]|salt.*=)' | head -5
```

---

## TLS/SSL Audit

### Certificate Chain Analysis

```bash
# Find all certificates
find . -name '*.pem' -o -name '*.crt' -o -name '*.cert' -o -name '*.der' 2>/dev/null | while read cert; do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -text -noout 2>/dev/null | grep -E \
        '(Subject:|Issuer:|Not Before|Not After|Public-Key|Signature Algorithm|CA:)' | head -10

    # Check for issues
    # Self-signed?
    issuer=$(openssl x509 -in "$cert" -issuer -noout 2>/dev/null)
    subject=$(openssl x509 -in "$cert" -subject -noout 2>/dev/null)
    [ "$issuer" = "$subject" ] && echo "  WARNING: Self-signed certificate"

    # Expired?
    openssl x509 -in "$cert" -checkend 0 -noout 2>/dev/null || echo "  WARNING: Certificate expired"

    # Weak signature algorithm?
    openssl x509 -in "$cert" -text -noout 2>/dev/null | grep 'Signature Algorithm' | \
        grep -i 'sha1\|md5' && echo "  WARNING: Weak signature algorithm"

    # Weak key?
    bits=$(openssl x509 -in "$cert" -text -noout 2>/dev/null | grep 'Public-Key' | grep -oE '[0-9]+')
    [ -n "$bits" ] && [ "$bits" -lt 2048 ] && echo "  WARNING: Weak key size ($bits bits)"
done
```

### TLS Configuration Audit

```bash
# TLS/SSL configuration files
find . -name '*ssl*' -o -name '*tls*' | grep -E '\.(conf|cfg|ini|yaml|json)$' | head -10

# Check for TLS 1.0/1.1 (deprecated)
grep -rI 'TLSv1[^.]|TLSv1\.0\|SSLv3\|SSLv2' . 2>/dev/null | head -5

# Check cipher suites
grep -rI 'cipher\|ciphersuite\|ssl_cipher' . 2>/dev/null | head -10

# Weak cipher suites
grep -rI 'NULL\|EXPORT\|DES\|RC4\|MD5\|anon' . 2>/dev/null | grep -i cipher | head -5

# Certificate verification disabled (CRITICAL)
strings <binary> | grep -iE '(verify.*none\|verify.*false\|insecure\|no.?verify\|skip.?verify)' | head -5
grep -rI 'SSL_CTX_set_verify.*SSL_VERIFY_NONE\|verify=False\|rejectUnauthorized.*false' . 2>/dev/null | head -5
```

---

## Firmware Decryption

### Identifying Encrypted Firmware

```bash
# High entropy throughout = likely encrypted
binwalk -E <firmware_path>

# Known encryption headers
hexdump -C <firmware_path> | head -4

# Common firmware encryption approaches:
# 1. AES-CBC with hardcoded key in update utility
# 2. AES-CBC with key derived from device serial/MAC
# 3. XOR with repeating key
# 4. Custom encryption (often weak)
# 5. RSA-encrypted AES key + AES-encrypted firmware
```

### XOR Encryption Analysis

```python
#!/usr/bin/env python3
"""Detect and break XOR encryption in firmware."""

def find_xor_key(data, known_plaintext=None, key_max_len=32):
    """Try to find XOR key via known plaintext or frequency analysis."""

    if known_plaintext:
        # Known plaintext attack
        results = []
        for offset in range(len(data) - len(known_plaintext)):
            key = bytes(a ^ b for a, b in zip(data[offset:], known_plaintext))
            results.append((offset, key))
        return results[:5]

    # Frequency analysis for single-byte XOR
    best_key = 0
    best_score = 0
    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in data[:1024])
        # Score based on ASCII printable ratio
        printable = sum(1 for b in decrypted if 32 <= b <= 126)
        if printable > best_score:
            best_score = printable
            best_key = key

    return best_key

with open('<firmware_path>', 'rb') as f:
    data = f.read()

# Try with known plaintext (e.g., ELF header, SquashFS magic)
elf_magic = b'\x7fELF'
key = find_xor_key(data, elf_magic)
print(f"Potential XOR key (ELF): {key}")
```

### Analyzing Update Mechanism for Keys

```bash
# Find firmware update utilities
find . -name '*update*' -o -name '*upgrade*' -o -name '*flash*' -o -name '*fota*' 2>/dev/null | head -10

# Search for encryption key in update utility
strings <update_binary> | grep -iE '(key|password|secret|decrypt|aes|iv|nonce)' | head -10

# Look for hardcoded key constants
strings <update_binary> | grep -oE '[0-9a-fA-F]{32,64}' | head -10

# Check for key file references
strings <update_binary> | grep -iE '(\.key|\.pem|keyfile|key_file|secret_file)' | head -5

# Reverse engineer decryption function
r2 -A <update_binary> -q -c '
izz~decrypt
izz~aes
izz~key
afl~crypt
afl~decrypt
' 2>/dev/null | head -20
```

---

## Custom Crypto Analysis

### Identifying Homebrew Ciphers

```bash
# Signs of custom/homebrew crypto:
# 1. No standard crypto library linked
readelf -d <binary> 2>/dev/null | grep -i 'ssl\|crypto\|mbedtls\|wolfssl'
# If no crypto library but encryption is used → likely custom

# 2. Simple XOR patterns
strings <binary> | grep -iE '(xor|^|encrypt|decrypt|cipher|scramble|obfuscate)' | head -10

# 3. Substitution tables (not matching known S-boxes)
python3 -c "
with open('<binary>', 'rb') as f:
    data = f.read()
# Look for 256-byte tables that could be substitution ciphers
for i in range(len(data) - 256):
    block = data[i:i+256]
    if len(set(block)) > 200:  # Mostly unique values = possible S-box
        # Check if it's a known S-box
        if block[:4] != bytes([0x63, 0x7c, 0x77, 0x7b]):  # Not AES
            print(f'Unknown substitution table at 0x{i:08x}')
" 2>/dev/null | head -10

# 4. Bit manipulation patterns (shifts, rotations)
strings <binary> | grep -iE '(rotate|shift|ror|rol|circular)' | head -5
```

### Attacking Weak Custom Crypto

```python
#!/usr/bin/env python3
"""Attack patterns for weak custom encryption."""

# 1. XOR cipher → frequency analysis
# 2. Substitution cipher → frequency analysis
# 3. Custom block cipher → differential/linear cryptanalysis
# 4. Weak key derivation → brute force
# 5. ECB mode → pattern analysis
# 6. Fixed IV → chosen-plaintext attack
# 7. Reused keystream → XOR of ciphertexts

# For firmware decryption, most common weakness is:
# - Hardcoded key (extract from binary)
# - Weak key derivation (predictable from device info)
# - XOR with short repeating key
```

---

## Robot-Specific Crypto

### DDS Security Certificates

```bash
# DDS security plugin certificates
find . -path '*dds*' -name '*.pem' -o -path '*dds*' -name '*.p7s' 2>/dev/null | head -10

# DDS governance and permissions
find . -name 'governance*.xml' -o -name 'permissions*.xml' 2>/dev/null | head -10

# Check DDS security configuration
grep -rI 'dds.sec\|rtps.security\|auth.plugin\|crypto.plugin\|access.plugin' . 2>/dev/null | head -10

# DDS Identity CA
find . -name 'identity_ca*' 2>/dev/null
# DDS Permissions CA
find . -name 'permissions_ca*' 2>/dev/null
```

### SROS2 Keystore Analysis

```bash
# SROS2 keystore directory structure
find . -path '*/keystore/*' 2>/dev/null | head -20

# Expected structure:
# keystore/
#   enclaves/
#     <node_namespace>/
#       <node_name>/
#         cert.pem          # Node certificate
#         key.pem           # Node private key
#         identity_ca.cert.pem
#         permissions_ca.cert.pem
#         governance.p7s
#         permissions.p7s

# Analyze node certificates
for cert in $(find . -path '*/keystore/*/cert.pem' 2>/dev/null); do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -text -noout 2>/dev/null | grep -E '(Subject:|Not After|Public-Key)' | head -5
done

# Check permissions (what each node can do)
for perm in $(find . -path '*/keystore/*/permissions.p7s' 2>/dev/null); do
    echo "=== $perm ==="
    openssl smime -verify -noverify -in "$perm" -inform PEM 2>/dev/null | head -30
done
```

### OPC UA Security Policies

```bash
# OPC UA security configuration
grep -rI 'SecurityPolicy\|securityPolicy' . 2>/dev/null | head -10

# OPC UA security policies:
# None → no security (CRITICAL)
# Basic128Rsa15 → deprecated (WEAK)
# Basic256 → deprecated (WEAK)
# Basic256Sha256 → acceptable
# Aes128_Sha256_RsaOaep → recommended
# Aes256_Sha256_RsaPss → recommended

# OPC UA certificates
find . -path '*opcua*' -name '*.der' -o -path '*opcua*' -name '*.pem' 2>/dev/null | head -10
```

### Firmware Signing / Secure Boot

```bash
# Secure boot configuration
strings <binary> | grep -iE '(secure.?boot|verified.?boot|signed.?image|boot.?verify|trust.?zone)' | head -5

# Code signing keys
find . -name '*sign*' -name '*.pem' -o -name '*sign*' -name '*.key' 2>/dev/null | head -5

# U-Boot verified boot
strings <firmware> | grep -iE '(fit.?image|verified.?boot|rsa.*verify|hash.*algo)' | head -5

# Check if secure boot can be bypassed
# Common bypasses:
# - Key stored alongside firmware (extract and re-sign)
# - Verification only checks header, not full image
# - Downgrade to unsigned firmware version
# - Physical bypass (JTAG/SWD to skip boot verification)
strings <binary> | grep -iE '(bypass\|skip\|disable).*verify' | head -5
```

---

## Crypto Vulnerability Severity Reference

| Finding | Severity | Notes |
|---------|----------|-------|
| No encryption on sensitive data | Critical | Plaintext credentials/commands |
| DES/RC4 for data protection | High | Broken algorithms |
| MD5/SHA1 for signatures | High | Collision attacks practical |
| Self-signed certificates | Medium | No trust chain verification |
| Expired certificates | Medium | May indicate abandoned security |
| ECB mode | Medium-High | Pattern preservation |
| Static IV/nonce | High | Breaks semantic security |
| Hardcoded encryption key | Critical | Anyone with binary has key |
| Weak KDF (low iterations) | Medium | Brute-force feasible |
| No firmware signature verification | Critical | Allows malicious firmware installation |
| Certificate verification disabled | Critical | MitM trivial |
| Weak PRNG for security | High | Predictable tokens/keys |
| Custom/homebrew cipher | High | Likely cryptographically weak |
| Missing TLS | High | All traffic in plaintext |
