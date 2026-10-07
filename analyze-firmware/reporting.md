# Reporting

Templates and guidelines for producing structured firmware security assessment reports. Covers report structure, severity scoring (CVSS v3.1 + safety dimension), CWE mapping, remediation guidance, and compliance mapping.

---

## Report Template

Generate the report as a markdown file. The filename should be:
`<firmware_name>_security_assessment_<date>.md`

```markdown
# Firmware Security Assessment Report

## Executive Summary

**Firmware:** [Name, version, build identifier]
**Assessment Date:** [YYYY-MM-DD]
**Analyst:** [Name/Team]
**Classification:** [Confidential/Internal/Public]

**Overall Risk Level:** [Critical / High / Medium / Low]

[1-2 paragraph summary: what was analyzed, key findings, overall security posture, and most critical recommendations. Write for a technical manager audience — specific enough to understand the risk, concise enough to read in 2 minutes.]

**Key Statistics:**
| Metric | Value |
|--------|-------|
| Total findings | N |
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Informational | N |

---

## Scope

**Target firmware:**
- Name: [firmware name]
- Version: [version string]
- Build: [build identifier if available]
- SHA256: [hash of analyzed firmware file]
- File size: [size]
- Source: [how firmware was obtained]

**Architecture:** [ARM 32-bit LE / ARM64 / MIPS BE / x86_64 / etc.]
**OS/RTOS:** [Linux 5.4.x / VxWorks 7 / FreeRTOS 10.4 / bare-metal / etc.]
**Bootloader:** [U-Boot 2020.04 / custom / N/A]
**Robot platform:** [UR5e / custom AGV / N/A]

**Analysis performed:**
- [x] Firmware extraction and unpacking
- [x] Architecture and OS identification
- [x] Static analysis (strings, symbols, checksec)
- [x] Reverse engineering (key binaries)
- [x] Robot-specific analysis (protocols, safety)
- [x] Vulnerability discovery
- [x] Crypto analysis
- [x] Network forensics (if PCAP provided)
- [x] PoC exploit development
- [ ] Dynamic analysis (requires hardware/emulation)

**Out of scope:**
- [List anything explicitly excluded]

---

## Firmware Overview

### Component Inventory

| Component | Type | Version | Location | Notes |
|-----------|------|---------|----------|-------|
| Linux kernel | OS | 5.4.x | /boot/zImage | |
| BusyBox | Utilities | 1.31.1 | /usr/bin/busybox | Known CVEs |
| OpenSSL | Crypto | 1.1.1g | /usr/lib/libssl.so | |
| lighttpd | Web server | 1.4.55 | /usr/sbin/lighttpd | |
| mosquitto | MQTT broker | 1.6.9 | /usr/sbin/mosquitto | |
| robot_controller | Application | unknown | /opt/robot/bin/controller | Main analysis target |

### Security Posture Summary

| Binary | NX | ASLR | Canary | PIE | RELRO |
|--------|----|----- |--------|-----|-------|
| robot_controller | Yes | No | No | No | Partial |
| web_server | Yes | No | Yes | No | Full |
| mqtt_handler | No | No | No | No | No |

### Network Services

| Port | Protocol | Service | Authentication | Encryption |
|------|----------|---------|----------------|------------|
| 22 | TCP | SSH (Dropbear) | Password | Yes |
| 80 | TCP | HTTP (lighttpd) | None | No |
| 502 | TCP | Modbus | None | No |
| 1883 | TCP | MQTT | None | No |
| 30001 | TCP | Robot control | None | No |

---

## Findings Summary

| ID | Title | Severity | CVSS | Safety | CWE | Status |
|----|-------|----------|------|--------|-----|--------|
| F-001 | Hardcoded root password | Critical | 9.8 | None | CWE-798 | Confirmed |
| F-002 | Stack buffer overflow in robot_controller | Critical | 9.8 | Critical | CWE-120 | PoC developed |
| F-003 | Unauthenticated Modbus access | High | 8.6 | High | CWE-306 | Confirmed |
| F-004 | Unsigned firmware update | High | 8.1 | High | CWE-494 | Confirmed |
| F-005 | Weak TLS configuration | Medium | 5.9 | None | CWE-326 | Confirmed |
| ... | ... | ... | ... | ... | ... | ... |

---

## Detailed Findings

### F-001: [Finding Title]

**Severity:** [Critical / High / Medium / Low / Informational]
**CVSS v3.1 Score:** [0.0 - 10.0]
**CVSS Vector:** [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]
**Safety Impact:** [Critical / High / Medium / Low / None]
**CWE:** [CWE-NNN: Name]
**Status:** [Confirmed / PoC Developed / Suspected]

#### Description
[Clear description of the vulnerability. What is the issue?]

#### Location
[Specific file, function, offset, or configuration]
- File: `/path/to/file`
- Function: `vulnerable_function()` at offset `0x08001234`
- Configuration: `/etc/service.conf`, line 42

#### Technical Details
[How the vulnerability works technically. Include relevant code snippets, disassembly, or configuration.]

```
[code/disassembly/config snippet]
```

#### Reproduction Steps
1. [Step-by-step instructions to reproduce]
2. [Include exact commands or PoC code]
3. [Expected vs actual behavior]

#### Proof of Concept
```python
[PoC code if developed]
```

#### Impact
- **Confidentiality:** [What data is exposed?]
- **Integrity:** [What can be modified?]
- **Availability:** [What can be disrupted?]
- **Safety:** [What physical safety impact? Is injury possible?]

#### Attack Scenario
[Realistic attack scenario: who is the attacker, what access do they need, what's the attack chain?]

#### Remediation
[Specific, actionable fix recommendations]
1. [Primary fix]
2. [Alternative/additional mitigation]

#### References
- [CVE links, vendor advisories, related research]

---

[Repeat for each finding]

---

## Vulnerability Chains

### Chain 1: [Name of attack chain]
[Describe how multiple findings combine for greater impact]

```
F-001 (Hardcoded password) → SSH access
  → F-003 (Unauth Modbus) → Control physical process
    → Safety system bypass → Physical damage possible
```

**Combined Impact:** [Description of chained impact]
**Combined CVSS:** [Score reflecting chained impact]

---

## Recommendations

### Immediate (Fix within 1 week)
1. **[Finding ID]:** [Brief description of fix]
2. **[Finding ID]:** [Brief description of fix]

### Short-Term (Fix within 1 month)
1. **[Finding ID]:** [Brief description of fix]
2. **[Finding ID]:** [Brief description of fix]

### Long-Term (Fix within 3 months)
1. **[Finding ID]:** [Brief description of fix]
2. [Architectural improvements]

### Security Architecture Recommendations
1. [Network segmentation]
2. [Secure boot implementation]
3. [Firmware signing]
4. [Protocol security (DDS security, MQTT TLS)]
5. [Safety controller independence]

---

## Appendices

### Appendix A: Tool Output
[Full checksec output, binwalk output, etc.]

### Appendix B: File Inventory
[Complete list of analyzed files]

### Appendix C: String Analysis
[Relevant strings found]

### Appendix D: CVE Cross-Reference
[Full CVE matching results]
```

---

## Severity Assessment

### CVSS v3.1 Scoring

| Metric Group | Metric | Values |
|-------------|--------|--------|
| **Attack Vector (AV)** | | Network (N) / Adjacent (A) / Local (L) / Physical (P) |
| **Attack Complexity (AC)** | | Low (L) / High (H) |
| **Privileges Required (PR)** | | None (N) / Low (L) / High (H) |
| **User Interaction (UI)** | | None (N) / Required (R) |
| **Scope (S)** | | Unchanged (U) / Changed (C) |
| **Confidentiality (C)** | | None (N) / Low (L) / High (H) |
| **Integrity (I)** | | None (N) / Low (L) / High (H) |
| **Availability (A)** | | None (N) / Low (L) / High (H) |

### CVSS Quick Reference for Common Firmware Findings

| Finding Type | Typical CVSS | Typical Vector |
|-------------|-------------|----------------|
| Hardcoded root password (network) | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Hardcoded password (physical) | 6.8 | AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stack overflow (network service) | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stack overflow (local binary) | 7.8 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Command injection (web) | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Unsigned firmware update | 8.1 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Unauthenticated protocol | 8.6 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Weak encryption | 5.9 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Debug interface exposed | 6.8 | AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Outdated library (known CVE) | Varies | Use CVE's original CVSS |

### Safety Impact Dimension

Standard CVSS does not account for physical safety. Add a safety dimension:

| Safety Level | Criteria | Examples |
|-------------|----------|---------|
| **Critical** | Direct risk of physical injury or death | E-stop bypass, safety controller compromise, uncontrolled robot motion |
| **High** | Risk of robot damage or indirect physical harm | Speed limit override, trajectory injection, force limit bypass |
| **Medium** | Operational safety degradation | Safety monitoring DoS, sensor data corruption, watchdog defeat |
| **Low** | Minimal safety impact | Safety config exposure, non-critical sensor spoof |
| **None** | No safety relevance | Web UI XSS, information disclosure of non-safety data |

**Combined severity** = max(CVSS severity, Safety severity)

A finding with CVSS 5.0 (Medium) but Safety Impact Critical should be treated as **Critical**.

---

## CWE Mapping

### Common Firmware CWEs

| CWE | Name | Typical Finding |
|-----|------|----------------|
| **CWE-120** | Buffer Copy without Checking Size | strcpy/gets buffer overflow |
| **CWE-134** | Use of Externally-Controlled Format String | printf(user_input) |
| **CWE-259** | Use of Hard-coded Password | Default/embedded passwords |
| **CWE-306** | Missing Authentication for Critical Function | Unauthenticated Modbus/MQTT |
| **CWE-311** | Missing Encryption of Sensitive Data | Plaintext protocols |
| **CWE-326** | Inadequate Encryption Strength | Weak cipher suites, short keys |
| **CWE-327** | Use of a Broken or Risky Crypto Algorithm | DES, RC4, MD5 for auth |
| **CWE-494** | Download of Code Without Integrity Check | Unsigned firmware update |
| **CWE-521** | Weak Password Requirements | No password complexity |
| **CWE-693** | Protection Mechanism Failure | Missing NX/ASLR/canary |
| **CWE-732** | Incorrect Permission Assignment | World-writable sensitive files |
| **CWE-798** | Use of Hard-coded Credentials | Embedded API keys, certs |
| **CWE-1188** | Insecure Default Initialization | Debug enabled by default |
| **CWE-1233** | Security-Sensitive Hardware Controls | JTAG/SWD left enabled |

### Robot-Specific CWE Extensions

| Finding | Closest CWE | Safety Mapping |
|---------|------------|----------------|
| Safety parameter tampering | CWE-306 + Safety | IEC 62443, ISO 13849 |
| Trajectory injection | CWE-306 + CWE-20 | Robot physical safety |
| E-stop bypass | CWE-693 + Safety | IEC 61508 SIL violation |
| Sensor data spoofing | CWE-345 + Safety | Robot situational awareness |
| Watchdog defeat | CWE-693 + Safety | Functional safety violation |
| Safety controller DoS | CWE-400 + Safety | Safety function loss |

---

## Remediation Guidance

### Secure Boot and Firmware Signing

```
Priority: HIGH
Findings addressed: Unsigned firmware updates (CWE-494)

Recommendations:
1. Implement cryptographic firmware signing (RSA-2048+ or ECDSA P-256+)
2. Verify signature in bootloader before executing firmware
3. Use a hardware root of trust (TPM, secure element) for key storage
4. Implement anti-rollback protection (version counter in OTP fuse)
5. Sign all firmware components (kernel, rootfs, application)
```

### Memory Protection

```
Priority: HIGH
Findings addressed: Buffer overflows (CWE-120), missing mitigations (CWE-693)

Recommendations:
1. Enable NX (non-executable stack/heap) — requires MMU
2. Enable stack canaries (-fstack-protector-strong)
3. Enable ASLR where OS supports it
4. Compile with -D_FORTIFY_SOURCE=2
5. Use AddressSanitizer during development
6. Replace unsafe functions (strcpy→strlcpy, sprintf→snprintf)
```

### Credential Management

```
Priority: CRITICAL
Findings addressed: Hardcoded credentials (CWE-798, CWE-259)

Recommendations:
1. Remove all hardcoded passwords from firmware
2. Generate unique credentials per device during provisioning
3. Require password change on first boot
4. Store credentials hashed with strong KDF (argon2id, bcrypt)
5. Implement certificate-based authentication where possible
6. Use hardware secure element for key storage
```

### Network Security

```
Priority: HIGH
Findings addressed: Unauthenticated protocols (CWE-306), missing encryption (CWE-311)

Recommendations:
1. Enable TLS for all network services (MQTT → port 8883, HTTP → HTTPS)
2. Implement authentication for Modbus/CAN/industrial protocols
3. Enable DDS security plugins (authentication, encryption, access control)
4. Enable SROS2 with Enforce strategy
5. Implement network segmentation (robot control network isolated)
6. Disable unnecessary services (Telnet, FTP, debug ports)
7. Implement firewall rules (iptables/nftables)
```

### Protocol Security

```
Priority: HIGH
Findings addressed: Protocol-specific vulnerabilities

MQTT:
- Set allow_anonymous false
- Configure ACL per topic
- Enable TLS (port 8883)
- Use MQTT v5 with enhanced authentication

DDS/ROS2:
- Enable DDS Security plugins
- Configure SROS2 with Enforce strategy
- Restrict DDS domain access
- Use signed governance/permissions

Modbus:
- Add application-layer authentication
- Use Modbus/TCP Security (TLS)
- Restrict register access by client
- Monitor for unauthorized write operations

CAN:
- Implement CAN message authentication (AUTOSAR SecOC or similar)
- Monitor for anomalous arbitration IDs
- Implement intrusion detection
```

### Safety-Critical Code Protection

```
Priority: CRITICAL
Findings addressed: Safety system vulnerabilities

Recommendations:
1. Isolate safety controller on independent hardware (separate CPU)
2. Implement hardware e-stop (not software-only)
3. Use certified safety PLC for safety functions (SIL-rated)
4. Protect safety parameters with hardware write protection
5. Implement safety communication protocols (PROFIsafe, CIP Safety, FSoE)
6. Regular safety integrity testing
7. Implement independent watchdog (IWDG, not software-fed only)
```

---

## Compliance Mapping

### IEC 62443 (Industrial Cybersecurity)

| IEC 62443 Requirement | Relevant Findings | Status |
|-----------------------|-------------------|--------|
| FR 1: Identification and Authentication | Hardcoded creds, unauthenticated protocols | Non-compliant |
| FR 2: Use Control | Missing access control | Non-compliant |
| FR 3: System Integrity | Unsigned firmware, missing checksec | Non-compliant |
| FR 4: Data Confidentiality | Plaintext protocols, weak crypto | Non-compliant |
| FR 5: Restricted Data Flow | No network segmentation | Non-compliant |
| FR 6: Timely Response to Events | No logging/monitoring | Non-compliant |
| FR 7: Resource Availability | DoS vulnerabilities | Non-compliant |

### NIST Cybersecurity Framework

| Function | Category | Relevant Findings |
|----------|----------|-------------------|
| Identify | Asset Management | Component inventory completed |
| Protect | Access Control | Hardcoded creds, unauthenticated access |
| Protect | Data Security | Missing encryption, weak crypto |
| Protect | Protective Technology | Missing NX/ASLR/canary |
| Detect | Anomalies and Events | No monitoring/logging |
| Respond | Response Planning | No incident response capability |
| Recover | Recovery Planning | Unsigned firmware allows recovery attack |

### OWASP IoT Top 10 (2018)

| # | Category | Relevant Findings |
|---|----------|-------------------|
| I1 | Weak/Guessable/Hardcoded Passwords | F-001: Hardcoded root password |
| I2 | Insecure Network Services | F-003: Unauthenticated Modbus |
| I3 | Insecure Ecosystem Interfaces | Web dashboard vulnerabilities |
| I4 | Lack of Secure Update Mechanism | F-004: Unsigned firmware update |
| I5 | Use of Insecure/Outdated Components | Outdated OpenSSL, BusyBox |
| I6 | Insufficient Privacy Protections | Plaintext sensor/camera data |
| I7 | Insecure Data Transfer/Storage | Plaintext protocols, weak crypto |
| I8 | Lack of Device Management | No remote management security |
| I9 | Insecure Default Settings | Debug enabled, default creds |
| I10 | Lack of Physical Hardening | JTAG/UART exposed |

### RIA TR R15.606 (Robot Cybersecurity)

| Requirement | Relevant Findings | Notes |
|------------|-------------------|-------|
| Authentication | Missing auth on control interfaces | Robot-specific |
| Authorization | No access control for motion commands | Robot-specific |
| Integrity | Unsigned firmware, no secure boot | Robot-specific |
| Confidentiality | Plaintext robot programs and data | Robot-specific |
| Safety integration | Safety controller not isolated | Robot-specific |
| Incident response | No logging or monitoring | Robot-specific |
