# Accepted Values Reference

Complete lookup tables for all Picus threat YAML field values.

---

## Table of Contents

1. [Modules and Categories](#modules-and-categories)
2. [MITRE ATT&CK Tactics](#mitre-attck-tactics)
3. [UKC Phases](#ukc-phases)
4. [Severity](#severity)
5. [Operating Systems](#operating-systems)
6. [Platforms (affected_platforms)](#platforms)
7. [OWASP Categories](#owasp-categories)
8. [URL Categories](#url-categories)
9. [Vulnerability Types](#vulnerability-types)
10. [Countries (Data Exfiltration)](#countries)
11. [Data Types](#data-types)
12. [Use Cases](#use-cases)
13. [Picus-Maintained Values](#picus-maintained-values)

---

## Modules and Categories

Each campaign belongs to one module. The `category` field on each action must match
one of the categories allowed for that module.

| Module | Valid Categories |
|---|---|
| `Endpoint Scenario` | `Attack Scenario`, `Lateral Movement Techniques (Windows)` |
| `Linux Endpoint Scenario` | `Attack Scenario` |
| `macOS Endpoint Scenario` | `Attack Scenario` |
| `Kubernetes Endpoint Scenario` | `Attack Scenario` |
| `Email` | `Malicious Code`, `Vulnerability Exploitation` |
| `File Download` | `Malicious Code`, `Vulnerability Exploitation` |
| `Web Application` | `Web Application` |
| `Data Exfiltration` | `Data Exfiltration` |
| `URL Filtering` | `URL Filtering` |
| `Azure Cloud Emulation` | `Azure ARM`, `Azure Entra ID`, `Azure m365` |
| `AWS Cloud Emulation` | `AWS` |
| `GCP Cloud Emulation` | `GCP` |

---

## MITRE ATT&CK Tactics

> The `tactic` field uses **IDs**, not names.

| ID | Tactic Name |
|---|---|
| `TA0001` | Initial Access |
| `TA0002` | Execution |
| `TA0003` | Persistence |
| `TA0004` | Privilege Escalation |
| `TA0005` | Stealth |
| `TA0006` | Credential Access |
| `TA0007` | Discovery |
| `TA0008` | Lateral Movement |
| `TA0009` | Collection |
| `TA0010` | Exfiltration |
| `TA0011` | Command and Control |
| `TA0040` | Impact |
| `TA0042` | Resource Development |
| `TA0043` | Reconnaissance |
| `TA0112` | Defense Impairment |

> `technique` and `sub_technique` also use MITRE ATT&CK IDs (e.g., `T1059`, `T1059.001`).
> Full catalog: https://attack.mitre.org — values must match IDs known to Picus.

---

## UKC Phases

Used in the `ukc_phase` field on actions.

| Phase |
|---|
| `Collection` |
| `Command & Control` |
| `Credential Access` |
| `Defense Evasion` |
| `Delivery` |
| `Discovery` |
| `Execution` |
| `Exfiltration` |
| `Exploitation` |
| `Impact` |
| `Lateral Movement` |
| `Objectives` |
| `Persistence` |
| `Pivoting` |
| `Privilege Escalation` |
| `Reconnaissance` |
| `Social Engineering` |
| `Weaponization` |

---

## Severity

Used in the `severity` field at campaign level.

| Value |
|---|
| `High` |
| `Medium` |
| `Low` |

---

## Operating Systems

Used in `affected_os` at both campaign and action level.

| Value |
|---|
| `Windows` |
| `Linux` |
| `macOS` |
| `AWS` |
| `Azure` |
| `GCP` |

---

## Platforms

Used in the `affected_platforms` field on actions. Each entry requires `name` and `architecture`.

```yaml
affected_platforms:
  - name: "Windows 10"
    architecture: "64-bit"
  - name: "Ubuntu 22.04"
    architecture: "64-bit"
```

### Windows Platforms

| Name | Architecture |
|---|---|
| `Windows 7` | `32-bit`, `64-bit` |
| `Windows 8.1` | `32-bit`, `64-bit` |
| `Windows 10` | `32-bit`, `64-bit` |
| `Windows 11` | `64-bit` |
| `Windows Server` | `64-bit` |
| `Windows Server 2008` | `32-bit`, `64-bit` |
| `Windows Server 2008 R2` | `32-bit`, `64-bit` |
| `Windows Server 2012` | `64-bit` |
| `Windows Server 2012 R2` | `64-bit` |
| `Windows Server 2016` | `64-bit` |
| `Windows Server 2019` | `64-bit` |
| `Windows Server 2022` | `64-bit` |
| `Windows Server 2025` | `64-bit` |

### Linux Platforms

| Name | Architecture |
|---|---|
| `Alpine 3.15` — `Alpine 3.22` | `64-bit` |
| `CentOS 7` — `CentOS 9` | `32-bit`, `64-bit` |
| `Debian 9` — `Debian 12` | `32-bit`, `64-bit` |
| `Red Hat Enterprise Linux 7` — `RHEL 10` | `32-bit`, `64-bit` |
| `Rocky Linux 8` — `Rocky Linux 9` | `32-bit`, `64-bit` |
| `SUSE 15`, `SUSE 15.1` — `SUSE 15.7` | `64-bit` |
| `Ubuntu 18.04` — `Ubuntu 24.04` | `32-bit`, `64-bit` |

### macOS Platforms

| Name | Architecture |
|---|---|
| `MacOS 11 Big Sur` | `64-bit` |
| `MacOS 12 Monterey` | `64-bit` |
| `MacOS 13 Ventura` | `64-bit` |
| `MacOS 14 Sonoma` | `64-bit` |
| `MacOS 15 Sequoia` | `64-bit` |
| `MacOS 26 Tahoe` | `64-bit` |

---

## OWASP Categories

Used in the `owasp` field on actions (primarily Web Application module).

| Category |
|---|
| `Broken Access Control` |
| `Cryptographic Failures` |
| `Identification and Authentication Failures` |
| `Injection` |
| `Insecure Design` |
| `Security Logging and Monitoring Failures` |
| `Security Misconfiguration` |
| `Server-Side Request Forgery (SSRF)` |
| `Software and Data Integrity Failures` |
| `Vulnerable and Outdated Components` |

---

## URL Categories

Used in the `url_category` field (URL Filtering module).

| Category | Category | Category |
|---|---|---|
| `Abuse` | `Hacking` | `Scam` |
| `Ads` | `Jobsearch` | `Shopping` |
| `Adult` | `Malware` | `Socialmedia` |
| `Chat` | `News` | `Sports` |
| `Command & Control` | `Piracy` | `Storage` |
| `Crypto` | `Redirect` | `Torrent` |
| `Dating` | | `Tracking` |
| `Drugs` | | `Travelling` |
| `Economy` | | `Weapons` |
| `Education` | | |
| `Entertainment` | | |
| `Fraud` | | |
| `Gambling` | | |
| `Games` | | |

---

## Vulnerability Types

Used in the `vulnerability_type` field on actions.

| Type |
|---|
| `Buffer Overflow` |
| `Code Execution` |
| `Denial of Service` |
| `File Disclosure` |
| `Information Disclosure` |
| `Input Manipulation` |
| `Memory Corruption` |
| `Privilege Escalation` |
| `Sandbox Bypass` |

---

## Countries

Used in the `country` field (Data Exfiltration module only).

| Country |
|---|
| `Australia` |
| `Brazil` |
| `Canada` |
| `Generic` |
| `Germany` |
| `India` |
| `Italy` |
| `Malaysia` |
| `Mexico` |
| `Qatar` |
| `Singapore` |
| `Spain` |
| `Turkey` |
| `United Arab Emirates` |
| `United Kingdom` |
| `United State of America` |

---

## Data Types

Used in the `data_type` field (Data Exfiltration module only).

| Data Type |
|---|
| `IBAN` |
| `ITIN` (Individual Taxpayer Identification Number) |
| `NINO` (National Insurance Number) |
| `Other` |
| `PCI` (Payment Card Industry) |
| `PII` (Personally Identifiable Information) |
| `SAM` (Security Account Manager Database) |
| `SIN` (Social Insurance Number) |
| `Source Code` |
| `SSN` (Social Security Number) |
| `TFN` (Tax File Number) |
| `UTR` (Unique Taxpayer Reference) |

---

## Use Cases

Used in the `use_case` field on actions.

| Use Case |
|---|
| `Known Vulnerability` |
| `Portscan` |
| `Sensitive Data Exposure` |
| `Service Exploit` |
| `Vulnerability Scanning Tool` |
| `Web Shell Backdoor` |
| `WebServer Attack - Buffer Overflow` |
| `WebServer Attack - CMS` |
| `WebServer Attack - Deserialization` |
| `WebServer Attack - DoS` |
| `WebServer Attack - File Inclusion` |
| `WebServer Attack - Injection` |
| `WebServer Attack - Path Traversal` |
| `WebServer Attack - Pollution` |
| `WebServer Attack - Protocol Anomaly / Violation` |
| `WebServer Attack - RCE` |
| `WebServer Attack - RFD` |
| `WebServer Attack - Security Misconfiguration` |
| `WebServer Attack - SQL Injection` |
| `WebServer Attack - SSRF` |
| `WebServer Attack - Unauthorized Access` |
| `WebServer Attack - Unvalidated Redirect` |
| `WebServer Attack - XSS` |
| `WebServer Attack - XXE` |
| `WebServer Vulnerability Probing - SQL Injection` |
| `WebServer Vulnerability Probing - XSS` |

---

## Picus-Maintained Values

The following fields accept values from lists maintained by Picus. Values may change
over time — use the export feature on a similar existing threat to discover current values.

| Field | Examples |
|---|---|
| `threat_actor` | `APT29`, `Lazarus Group`, `FIN7`, `Turla`, `APT28`, `Kimsuky` |
| `affected_products` (campaign) | `Microsoft Windows`, `Apache Tomcat`, `FortiOS` |
| `affected_product` (action) | Same list as above |
| `malware_family` | `Cobalt Strike`, `Emotet`, `TrickBot`, `Ryuk`, `Mimikatz` |
| `technique` | MITRE ATT&CK IDs: `T1059`, `T1566`, `T1003`, `T1021`, … |
| `sub_technique` | MITRE ATT&CK sub-IDs: `T1059.001`, `T1003.001`, `T1566.001`, … |

> **Tip:** If a value is rejected on import, export a similar existing threat and check
> the exact string used in its `threat.yaml`.
