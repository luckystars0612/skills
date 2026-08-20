# File Download / Email / Network Infiltration Module Reference

---

## File Download Module

**Valid categories:** `Malicious Code`, `Vulnerability Exploitation`

Used to simulate delivery of malicious files through network download channels.
Does **not** use `play_processes` — uses `remote_files` instead.

### File Download Action Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `remote_files` | No | List | Malicious file payloads. See Remote Files structure. |
| `keyword_queries` | No | List | Search terms for detection (SHA256, filename, etc.). |

### Full File Download Campaign Example

```yaml
campaign:
  name: Emotet Dropper Delivery Simulation
  module: File Download
  severity: High
  description: Simulates Emotet dropper delivery via HTTP file download.
  affected_os:
    - Windows
  malware_family: Emotet        # note: this is an action-level field too
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Initial Access
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
            - Right:
                Value: unblocked
              Left:
                Value: '%action-2%'
              Operator: eq
          Operator: and
      actions:
        - name: action_one
          title: Download Emotet Stage 1 Dropper
          affected_os:
            - Windows
          is_atomic: true
          ukc_phase: Delivery
          category: Malicious Code
          tactic: TA0001
          technique: T1566
          malware_family: Emotet
          keyword_queries:
            - (("<sha256_of_payload1>" OR "stage1_dropper.exe"))
          remote_files:
            - file: files/stage1_dropper.exe
              path: stage1_dropper.exe
              is_executable: true
              is_downloaded: true

        - name: action_two
          title: Download Emotet Stage 2 Loader
          description: Downloads the secondary stage loader module
          affected_os:
            - Windows
          is_atomic: true
          ukc_phase: Delivery
          category: Malicious Code
          tactic: TA0001
          technique: T1566
          malware_family: Emotet
          keyword_queries:
            - (("<sha256_of_payload2>" OR "stage2_loader.dll"))
          remote_files:
            - file: files/stage2_loader.dll
              path: stage2_loader.dll
              is_executable: false
              is_downloaded: true
```

---

## Email Infiltration Module

**Valid categories:** `Malicious Code`, `Vulnerability Exploitation`

Simulates phishing email delivery with either file attachments or malicious URLs.

### Email-Specific Action Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `execution_methods` | No | List | Delivery method. Accepted values: `Attachment`, `URL`. |
| `remote_files` | No | List | Attached files (malicious documents, executables). |

### Full Email Campaign Example

```yaml
campaign:
  name: Phishing Campaign — Malicious Office Macro
  module: Email
  severity: High
  description: Simulates a phishing email delivering a macro-laden Office document.
  affected_os:
    - Windows
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Initial Access
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
          Operator: and
      actions:
        - name: macro_doc_delivery
          title: Deliver Macro-Enabled Word Document
          description: Sends a phishing email with a .docm file as attachment
          affected_os:
            - Windows
          is_atomic: true
          ukc_phase: Delivery
          category: Malicious Code
          tactic: TA0001
          technique: T1566
          sub_technique: T1566.001
          execution_methods:
            - Attachment
          keyword_queries:
            - (("<sha256_of_doc>" OR "invoice_q3.docm"))
          remote_files:
            - file: files/invoice_q3.docm
              path: invoice_q3.docm
              is_downloaded: true
              is_executable: false

        - name: url_delivery
          title: Deliver Malicious URL via Email
          description: Sends phishing link redirecting to payload download
          is_atomic: true
          ukc_phase: Delivery
          category: Malicious Code
          tactic: TA0001
          technique: T1566
          sub_technique: T1566.002
          execution_methods:
            - URL
```

---

## Network Infiltration Module

Used for simulating malware delivery over a network connection without email.
Actions use `remote_files` to define the payload files.

### Network Infiltration Action Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `remote_files` | No | List | Malicious file payloads delivered over the network. |

### Full Network Infiltration Campaign Example

```yaml
campaign:
  name: Cobalt Strike Beacon Delivery
  module: Network Infiltration Attack
  severity: Critical
  description: Simulates delivery of a Cobalt Strike beacon over HTTP.
  affected_os:
    - Windows
  threat_actor: FIN7
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Command and Control
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
          Operator: and
      actions:
        - name: beacon_delivery
          title: Deliver Cobalt Strike Beacon
          is_atomic: true
          ukc_phase: Delivery
          category: Malicious Code
          tactic: TA0011
          technique: T1071
          malware_family: Cobalt Strike
          keyword_queries:
            - (("<sha256_of_beacon>" OR "beacon.exe" OR "CobaltStrike"))
          remote_files:
            - file: files/beacon.exe
              path: beacon.exe
              is_executable: true
              is_downloaded: true
```

---

## Remote Files — Common Patterns

### Binary executable
```yaml
remote_files:
  - file: files/payload.exe
    path: C:\Temp\payload.exe
    is_executable: true
    is_downloaded: true
```

### DLL / library
```yaml
remote_files:
  - file: files/inject.dll
    path: inject.dll
    is_executable: false
    is_downloaded: true
```

### Nested ZIP (skip extraction)
```yaml
remote_files:
  - file: files/archive.zip
    path: archive.zip
    is_downloaded: true
    skip_zip_extract: true
```

### Multiple files
```yaml
remote_files:
  - file: files/dropper.exe
    path: dropper.exe
    is_executable: true
    is_downloaded: true
  - file: files/config.dat
    path: config.dat
    is_downloaded: true
```
