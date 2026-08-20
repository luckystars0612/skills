---
name: picus-threat-yaml
description: >
  Comprehensive skill for creating, validating, and structuring custom threat YAML files
  for the Picus Security Platform Threat Library. Use this skill whenever the user wants
  to create a custom threat, write a threat.yaml, build a threat archive (ZIP), define
  attack campaigns, configure objectives or actions, set MITRE ATT&CK tactics/techniques,
  configure remote files or play_processes, or package a custom threat for Picus SCV.
  Also trigger when the user asks about threat modules, categories, UKC phases, result
  conditions, or any Picus-specific field values. Always use this skill for anything
  related to Picus threat authoring — even if the user just says "create a threat" or
  "write a threat file".
  Also use this skill when the user provides a Splunk SPL rule, a Sigma rule, or a
  plain-text goal and wants an import-ready Picus campaign generated automatically.
---

# Picus Custom Threat YAML Skill

A complete guide for authoring, structuring, and packaging custom threats for the Picus
Security Continuous Validation (SCV) platform.

---

## Workflow Overview

When a user asks to create a custom threat, follow this sequence:

1. **Gather intent** — ask which attack module and what the threat should simulate
2. **Choose the module** → load the correct reference section for that module
3. **Draft the threat.yaml** — use the templates and field rules below
4. **Validate** — check required fields, file path consistency, result_condition references
5. **Package** — give ZIP instructions with the correct password

---

## Rule-to-Threat Generation (auto-pipeline)

When the user provides a **detection rule or a plain-text goal** — not raw YAML —
use the auto-pipeline below. This is the recommended path for users who want to
turn an existing detection rule into a Picus threat without hand-writing the YAML.

### Accepted input formats

The skill auto-detects the format and routes through the correct parser:

| Input | How it is detected | Parser |
|---|---|---|
| **Splunk SPL** | `index=...`, `sourcetype=...`, `\|`, `match(...)`, `stats ` | `scripts/parse_spl.py` |
| **Sigma rule** | `title:`, `logsource:`, `detection:` blocks | `scripts/parse_sigma.py` |
| **Plain-text goal** | anything else | `scripts/parse_goal.py` |

Detection is heuristic — see `scripts/detect_format.py`.

### Pipeline

```
input (file path or pasted text)
  │
  ▼
scripts/detect_format.py        →  format = spl | sigma | goal
  │
  ▼
scripts/parse_<format>.py       →  list[ActionSpec] (JSON on stdout)
  │
  ▼
scripts/build_dropper.py        →  writes files/<name>.sh + computes
                                       SHA-256, SHA-1, MD5 of each dropper
  │
  ▼
scripts/build_threat.py         →  writes <campaign>/threat.yaml
  │
  ▼
scripts/package.py              →  AES-256-encrypted ZIP with password `picus`
```

### Direct CLI invocation

The skill provides a one-shot shell pipeline. Save the user's input as a file
(`/tmp/user-input.spl`) and run:

```bash
# Output campaign folder name (one word, no spaces recommended)
CAMPAIGN=linux-sensitive-file-access-via-shell
OUT=/tmp/$CAMPAIGN
rm -rf $OUT && mkdir -p $OUT/files

# 1. Detect format
FMT=$(python3 ~/.claude/skills/picus-threat-yaml/scripts/detect_format.py /tmp/user-input.spl)

# 2. Parse
python3 ~/.claude/skills/picus-threat-yaml/scripts/parse_${FMT}.py /tmp/user-input.spl \
  > /tmp/actions.json

# 3. Build droppers (writes files/<name>.sh) and capture hashes
python3 ~/.claude/skills/picus-threat-yaml/scripts/build_dropper.py \
  --actions-json /tmp/actions.json \
  --files-dir $OUT/files > /tmp/dropper-info.json

# 4. Merge hashes into actions
python3 -c '
import json
actions = json.load(open("/tmp/actions.json"))
drops = json.load(open("/tmp/dropper-info.json"))
for a in actions:
    d = drops[a["name"]]
    a["dropper_name"]  = d["dropper_name"]
    a["dropper_sha256"] = d["sha256"]
    a["dropper_sha1"]   = d["sha1"]
    a["dropper_md5"]    = d["md5"]
json.dump(actions, open("/tmp/actions-with-hashes.json", "w"), indent=2)
'

# 5. Build threat.yaml inside the campaign folder
python3 ~/.claude/skills/picus-threat-yaml/scripts/build_threat.py \
  --title "Linux Sensitive File Access via Shell" \
  --description "Detects shell access to /etc/shadow, /etc/passwd, ..." \
  --severity High \
  --actions-json /tmp/actions-with-hashes.json \
  --output $OUT/threat.yaml

# 6. Package as AES-256 encrypted ZIP (password: picus)
python3 ~/.claude/skills/picus-threat-yaml/scripts/package.py \
  --campaign $OUT \
  --output /tmp/$CAMPAIGN.zip

echo "Ready to import: /tmp/$CAMPAIGN.zip"
```

The output is a Picus-importable ZIP, password `picus`, containing:

```
/tmp/$CAMPAIGN/
    threat.yaml
    files/
        read_etc_shadow.sh
        read_etc_passwd.sh
        ...
```

### What the pipeline emits (in the YAML)

The skill generates a **structurally valid Linux Endpoint Scenario** threat matching
the PUMAKIT / BlackMatter canonical shape:

- Module: `Linux Endpoint Scenario`
- Severity: `High` by default
- One **objective per UKC phase** (Credential Access, Discovery, Persistence, …)
- Each action has:
  - the **16-distro Linux `affected_platforms` block** (canonical constant)
  - **action-level `result_condition`** with unquoted `true: unblocked / false: blocked`,
    a `Terms:` list, and `%process-1%`
  - **hash-based `keyword_queries`** with SHA-256, SHA-1, MD5, dropper name, target
    path, wrapped in `((((...))))` with the `AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf"))`
    tail
  - **`success_conditions.output:`** substring match (not `code: 0`)
  - **`rewind_processes`** to clear history and the dropper
- Campaign-level `result_condition` uses `Terms:` with `%objective-N%` references
- No `comment:` field, no redundant `delay: 0` / `is_async: false` / `is_inverse: false`
- Sub-technique is omitted from the YAML when empty

### Worked example (user's SPL input)

User input (`/tmp/user-input.spl`):

```spl
index=os_nix sourcetype=auditd type=EXECVE (a0="sh" OR a0="bash" OR a0="dash") a1="-c"
| where match(execve_command, "/etc/(shadow|passwd|gshadow)|/proc/net/|/\\.ssh/|authorized_keys|\\.bash_history")
| table _time host uid auid ppid comm exe execve_command
```

The pipeline produces 7 actions grouped into 3 objectives:

| Objective | Action | MITRE | UKC |
|---|---|---|---|
| Credential Access | `read_etc_shadow` | TA0006 / T1003.008 | Credential Access |
| Credential Access | `read_etc_gshadow` | TA0006 / T1003.008 | Credential Access |
| Credential Access | `read_bash_history` | TA0006 / T1552.003 | Credential Access |
| Discovery | `read_etc_passwd` | TA0007 / T1083 | Discovery |
| Discovery | `enumerate_proc_net` | TA0007 / T1016 | Discovery |
| Discovery | `list_ssh_directory` | TA0007 / T1083 | Discovery |
| Persistence | `read_ssh_authorized_keys` | TA0003 / T1098.004 | Persistence |

Each action has a hash-based `keyword_queries` entry, the 16-distro
`affected_platforms` block, and a working `success_conditions: - output: <substring>`.

### When NOT to use the auto-pipeline

- The user wants a non-Linux module (Windows / macOS / Kubernetes / Web / Cloud / …).
  The pipeline currently emits only `Linux Endpoint Scenario`. For other modules,
  fall back to the **hand-authoring workflow** below.
- The user wants to author a custom threat from scratch (no detection rule to
  start from).
- The user wants to edit an existing threat.yaml directly.

### Reference docs used by the pipeline

- `references/parsers/splunk-spl.md` — SPL grammar + extraction rules
- `references/parsers/sigma.md` — Sigma `detection.selection` field mapping
- `references/parsers/goal.md` — keyword extraction for plain-text goals
- `references/mappings/linux-targets.md` — file → MITRE / UKC / output table
- `references/mappings/linux-platforms.md` — the 16-distro block
- `references/mappings/output-patterns.md` — `success_conditions.output` picks
- `references/success-conditions.md` — what `output:` is and why not `code: 0`

### Examples

Three example inputs are in `examples/` — the user's SPL, a Sigma rule, and a
plain-text goal. Each one round-trips through the pipeline into a valid threat.

---

## Step 1 — Identify the Attack Module

Ask the user which module best fits. The module determines which fields and categories are available.

| Module | Best For |
|---|---|
| `Endpoint Scenario` | Windows process execution, lateral movement |
| `Linux Endpoint Scenario` | Linux process execution |
| `macOS Endpoint Scenario` | macOS process execution |
| `Kubernetes Endpoint Scenario` | Kubernetes cluster attacks |
| `File Download` | Delivering malicious file payloads via network |
| `Email` | Phishing attachments or URL delivery |
| `Web Application` | HTTP request-based attacks against web apps |
| `Data Exfiltration` | Simulating data theft scenarios |
| `URL Filtering` | Testing URL category filtering controls |
| `Azure Cloud Emulation` | Azure ARM / Entra ID / m365 attack steps |
| `AWS Cloud Emulation` | AWS attack command sequences |
| `GCP Cloud Emulation` | GCP attack command sequences |

**→ After choosing, read:** `references/modules/` for the module-specific field reference.

---

## Step 2 — ZIP Archive Structure

Every import (except standalone `.yaml` threats without remote files) must be a
**password-protected ZIP** with this exact layout:

```
<threat-name>/
    threat.yaml
    files/
        <payload-file-1>
        <payload-file-2>
        ...
```

Rules:
- Root folder name = threat name (no spaces recommended)
- `threat.yaml` must be at the root of that folder
- All payload files go inside `files/`
- The `file:` path in `remote_files` must match exactly (e.g., `files/payload.bin`)
- ZIP must be AES-256 encrypted with password **`picus`** (hard requirement)

> **Exception:** URL Filtering threats (no remote files) export/import as `.yaml` only.

---

## Step 3 — threat.yaml Structure

### Full Hierarchy

```yaml
campaign:
  name:               # required, unique per account, max 255 chars
  module:             # required — see Module list
  severity:           # High | Medium | Low
  description:        # optional, max 2000 chars
  affected_os:        # list: Windows | Linux | macOS | AWS | Azure | GCP
  threat_actor:       # optional, must match Picus-known name (e.g. APT29)
  affected_products:  # optional list of product names known to Picus
  comment:            # optional internal note, max 255 chars
  result_condition:   # optional, see Result Conditions section
  objectives:         # REQUIRED — at least one
    - type:           # free text (e.g. Collection, Execution, Discovery)
      result_condition:
      actions:        # REQUIRED — at least one per objective
        - name:       # internal ID, no spaces
          title:      # human-readable display name
          description:
          category:   # must match valid category for the module
          tactic:     # MITRE ATT&CK tactic ID (e.g. TA0002)
          technique:  # MITRE ATT&CK technique ID (e.g. T1059)
          sub_technique:
          ukc_phase:  # see UKC Phases list
          is_atomic:  # true | false
          affected_os:
          keyword_queries: []
          result_condition:
          # --- Module-specific fields below ---
          remote_files: []        # File Download, Email, Network, Data Exfil
          play_processes: []      # Endpoint modules only
          rewind_processes: []    # Endpoint modules only
          steps: []               # Cloud modules only
          rewind_steps: []        # Cloud modules only
          execution_methods: []   # Email only
          request_content:        # Web Application only
          filter_url:             # URL Filtering only
          url_category:           # URL Filtering only
          country:                # Data Exfiltration only
          data_type:              # Data Exfiltration only
```

---

## Step 4 — Result Conditions

Result conditions define pass/fail logic. They exist at **three levels**:
campaign → objective → action (endpoint only).

References use **positional notation** starting at 1:
- Campaign references objectives: `%objective-1%`, `%objective-2%`, …
- Objective references actions: `%action-1%`, `%action-2%`, …
- Action references processes: `%process-1%`, `%process-2%`, … (endpoint only)

**Template:**
```yaml
result_condition:
  "true": unblocked      # label when condition IS met
  "false": blocked       # label when condition is NOT met
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
    Operator: and        # "and" = all must pass | "or" = any must pass
```

> **Critical:** References must not exceed the count of actual items. If there are 2 actions,
> `%action-3%` will cause an import error.

---

## Step 5 — Remote Files

Used in: File Download, Email, Network Infiltration, Data Exfiltration.

```yaml
remote_files:
  - file: files/payload.exe      # path inside ZIP — MUST exist
    path: C:\Temp\payload.exe    # destination on simulated target
    is_executable: true
    is_downloaded: true
    skip_zip_extract: false      # set true if file is itself a zip
```

| Field | Required | Description |
|---|---|---|
| `file` | **Yes** | Path inside ZIP (must match exactly) |
| `path` | No | Destination filename on target system |
| `is_executable` | No | Whether the file is an executable |
| `is_downloaded` | No | Whether the file should be downloaded |
| `skip_zip_extract` | No | Skip extraction if file is a nested ZIP |

> **Tip:** If import fails due to filename encoding, use base64-encoded filenames —
> the backend decodes them automatically.

---

## Step 6 — Module-Specific Templates

**→ For full module templates and field details, read:**
- `references/modules/endpoint.md` — Endpoint / Linux / macOS / Kubernetes
- `references/modules/file-download-email-network.md` — File Download, Email, Network Infiltration
- `references/modules/web-cloud.md` — Web Application, Cloud Emulation, URL Filtering, Data Exfiltration

---

## Step 7 — Package as Password-Protected ZIP

**macOS / Linux:**
```bash
zip -r -P picus my_threat.zip <threat-name>/
```

**Windows (7-Zip):**
```bash
7z a -p"picus" -tzip my_threat.zip <threat-name>\
```

> **IMPORTANT:** Password must be exactly `picus`. Any other password → 400 error on import.

---

## Quick Reference — Accepted Values

**→ For complete accepted values tables, read:** `references/accepted-values.md`

### Module → Valid Categories (quick lookup)

| Module | Valid Categories |
|---|---|
| Endpoint Scenario | `Attack Scenario`, `Lateral Movement Techniques (Windows)` |
| Linux / macOS / Kubernetes Endpoint | `Attack Scenario` |
| Email | `Malicious Code`, `Vulnerability Exploitation` |
| File Download | `Malicious Code`, `Vulnerability Exploitation` |
| Web Application | `Web Application` |
| Data Exfiltration | `Data Exfiltration` |
| URL Filtering | `URL Filtering` |
| Azure Cloud Emulation | `Azure ARM`, `Azure Entra ID`, `Azure m365` |
| AWS Cloud Emulation | `AWS` |
| GCP Cloud Emulation | `GCP` |

### MITRE ATT&CK Tactic IDs (quick lookup)

`TA0001` Initial Access · `TA0002` Execution · `TA0003` Persistence ·
`TA0004` Privilege Escalation · `TA0005` Stealth · `TA0006` Credential Access ·
`TA0007` Discovery · `TA0008` Lateral Movement · `TA0009` Collection ·
`TA0010` Exfiltration · `TA0011` Command and Control · `TA0040` Impact ·
`TA0042` Resource Development · `TA0043` Reconnaissance · `TA0112` Defense Impairment

### Severity: `High` | `Medium` | `Low`

### Operating Systems: `Windows` | `Linux` | `macOS` | `AWS` | `Azure` | `GCP`

---

## Validation Checklist

Before handing off the threat.yaml to the user, verify:

- [ ] `name` is unique (no duplicates in their account)
- [ ] `module` matches one of the valid module strings exactly
- [ ] `category` on each action is valid for the chosen module
- [ ] `affected_os` values are from the accepted OS list
- [ ] Each `remote_files[].file` path matches a real file in `files/`
- [ ] Result condition references (`%action-1%` etc.) don't exceed the item count
- [ ] Endpoint actions have at least one `play_processes` entry with a `path`
- [ ] Web Application actions have `request_content` pointing to a file in the ZIP
- [ ] ZIP password is `picus` (remind the user)

---

## Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| `400 — invalid archive` | Wrong ZIP password or corrupt archive | Re-zip with `-P picus` / `-p"picus"` |
| `400 — missing threat.yaml` | `threat.yaml` not at root of the inner folder | Check ZIP structure — must be `<name>/threat.yaml` |
| `400 — invalid YAML` | Syntax error or missing required field | Check indentation, required fields (`name`, `module`, `objectives`, `actions`) |
| `File not found in archive` | `remote_files.file` path doesn't match | Ensure `file: files/payload.bin` matches actual ZIP path |
