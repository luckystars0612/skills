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
  Also use this skill when the user provides a Splunk SPL rule, a Sigma rule, a plain-text
  goal, or a real-world threat / CVE / malware description and wants an import-ready Picus
  campaign generated automatically.
---

# Picus Custom Threat YAML Skill

A complete guide for authoring, structuring, and packaging custom threats for the Picus
Security Continuous Validation (SCV) platform.

This is a **skill for an AI agent**. It supplies the context — canonical YAML shapes,
canonical worked examples, field vocabularies, module invariants, packaging rules — so
the agent can hand-author any threat for any module on demand. The user may ask the
agent to build a binary sample, compute hashes, generate base64 filenames, write
`success_conditions`, package the ZIP, or do anything else threat-related. The agent
has the full context here to act.

---

## Quick start

When the user asks for a threat:

1. **Identify the module** — see [Module index](#module-index--reference-docs).
2. **Read the per-module reference doc** + canonical example listed in that index.
3. **Hand-author `threat.yaml`** using the module's invariants, field inventory, and
   keyword-queries template.
4. **Build the payload** (binary, PDF, `.req`, sample data) and drop it in `files/`.
5. **Validate** — see [Validation Checklist](#validation-checklist) at the bottom.
6. **Package** — AES-256-encrypted ZIP with password `picus`.

If the input is a Splunk SPL / Sigma rule / plain-text goal AND the module is
**Linux Endpoint** or **Windows Endpoint**, you can use the [auto-pipeline](#auto-pipeline-linux--windows-endpoint-only)
as a shortcut. For every other module, hand-authoring is the only path.

---

## Module index — reference docs

The per-module docs are canonical, derived from real Picus threats under
`~/Desktop/picus-threats/`. **Open the doc that matches the user's chosen module and
read it before authoring.**

| Module | Reference doc | Canonical example threat |
|---|---|---|
| `Endpoint Scenario` (Windows) / `Linux Endpoint Scenario` | [endpoint.md](references/modules/endpoint.md) | Linux-sensitive-file canonical examples in [endpoint.md](references/modules/endpoint.md) |
| `macOS Endpoint Scenario` | [macos-endpoint.md](references/modules/macos-endpoint.md) | [Realst Infostealer Campaign](../../../Desktop/picus-threats/Realst%20Infostealer%20Campaign/threat.yaml) |
| `Kubernetes Endpoint Scenario` | [kubernetes-endpoint.md](references/modules/kubernetes-endpoint.md) | [Command and Control Kubernetes Micro Emulation Plan](../../../Desktop/picus-threats/Command%20and%20Control%20Kubernetes%20Micro%20Emulation%20Plan/threat.yaml) |
| `File Download` | [file-download.md](references/modules/file-download.md) | [CRPX0 Ransomware Download Threat](../../../Desktop/picus-threats/CRPX0%20Ransomware%20Download%20Threat/threat.yaml) |
| `Email` | [email.md](references/modules/email.md) | [ChainDrop Malware Dropper Email Threat](../../../Desktop/picus-threats/ChainDrop%20Malware%20Dropper%20Email%20Threat/threat.yaml) |
| `Web Application` | [web-application.md](references/modules/web-application.md) | [Generic XSS Evasion Web Attack Campaign - 14](../../../Desktop/picus-threats/Generic%20XSS%20Evasion%20Web%20Attack%20Campaign%20-%2014/threat.yaml) |
| `Data Exfiltration` | [data-exfiltration.md](references/modules/data-exfiltration.md) | [PDF Format Data Exfiltration Campaign](../../../Desktop/picus-threats/PDF%20Format%20Data%20Exfiltration%20Campaign/threat.yaml) |
| `URL Filtering` | [url-filtering.md](references/modules/url-filtering.md) | no canonical example under `~/Desktop/picus-threats/` — see doc for template |
| `Azure / AWS / GCP Cloud Emulation` | [cloud-emulation.md](references/modules/cloud-emulation.md) | no canonical example under `~/Desktop/picus-threats/` — see doc for template |

**The skill author itself, not the auto-pipeline, is the source of truth for every
module above.** The reference docs contain: field inventory with real values, canonical
keyword-queries template, real worked example, differences vs other modules, and a
module-specific authoring checklist. Read the doc, follow the checklist, ship the
threat.

---

## Workflow

### Step 1 — Identify the attack module

Ask the user if unclear. The module determines which fields, categories, UKC phases,
keyword-queries noise filters, and packaging conventions apply.

| Module | Best for |
|---|---|
| `Endpoint Scenario` | Windows process execution, lateral movement |
| `Linux Endpoint Scenario` | Linux process execution |
| `macOS Endpoint Scenario` | macOS process execution |
| `Kubernetes Endpoint Scenario` | Attacks on a Kubernetes node (Linux process execution, K8s routing) |
| `File Download` | Delivering malicious file payloads via network |
| `Email` | Phishing attachments or URL delivery |
| `Web Application` | HTTP request-based attacks against web apps |
| `Data Exfiltration` | Simulating data theft scenarios (typically file uploads) |
| `URL Filtering` | Testing URL category filtering controls |
| `Azure Cloud Emulation` | Azure ARM / Entra ID / m365 attack steps |
| `AWS Cloud Emulation` | AWS attack command sequences |
| `GCP Cloud Emulation` | GCP attack command sequences |

After choosing, **read the matching reference doc from the [index](#module-index--reference-docs)**.

### Step 2 — Hand-author `threat.yaml`

Use the reference doc for that module. Every doc includes:

1. **Module invariants table** — fields that are constant across every action.
2. **Campaign/objective/action shape** — the literal YAML skeleton.
3. **Field inventory** — every field with required/optional and an example value.
4. **Substructure docs** — `play_processes` steps, `remote_files` encoding, `.req` format,
   etc.
5. **Keyword-queries canonical template** — the exact boolean expression to emit.
6. **Real worked example** — copy/adapt this for the user's threat.
7. **Authoring checklist** — verify before packaging.

The agent is responsible for:

- Picking MITRE ATT&CK tactic / technique / sub-technique IDs that match the user's intent.
- Computing SHA-256 / SHA-1 / MD5 of any binary payload.
- Encoding on-disk filenames as `files/<base64(MD5)>___<base64(UUID)>.<ext>`.
- Writing `success_conditions` (substring output matches) and `result_condition` (pass/fail logic).
- Building the payload itself: shell scripts, `.bat` files, ELF binaries, dropper chains,
  PDF samples, HTTP request bodies, etc. — the user wants the agent to produce these.

### Step 3 — Build the payload files

Whatever the action needs, drop it in `<threat-name>/files/`. Conventions:

- **Endpoint (Linux/Windows/macOS/K8s):** dropper shell script or compiled binary.
- **File Download / Email:** malicious binary in `files/`; on-disk filename is
  `files/<base64(MD5)>___<base64(UUID)>.<ext>` to dodge filesystem encoding issues.
- **Web Application:** HTTP request body in `files/<digits>.req` with the mandatory
  `/page{PICUSID}/…` placeholder.
- **Data Exfiltration:** realistic-looking PDF in `files/<base64(NUMERIC_ID)>___<base64(UUID)>.pdf`.
- **URL Filtering:** no payload (`.yaml`-only export).

### Step 4 — Validate

See [Validation Checklist](#validation-checklist).

### Step 5 — Package as AES-256-encrypted ZIP

```
<threat-name>/
    threat.yaml
    files/
        <payload-file-1>
        ...
```

**macOS / Linux (system `zip` only does ZipCrypto — Picus rejects it):**

```bash
7z a -tzip -mem=AES256 -p"picus" my_threat.zip <threat-name>/
```

**Windows (7-Zip):**

```bash
7z a -tzip -mem=AES256 -p"picus" my_threat.zip <threat-name>\
```

> **Password must be exactly `picus`. Any other password → 400 error on import.**

> **Exception:** URL Filtering threats (no `files/`) export/import as `.yaml` only.

---

## Auto-pipeline (Linux + Windows Endpoint only)

When the user provides a **detection rule or a plain-text goal** — not raw YAML — for
**Linux Endpoint** or **Windows Endpoint**, the auto-pipeline turns it into an
import-ready ZIP without hand-writing the YAML. For every other module, use the
[hand-authoring workflow](#step-2--hand-author-threatyaml).

### Accepted input formats

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

```bash
CAMPAIGN=linux-sensitive-file-access-via-shell
OUT=/tmp/$CAMPAIGN
rm -rf $OUT && mkdir -p $OUT/files
MODULE=linux

FMT=$(python3 ~/.claude/skills/picus-threat-yaml/scripts/detect_format.py /tmp/user-input.spl)

python3 ~/.claude/skills/picus-threat-yaml/scripts/parse_${FMT}.py \
  --module $MODULE /tmp/user-input.spl > /tmp/actions.json

python3 ~/.claude/skills/picus-threat-yaml/scripts/build_dropper.py \
  --actions-json /tmp/actions.json \
  --files-dir $OUT/files > /tmp/dropper-info.json

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

python3 ~/.claude/skills/picus-threat-yaml/scripts/build_threat.py \
  --module $MODULE \
  --title "Linux Sensitive File Access via Shell" \
  --description "Detects shell access to /etc/shadow, /etc/passwd, ..." \
  --severity High \
  --actions-json /tmp/actions-with-hashes.json \
  --output $OUT/threat.yaml

python3 ~/.claude/skills/picus-threat-yaml/scripts/package.py \
  --campaign $OUT \
  --output /tmp/$CAMPAIGN.zip

echo "Ready to import: /tmp/$CAMPAIGN.zip"
```

> **Windows variant.** Swap `MODULE=windows`. The pipeline produces an `Endpoint Scenario`
> threat with the 6-distro Windows `affected_platforms` block, the Windows
> `keyword_queries` AND-NOT clause, and per-target `play_processes` (e.g. `reg.exe add …`,
> `vssadmin Delete Shadows /All /Quiet`). Dropper extension defaults to `.bat`.

### When to use the auto-pipeline

- Input is SPL / Sigma / goal text.
- Module is **Linux Endpoint Scenario** or **Windows Endpoint Scenario** (Endpoint Scenario).
- User wants the full pipeline (dropper scripts, hashes, ZIP) generated automatically.

### When NOT to use the auto-pipeline

- Module is anything other than Linux/Windows Endpoint: **macOS Endpoint, Kubernetes
  Endpoint, File Download, Email, Web Application, Data Exfiltration, URL Filtering, or
  any Cloud Emulation**. Use hand-authoring + the matching per-module reference doc.
- The user wants to author from scratch (no detection rule, just a goal/intent).
- The user wants to edit an existing `threat.yaml` directly.

### Reference docs used by the auto-pipeline

- `references/parsers/splunk-spl.md` — SPL grammar + extraction rules
- `references/parsers/sigma.md` — Sigma `detection.selection` field mapping
- `references/parsers/goal.md` — keyword extraction for plain-text goals
- `references/mappings/linux-targets.md` — Linux file → MITRE / UKC / output table
- `references/mappings/linux-platforms.md` — the 16-distro Linux block
- `references/mappings/windows-targets.md` — Windows target → MITRE / UKC / output / play_template
- `references/mappings/windows-platforms.md` — the 6-distro Windows block
- `references/mappings/output-patterns.md` — `success_conditions.output` picks
- `references/success-conditions.md` — what `output:` is and why not `code: 0`

---

## Quick reference — shared concepts

These fields/conventions are common to most modules. **Always defer to the per-module
doc for module-specific shape, keywords, or noise filters.**

### `threat.yaml` top-level hierarchy

```yaml
campaign:
  name:               # required, unique per account, max 255 chars
  module:             # required — see Module list above
  severity:           # High | Medium | Low
  description:        # optional, max 2000 chars
  affected_os:        # list: Windows | Linux | macOS | AWS | Azure | GCP
  threat_actor:       # optional, must match Picus-known name (e.g. APT29)
  affected_products:  # optional list of product names known to Picus
  comment:            # optional internal note, max 255 chars
  result_condition:   # see Result Conditions
  objectives:         # REQUIRED — at least one
    - type:           # free text or umbrella category (K8s)
      result_condition:
      actions:        # REQUIRED — at least one per objective
        - name:
          title:              # module-specific (omit on macOS Endpoint)
          description:
          category:           # must match valid category for the module
          tactic:             # MITRE ATT&CK tactic ID (TAxxxx) — Endpoint modules
          technique:          # MITRE ATT&CK technique ID (Txxxx) — Endpoint modules
          sub_technique:      # optional MITRE sub-technique ID
          ukc_phase:          # see UKC Phases list
          is_atomic:
          affected_os:
          keyword_queries: []
          result_condition:
          # --- Module-specific fields ---
          remote_files: []        # File Download, Email, Data Exfil
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

### Result conditions

Result conditions define pass/fail logic at **three levels**: campaign → objective → action
(action-level is Endpoint-only, references processes).

References use **positional notation** starting at 1:

- Campaign references objectives: `%objective-1%`, `%objective-2%`, …
- Objective references actions: `%action-1%`, `%action-2%`, …
- Action references processes: `%process-1%`, `%process-2%`, … (Endpoint only)

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

> **Critical:** References must not exceed the count of actual items. If there are 2
> actions, `%action-3%` will cause an import error.

**Join operator per module:**

| Module | Campaign-level join | Action-level join |
|---|---|---|
| Endpoint Scenario (Windows) | `and` | `and` |
| Linux Endpoint Scenario | `and` | `and` |
| macOS Endpoint Scenario | `and` | `and` |
| Kubernetes Endpoint Scenario | **`or`** | `and` |
| File Download | `or` | (no action-level) |
| Email | `or` | (no action-level) |
| Web Application | `or` | (no action-level) |
| Data Exfiltration | `or` | (no action-level) |
| URL Filtering | `or` | (no action-level) |

### `remote_files`

Used in File Download, Email, Data Exfiltration, and Endpoint modules for dropper
payloads.

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
| `is_executable` | No | Whether the file is an executable (Endpoint modules; omit on File Download / Email / Data Exfil) |
| `is_downloaded` | No | Whether the file should be downloaded |
| `skip_zip_extract` | No | Skip extraction if file is a nested ZIP |

> **Tip:** If import fails due to filename encoding, use base64-encoded filenames —
> the backend decodes them automatically.

### Module → Valid categories

| Module | Valid categories |
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

### MITRE ATT&CK tactic IDs

`TA0001` Initial Access · `TA0002` Execution · `TA0003` Persistence ·
`TA0004` Privilege Escalation · `TA0005` Stealth · `TA0006` Credential Access ·
`TA0007` Discovery · `TA0008` Lateral Movement · `TA0009` Collection ·
`TA0010` Exfiltration · `TA0011` Command and Control · `TA0040` Impact ·
`TA0042` Resource Development · `TA0043` Reconnaissance · `TA0112` Defense Impairment

### Severity

`High` | `Medium` | `Low`

### Operating systems

`Windows` | `Linux` | `macOS` | `AWS` | `Azure` | `GCP`

### UKC phases

Collection · Command & Control · Credential Access · Defense Evasion · Delivery ·
Discovery · Execution · Exfiltration · Exploitation · Impact · Lateral Movement ·
Persistence · Privilege Escalation · Reconnaissance · Social Engineering · Weaponization

---

## Validation Checklist

Before handing off the `threat.yaml` to the user, verify:

- [ ] `name` is unique (no duplicates in their account)
- [ ] `module` matches one of the valid module strings exactly
- [ ] `category` on each action is valid for the chosen module (see table above)
- [ ] `affected_os` values are from the accepted OS list
- [ ] Each `remote_files[].file` path matches a real file in `files/`
- [ ] Each `request_content` path matches a real `.req` file in `files/` (Web Application)
- [ ] Result-condition references (`%action-1%`, `%objective-N%`, `%process-N%`) don't exceed the actual item count
- [ ] Result-condition join operator matches the module table above
- [ ] `keyword_queries` follows the canonical template for the module
- [ ] Module-specific AND-NOT noise filter is present and correct for the module
- [ ] Endpoint actions have at least one `play_processes` entry with a `path` or `arguments`
- [ ] File Download / Email actions have `remote_files[].is_downloaded: true`
- [ ] ZIP password is `picus` (AES-256 via `7z -mem=AES256 -tzip`)
- [ ] Module-specific items in the per-module reference doc's authoring checklist pass

---

## Common errors & fixes

| Error | Cause | Fix |
|---|---|---|
| `400 — invalid archive` | Wrong ZIP password or ZipCrypto (not AES-256) | Re-zip with `7z a -tzip -mem=AES256 -p"picus"` |
| `400 — missing threat.yaml` | `threat.yaml` not at root of the inner folder | Check ZIP structure — must be `<name>/threat.yaml` |
| `400 — invalid YAML` | Syntax error or missing required field | Check indentation, required fields (`name`, `module`, `objectives`, `actions`) |
| `File not found in archive` | `remote_files.file` path doesn't match | Ensure `file: files/payload.bin` matches actual ZIP path |
| Result condition reference error | `%action-N%` or `%objective-N%` exceeds item count | Renumber so max reference ≤ actual item count |
</content>
</invoke>