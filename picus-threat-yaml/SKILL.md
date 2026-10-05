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
5. **Validate** — run the checker, do not eyeball it:

   ```bash
   python3 ~/.claude/skills/picus-threat-yaml/scripts/validate_threat.py <campaign-dir>
   ```

   It enforces every rule measured from the live library (categories per module, UKC
   phases, MITRE tactic ids, platform pairs, `remote_files` placement, payload filename
   encoding, result-condition references, per-module `AND NOT` policy) and checks
   `malware_family` / `threat_actor` / `url_category` / `use_case` / `owasp` against
   Picus's real vocabularies. Exit code 0 means no errors. All 32 genuine Picus and
   local threats pass with zero errors; a deliberately broken threat trips 18 checks.
6. **Package** — AES-256-encrypted ZIP with password `picus`, then validate the archive
   itself: `validate_threat.py my_threat.zip`.

If the input is a Splunk SPL / Sigma rule / plain-text goal AND the module is
**Linux Endpoint** or **Windows Endpoint**, you can use the [auto-pipeline](#auto-pipeline-linux--windows-endpoint-only)
as a shortcut. For every other module, hand-authoring is the only path.

---

## Ground truth first

[**ground-truth-library.md**](references/ground-truth-library.md) holds counted facts from the
live library — all 7830 Picus-authored threats and all 31180 of their actions, measured
2026-10-05: value vocabularies, per-module `keyword_queries` templates with real frequencies,
which modules use an `AND NOT` filter, campaign shape norms, and the fields Picus sets that the
rest of this skill omits. **When this skill and that file disagree, that file wins.**

Alongside it:

| Reference | Contents |
|---|---|
| [detection.md](references/detection.md) | what "detection" means in Picus, how `keyword_queries` drives it, and the 5858-rule Detection Content catalog |
| [vocab-threat-actors.md](references/vocab-threat-actors.md) | all 206 `threat_actor` values **with aliases** |
| [vocab-malware-families.md](references/vocab-malware-families.md) | all 2233 `malware_family` values |
| [vocab-platforms.md](references/vocab-platforms.md) | all 92 `affected_platforms` name/architecture pairs |
| [vocab-file-types.md](references/vocab-file-types.md) | the 131 recognised payload extensions |
| [vocab-tags.md](references/vocab-tags.md) | the 258 `tags` values |
| [vocab-action-titles.md](references/vocab-action-titles.md) | the 52 title verbs Picus's own UI offers |

`scripts/vocab.json` holds the same vocabularies machine-readably; `validate_threat.py`
reads it, so a rejected value always names the reference file to look in.

---

## Module index — reference docs

The per-module docs are canonical, derived from real Picus threats. Worked examples are
bundled inside this skill under `references/examples/` (copied in — not a symlink or a
pointer out to a user's home directory — so the skill resolves on any machine it's
installed on). **Open the doc that matches the user's chosen module and read it before
authoring.**

| Module | Reference doc | Canonical example threat |
|---|---|---|
| `Endpoint Scenario` (Windows) / `Linux Endpoint Scenario` | [endpoint.md](references/modules/endpoint.md) | Linux-sensitive-file canonical examples inlined in [endpoint.md](references/modules/endpoint.md) |
| `macOS Endpoint Scenario` | [macos-endpoint.md](references/modules/macos-endpoint.md) | [Realst Infostealer Campaign](references/examples/Realst%20Infostealer%20Campaign/threat.yaml) |
| `Kubernetes Endpoint Scenario` | [kubernetes-endpoint.md](references/modules/kubernetes-endpoint.md) | [Command and Control Kubernetes Micro Emulation Plan](references/examples/Command%20and%20Control%20Kubernetes%20Micro%20Emulation%20Plan/threat.yaml) |
| `File Download` | [file-download.md](references/modules/file-download.md) | [CRPX0 Ransomware Download Threat](references/examples/CRPX0%20Ransomware%20Download%20Threat/threat.yaml) |
| `Email` | [email.md](references/modules/email.md) | [ChainDrop Malware Dropper Email Threat](references/examples/ChainDrop%20Malware%20Dropper%20Email%20Threat/threat.yaml) |
| `Web Application` | [web-application.md](references/modules/web-application.md) | [Generic XSS Evasion Web Attack Campaign - 14](references/examples/Generic%20XSS%20Evasion%20Web%20Attack%20Campaign%20-%2014/threat.yaml) — see the doc for 5 more real packages (ThinkPHP, Auth Bypass, Java Deserialization, Encoded URI, SharePoint) |
| `Data Exfiltration` | [data-exfiltration.md](references/modules/data-exfiltration.md) | [PDF Format Data Exfiltration Campaign](references/examples/PDF%20Format%20Data%20Exfiltration%20Campaign/threat.yaml) |
| `URL Filtering` | [url-filtering.md](references/modules/url-filtering.md) | [Ai Services - 7](references/examples/Ai%20Services%20-%207/threat.yaml) — exported from the live library; `.yaml` only, no `files/` |
| `Azure / AWS / GCP Cloud Emulation` | [cloud-emulation.md](references/modules/cloud-emulation.md) | no canonical example bundled — see doc for template |

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

Whatever the action needs, drop it in `<threat-name>/files/`.

> **The on-disk name is one base64 blob.** Picus stores a payload as
> `files/<base64("<name>___<uuid>.<ext>")>` — the `___` separator and the extension live
> *inside* the encoded string, and the `=` padding is kept. The encoded form never
> contains `___` and never carries a dot. Verified on 76/76 `remote_files[].file`
> entries in genuine Picus exports.
>
> ```python
> import base64, uuid
> plain = f"{md5_or_name}___{uuid.uuid4()}{ext}"   # ext includes the dot, or ""
> archive_name = base64.b64encode(plain.encode()).decode()   # keep the padding
> ```
>
> `scripts/profiles/base.py` exposes this as `picus_archive_name(name, ext)`.

Conventions:

- **Endpoint (Linux/Windows/macOS/K8s):** dropper shell script or compiled binary.
- **File Download / Email:** malicious binary in `files/`; the on-disk filename is a
  **single base64 blob** — `files/<base64("<md5>___<uuid>.<ext>")>`. The `___` and the
  extension are *inside* the encoded string. Verified 76/76 in real Picus exports.
  Keep the `=` padding. **Not** `<base64(MD5)>___<base64(UUID)>.<ext>`.
- **Web Application:** HTTP request body in `files/<digits>.req` with the mandatory
  `{PICUSID}` placeholder somewhere in the path (not necessarily its own `/page{PICUSID}/`
  segment — `/page{PICUSID}.htm` and `/loginpage{PICUSID}.htm` are both confirmed-valid forms,
  see [web-application.md](references/modules/web-application.md)) and **no `Host:` header**
  (the target host/port comes from the Picus assessment config, not the `.req` file).
- **Data Exfiltration:** realistic-looking PDF/XLSX in `files/<base64("<id>___<uuid>.<ext>")>`
  — one base64 blob, same rule as above.
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
scripts/build_dropper.py        →  writes files/<base64 blob> + computes
                                       SHA-256/SHA-1/MD5 and returns
                                       archive_name + drop_path so build_threat
                                       wires remote_files into the process
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
    a["archive_name"]   = d["archive_name"]   # base64 name inside the ZIP
    a["drop_path"]      = d["drop_path"]      # where it lands on the target
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

python3 ~/.claude/skills/picus-threat-yaml/scripts/validate_threat.py $OUT || exit 1

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
    - type:           # NOT free text — one of the 16 values Picus uses:
                      #   Delivery | Exploitation | Initial Access | Exfiltration |
                      #   Defense Evasion | Discovery | Execution | Credential Access |
                      #   Persistence | Collection | Command and Control | Impact |
                      #   Privilege Escalation | Lateral Movement | Reconnaissance | Network
                      # Note: "Command and Control" here, vs "Command & Control" for ukc_phase.
      result_condition:
      actions:        # REQUIRED — at least one per objective
        - name:
          title:              # Picus OMITS it on Endpoint Scenario (0/218), Linux Endpoint
                              #   (4/104) and macOS Endpoint (0/12). ALWAYS sets it on
                              #   Kubernetes (174/174), Email (175/175), File Download (77/77),
                              #   Data Exfiltration (174/174), Web Application (48/49).
                              #   URL Filtering: absent in the one sampled threat — unconfirmed.
          description:
          category:           # must match valid category for the module
          tactic:             # MITRE ATT&CK tactic ID (TAxxxx) — Endpoint modules
          technique:          # MITRE ATT&CK technique ID (Txxxx) — Endpoint modules
          sub_technique:      # optional MITRE sub-technique ID
          ukc_phase:          # see UKC Phases list
          is_atomic:
          is_applicable_to_all_platforms:   # set on EVERY Picus action, every module
          affected_os:
          keyword_queries: []               # list of PLAIN STRINGS in YAML (249/249 real actions)
          result_condition:
          # --- Module-specific fields ---
          remote_files: []        # File Download, Email, Data Exfil (action level)
          play_processes: []      # Endpoint modules only — see shape below
          rewind_processes: []    # Endpoint modules only
          #   each play_processes / rewind_processes entry accepts:
          #     path, arguments, timeout, delay, is_async,
          #     remote_files[], success_conditions[]
          #   `path` is often OMITTED on Linux/Kubernetes — whole command in `arguments`
          steps: []               # Cloud modules only
          rewind_steps: []        # Cloud modules only
          execution_methods: []   # Email only
          request_content:        # Web Application only
          filter_url:             # URL Filtering only
          url_category:           # URL Filtering only
          country:                # Data Exfiltration only
          data_type:              # Data Exfiltration only
          malware_family:         # Email, File Download (2233 valid values)
          use_case:               # Web Application only (27 valid values)
          affected_product:       # Web Application only (singular; action-level)
          affected_versions:      # Web Application only
          cve:                    # Web Application (e.g. CVE-2026-72898)
          cwe:                    # Web Application (lowercase prefix, e.g. cwe-89)
          owasp:                  # Web Application (98% of Picus Web App actions set it)
          is_wats_lite:           # Web Application only
          is_privileged:          # all Endpoint modules (Windows 16/24, Linux 14/25, macOS 4/12, K8s 1/17)
          comment:                # action-level note (Data Exfiltration, Web Application)
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

The **objective-level** operator mirrors the campaign operator in every verified export, and
the campaign `Terms` count always equals the objective count.

| Module | Campaign-level join | Objective-level join | Action-level join |
|---|---|---|---|
| Endpoint Scenario (Windows) | `and` | `and` | `and` |
| Linux Endpoint Scenario | `and` | `and` | `and` |
| macOS Endpoint Scenario | `and` | `and` | `and` |
| Kubernetes Endpoint Scenario | **`or`** | `or` | `and` |
| File Download | `or` | `or` | (no action-level) |
| Email | `or` | `or` | (no action-level) |
| Web Application | `or` | `or` | (no action-level) |
| Data Exfiltration | `or` ¹ | `or` | (no action-level) |
| URL Filtering | `or` | `or` | (no action-level) |

¹ Data Exfiltration is the one module where Picus uses both: `or` on a 21-objective threat,
`and` on a 1-objective threat. With a single term `and` and `or` are logically identical, so
`or` is the safe default. The objective-level operator matched the campaign operator in 21 of
22 sampled threats — that same single-objective Data Exfiltration threat is the exception
(campaign `and`, objective `or`).

### `remote_files`

**Placement depends on the module** — verified over 170 actions in 29 genuine Picus threats:

| Module | `remote_files` lives on | Evidence |
|---|---|---|
| File Download, Email, Data Exfiltration | the **action** | 41/41 actions |
| Endpoint, Linux, macOS, Kubernetes Endpoint | each **`play_processes` entry** | 51 processes; **0** at action level |

```yaml
# File Download / Email / Data Exfiltration — action level
remote_files:
  - file: files/<base64 blob>    # path inside ZIP — MUST exist
    path: C:\Temp\payload.exe    # destination on simulated target
    is_downloaded: true

# Endpoint modules — nested under the process that uses it
play_processes:
  - path: reg.exe
    arguments: add "HKCU\...\RunOnce" /v "*x" /d "%TMP%\dummy.exe" /f
    timeout: 15                  # process-level, undocumented until now
    remote_files:
      - file: files/<base64 blob>
        path: '%TMP%\dummy.exe'
        is_downloaded: true
        is_executable: true
    success_conditions:          # process-level, not action-level
      - output: The operation completed successfully.
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
| Endpoint Scenario | `Attack Scenario`, `Lateral Movement Techniques` |
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
**Objectives** · Persistence · **Pivoting** · Privilege Escalation · Reconnaissance ·
Social Engineering · Weaponization

All 18 are valid. Only 14 are ever used by a Picus-authored action — `Weaponization`,
`Social Engineering`, `Pivoting` and `Objectives` are unused in the library. Each phase also
has a fixed UKC `stage` (`Initial Foothold` / `Network Propagation` / `Action on Objectives`);
see [ground-truth-library.md](references/ground-truth-library.md).

---

## Detection — what it is and where it lives

A Picus simulation produces **two** verdicts per action:

| Verdict | Means | Driven by |
|---|---|---|
| **Prevention** | `blocked` / `unblocked` — did a control stop the attack? | the attack itself (`play_processes`, `remote_files`, `request_content`, `filter_url`) |
| **Detection** | `logged` / `not logged`, `alerted` / `not alerted` — did the SIEM/EDR see it? | **`keyword_queries`** |

**There is no `detection:` block in `threat.yaml`.** Verified by scanning 29 genuine Picus
threats (12 fresh API exports + 13 bundled examples + local copies) for any
`detection` / `sigma` / `rule` / `siem` / `alert` key — none exists. `keyword_queries` *is* the
detection half of a threat: Picus runs that boolean expression against the logs pulled from
each SIEM/EDR integration, and an action counts as detected when the query matches.

So authoring detection = authoring `keyword_queries` correctly. Get the per-module template and
the `AND NOT` rules from [ground-truth-library.md](references/ground-truth-library.md); they are
measured over all 31180 Picus actions. Key points:

- In **YAML** a `keyword_queries` entry is a **plain string** — verified on 249/249 actions in
  real Picus threats. The `{id, query, type: Default}` object is only how the **API** returns it;
  never write a `type:` key into `threat.yaml`.
- One query per action (99.98% of the library).
- The query must contain something **uniquely attributable to this action** — a file hash, the
  `{PICUSID}` marker, a sandbox-unique argument — or every simulation will look detected.
- `AND NOT (…)` exists to suppress Picus's **own** cleanup noise (`PICUS_REWIND`, `rm -rf`,
  `pkill`). Add it only for Endpoint modules and Data Exfiltration.

### Detection Content (the platform feature) is a different API

Picus also ships vendor-specific SIEM rules — "Detection Content" — recommended for actions that
were not detected. That is **not** part of a threat archive. It lives behind:

```
GET  /v1/mitigation/detection-content/sources          # Splunk, QRadar, Sentinel, ...
GET  /v1/mitigation/detection-content/{source}/rules
GET  /v1/mitigation/detection-content/{source}/rules/{ruleId}
GET  /v1/mitigation/detection-content/custom           # your own content
POST /v1/mitigation/detection-content/custom
GET  /v1/mitigation/detection-content/mitre/{tactics|techniques|sub-techniques}
GET  /v1/mitigation/detection-content/devices
```

Every one of those needs a **Mitigation** token scope. With a Threat-Library-only scope they all
return `403 {"message":"token scope not permitted"}` — confirmed on this deployment 2026-10-05.
There is also `POST /v1/threat-library/actions/custom-keyword`, which asks Picus to *generate*
the detection keyword for a custom action from its hashes / filename / process ids — useful when
hand-writing `keyword_queries` for a new action.

---

## Validation Checklist

**Run `scripts/validate_threat.py` first** — it mechanically enforces everything below
that can be checked, against vocabularies measured from the live library. This list is
what it checks, plus the few judgement calls it cannot make:

- [ ] `name` is unique (no duplicates in their account)
- [ ] `module` matches one of the valid module strings exactly
- [ ] `category` on each action is valid for the chosen module (see table above)
- [ ] `affected_os` values are from the accepted OS list
- [ ] Each `remote_files[].file` path matches a real file in `files/`
- [ ] `remote_files` is at the **right level**: action for File Download / Email / Data Exfiltration,
      inside `play_processes` for the Endpoint modules
- [ ] On-disk payload name is ONE base64 blob of `<name>___<uuid>.<ext>`, padding kept
- [ ] `success_conditions` sits on the **process**, not the action
- [ ] `title` omitted for macOS Endpoint and URL Filtering, present elsewhere
- [ ] Each `request_content` path matches a real `.req` file in `files/` (Web Application)
- [ ] Result-condition references (`%action-1%`, `%objective-N%`, `%process-N%`) don't exceed the actual item count
- [ ] Result-condition join operator matches the module table above
- [ ] `keyword_queries` follows the canonical template for the module
- [ ] `AND NOT` noise filter present **only** for Endpoint modules and Data Exfiltration —
      Picus uses none at all for File Download, Email, Web Application, URL Filtering, AWS or GCP
- [ ] `keyword_queries` entries are plain strings (no `query:` / `type:` keys — that is the API shape)
- [ ] `is_applicable_to_all_platforms` is set on every action
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