# Library Ground Truth — measured, not inferred

Derived from the **live Picus on-prem Threat Library** on 2026-10-05 via the Customer API.
Sample: **7830 Picus-authored predefined threats** (`is_predefined=true`, the complete set)
and **31180 unique actions** (the complete set referenced by those threats), plus the
authoritative vocabulary from `GET /v1/threat-library/action-parameters`.

Use this file to settle any question about *what values Picus actually uses*. Where it
disagrees with another doc in this skill, this file wins — every number here is counted.

> **Representation caveat.** The API's JSON for an action is **not** the YAML import schema.
> The API reports hashes under `module_based_details.file`, while YAML uses `remote_files`;
> the API exposes `frameworks.mitre.tactic_id`, while YAML uses `tactic`. Treat the
> **value vocabularies** below as authoritative for YAML, and the **structural** notes as
> API-side observations unless a bundled `references/examples/*/threat.yaml` confirms them.
> All 13 bundled examples were verified present in the predefined library, so they are
> genuine Picus YAML.

---

## Library composition

| Module | Threats | Share |
|---|---:|---:|
| `File Download` | 3591 | 45.9% |
| `Email` | 3205 | 40.9% |
| `Web Application` | 408 | 5.2% |
| `Endpoint Scenario` | 242 | 3.1% |
| `Azure Cloud Emulation` | 88 | 1.1% |
| `Data Exfiltration` | 68 | 0.9% |
| `Linux Endpoint Scenario` | 66 | 0.8% |
| `AWS Cloud Emulation` | 56 | 0.7% |
| `macOS Endpoint Scenario` | 43 | 0.5% |
| `URL Filtering` | 38 | 0.5% |
| `Kubernetes Endpoint Scenario` | 13 | 0.2% |
| `GCP Cloud Emulation` | 12 | 0.2% |

**File Download + Email alone are 6796 of 7830 threats
(87%).** The auto-pipeline in `SKILL.md` covers
only Linux + Windows Endpoint = 308 threats
(3.9%). Hand-authoring is the
normal path, not the exception.

Severity across the library:
| Severity | Threats | Share |
|---|---:|---:|
| `High` | 7204 | 92.0% |
| `Medium` | 495 | 6.3% |
| `Low` | 131 | 1.7% |

## Campaign shape — what "normal" looks like

| Metric | Median | Mean | Max |
|---|---:|---:|---:|
| objectives per threat | 2 | 4.89 | 90 |
| actions per threat | 2 | 5.12 | 90 |

- **64%** of Picus threats have **more than one objective**.
  A single-objective campaign is the minority case.
- 36% have exactly one action.
- The largest real campaign has **90 objectives / 90 actions** — so
  `%objective-N%` / `%action-N%` references legitimately run into the dozens.

---

## `objectives[].type` is a closed vocabulary, not free text

16 distinct values across all
38284 objectives in the library:

| `type` | Occurrences |
|---|---:|
| `Delivery` | 28581 |
| `Exploitation` | 4139 |
| `Initial Access` | 1757 |
| `Exfiltration` | 952 |
| `Defense Evasion` | 670 |
| `Discovery` | 522 |
| `Execution` | 333 |
| `Credential Access` | 287 |
| `Persistence` | 272 |
| `Collection` | 202 |
| `Command and Control` | 198 |
| `Impact` | 153 |
| `Privilege Escalation` | 126 |
| `Lateral Movement` | 89 |
| `Reconnaissance` | 2 |
| `Network` | 1 |

These read like MITRE tactic names but are **not** the same strings as `ukc_phase`: here it is
`Command and Control` (spelled out), whereas `ukc_phase` uses `Command & Control` (ampersand).
Do not interchange them.

---

## MITRE tactics — Picus uses its own names for two of them

Counted from `frameworks.mitre.tactic_id` on every action that carries one:

| `tactic` ID | Picus tactic name | Note |
|---|---|---|
| `TA0001` | `Initial Access` | matches MITRE |
| `TA0002` | `Execution` | matches MITRE |
| `TA0003` | `Persistence` | matches MITRE |
| `TA0004` | `Privilege Escalation` | matches MITRE |
| `TA0005` | `Stealth` | MITRE calls this *Defense Evasion*; **Picus renames it `Stealth`** |
| `TA0006` | `Credential Access` | matches MITRE |
| `TA0007` | `Discovery` | matches MITRE |
| `TA0008` | `Lateral Movement` | matches MITRE |
| `TA0009` | `Collection` | matches MITRE |
| `TA0010` | `Exfiltration` | matches MITRE |
| `TA0011` | `Command and Control` | matches MITRE |
| `TA0040` | `Impact` | matches MITRE |
| `TA0043` | `Reconnaissance` | matches MITRE |
| `TA0112` | `Defense Impairment` | **Picus-specific tactic** — not in MITRE ATT&CK Enterprise |
| `TA0042` | `Resource Development` | exists in the vocabulary but **no action uses it** (`has_actions: false`) |

`technique` / `sub_technique` are standard MITRE IDs (`T1016`, `T1548.005`) paired with a name.
Some actions ship an **empty** technique (`"technique": "", "technique_id": ""`) — a tactic alone
is acceptable.

---

## UKC has a second dimension the skill never mentions: `stage`

Every action's `frameworks.ukc` carries **both** a `phase` and a `stage`. The mapping is fixed:

| `ukc_phase` | UKC `stage` |
|---|---|
| `Collection` | `Action on Objectives` |
| `Command & Control` | `Initial Foothold` |
| `Credential Access` | `Network Propagation` |
| `Defense Evasion` | `Initial Foothold` |
| `Delivery` | `Initial Foothold` |
| `Discovery` | `Network Propagation` |
| `Execution` | `Network Propagation` |
| `Exfiltration` | `Action on Objectives` |
| `Exploitation` | `Initial Foothold` |
| `Impact` | `Action on Objectives` |
| `Lateral Movement` | `Network Propagation` |
| `Persistence` | `Initial Foothold` |
| `Privilege Escalation` | `Network Propagation` |
| `Reconnaissance` | `Initial Foothold` |

The vocabulary endpoint lists **18** phases in this canonical order:

  1. `Reconnaissance`
  2. `Weaponization`
  3. `Delivery`
  4. `Social Engineering`
  5. `Exploitation`
  6. `Persistence`
  7. `Defense Evasion`
  8. `Command & Control`
  9. `Pivoting`
  10. `Discovery`
  11. `Privilege Escalation`
  12. `Execution`
  13. `Credential Access`
  14. `Lateral Movement`
  15. `Collection`
  16. `Exfiltration`
  17. `Impact`
  18. `Objectives`

Only 14 of them are used by any Picus action. Never observed in the library:
`Weaponization`, `Social Engineering`, `Pivoting`, `Objectives` — they are valid values, just unused.

---

## `keyword_queries` — the real templates

- **API shape only:** the API returns each entry as `{id, query, type}` with `type` **always
  `"Default"`**. In `threat.yaml` a `keyword_queries` entry is a **plain string** (verified
  249/249 actions in real Picus exports) — do not write `type:` into YAML. (31184 of
  31184 queries). No other value appears.
- 99.99% of actions carry **exactly one** query.

Dominant boolean skeleton per module (`TERM` = a quoted string):

| Module | n | Dominant skeleton | Share |
|---|---:|---|---:|
| `File Download` | 12571 | `((TERM OR TERM OR TERM) OR (TERM AND TERM))` | 98.7% |
| `Email` | 11822 | `((TERM AND (TERM OR TERM)) OR ((TERM OR TERM OR TERM) OR (TERM AND TERM)))` | 98.7% |
| `Web Application` | 2641 | `(TERM)` | 100.0% |
| `URL Filtering` | 1539 | `(TERM)` | 100.0% |
| `Endpoint Scenario` | 1530 | `((TERM OR TERM OR TERM OR TERM) AND NOT (TERM OR (TERM AND (TERM OR TERM))))` | 16.8% |
| `Linux Endpoint Scenario` | 324 | `((TERM OR TERM OR TERM OR TERM) AND NOT (TERM OR TERM OR (TERM AND TERM)))` | 15.7% |
| `Data Exfiltration` | 238 | `((((TERM AND TERM) OR TERM OR TERM) OR ((TERM OR TERM OR TERM) OR (TERM AND TERM))) AND NO` | 100.0% |
| `macOS Endpoint Scenario` | 213 | `((TERM OR TERM OR TERM OR TERM) AND NOT ((TERM AND TERM) OR TERM OR TERM))` | 16.4% |
| `Kubernetes Endpoint Scenario` | 168 | `((((TERM OR TERM)) OR (TERM OR TERM OR TERM)) AND NOT (TERM OR TERM OR (TERM AND TERM)))` | 25.0% |
| `Azure Cloud Emulation` | 66 | `(TERM AND TERM)` | 62.1% |
| `AWS Cloud Emulation` | 56 | `(TERM)` | 64.3% |
| `GCP Cloud Emulation` | 12 | `(TERM)` | 66.7% |

Read in plain terms:

- **File Download** — `((SHA256 OR SHA1 OR MD5) OR (MD5 AND "<ext>"))`
- **Email** — `(("<display_id>" AND ("Attachment" OR "URL")) OR ((SHA256 OR SHA1 OR MD5) OR (MD5 AND "<ext>")))`
- **Web Application** — a **single term**: `("page<PICUSID>")`
- **URL Filtering** — a **single term**: `("<domain>")`
- **Data Exfiltration** — `(((("act_id" AND "<id>") OR "-<id>-" OR "|<id>|") OR ((hashes) OR ("<dataset>" AND "<ext>"))) AND NOT ("picexfil" AND "short-url"))`
- **Endpoint (all OS)** — `((<name/hash/arg terms>) AND NOT (<rewind + cleanup noise>))`
- **Cloud Emulation** — plain API-call names: `("AssumeRole" OR "GetCallerIdentity")`, `("Add app role assignment to service principal" AND "Mail.Send")`

---

## The `AND NOT` noise filter is NOT universal

`SKILL.md`'s validation checklist asks for a "module-specific AND-NOT noise filter" on every
threat. Measured reality:

| Module | Queries with `AND NOT` | Share |
|---|---:|---:|
| `File Download` | 0/12571 | 0.0% |
| `Email` | 0/11822 | 0.0% |
| `Web Application` | 0/2641 | 0.0% |
| `URL Filtering` | 0/1539 | 0.0% |
| `Endpoint Scenario` | 1200/1530 | 78.4% |
| `Linux Endpoint Scenario` | 288/328 | 87.8% |
| `Data Exfiltration` | 238/238 | 100.0% |
| `macOS Endpoint Scenario` | 191/213 | 89.7% |
| `Kubernetes Endpoint Scenario` | 137/168 | 81.5% |
| `Azure Cloud Emulation` | 2/66 | 3.0% |
| `AWS Cloud Emulation` | 0/56 | 0.0% |
| `GCP Cloud Emulation` | 0/12 | 0.0% |

**Do not add an `AND NOT` clause for File Download, Email, Web Application, URL Filtering,
AWS or GCP** — Picus never does. It belongs to the Endpoint modules and Data Exfiltration.

The actual clauses Picus uses:

| Module | `AND NOT (…)` clause | n |
|---|---|---:|
| Endpoint Scenario (Windows) | `("PICUS_REWIND" OR ("File created:" AND ("Scenarios" OR "Simulation")))` | 586 |
| Endpoint Scenario (Windows) | `("PICUS_REWIND")` | 583 |
| Linux Endpoint | `("pkill" OR "killall" OR ("rm" AND "-rf"))` | 423 |
| macOS Endpoint | `(("rm" AND " -rf"))` — note the space before `-rf` | 147 |
| Data Exfiltration | `("picexfil" AND "short-url")` | 238 (100%) |

---

## `frameworks` presence — which modules carry MITRE/UKC at all

| Module | Actions with `frameworks` |
|---|---|
| `File Download` | 0/12571 |
| `Email` | 0/11822 |
| `Web Application` | 0/2641 |
| `URL Filtering` | 0/1539 |
| `Endpoint Scenario` | 1530/1530 |
| `Linux Endpoint Scenario` | 324/324 |
| `Data Exfiltration` | 5/238 |
| `macOS Endpoint Scenario` | 213/213 |
| `Kubernetes Endpoint Scenario` | 168/168 |
| `Azure Cloud Emulation` | 66/66 |
| `AWS Cloud Emulation` | 56/56 |
| `GCP Cloud Emulation` | 12/12 |

> **Do not conclude that `ukc_phase` may be omitted for File Download / Email / Web Application /
> URL Filtering.** All 13 bundled Picus YAML exports set `ukc_phase` on every action in every
> module. The API simply does not surface `frameworks` for those modules. `tactic` / `technique`
> / `sub_technique`, by contrast, really are absent from those modules' YAML.

---

## `module_based_details` by module (API-side shape)

| Module | Key | Payload |
|---|---|---|
| `AWS Cloud Emulation` | `file` | `{name, MD5, SHA1, SHA256}` — the API view of `remote_files` |
| `Azure Cloud Emulation` | `file` | `{name, MD5, SHA1, SHA256}` — the API view of `remote_files` |
| `Data Exfiltration` | `file` | `{name, MD5, SHA1, SHA256}` — the API view of `remote_files` |
| `Email` | `file` | `{name, MD5, SHA1, SHA256}` — the API view of `remote_files` |
| `Endpoint Scenario` | `processes` | `[{id, path, arguments}]` — the API view of `play_processes` |
| `File Download` | `file` | `{name, MD5, SHA1, SHA256}` — the API view of `remote_files` |
| `GCP Cloud Emulation` | `file` | `{name, MD5, SHA1, SHA256}` — the API view of `remote_files` |
| `Kubernetes Endpoint Scenario` | `processes` | `[{id, path, arguments}]` — the API view of `play_processes` |
| `Linux Endpoint Scenario` | `processes` | `[{id, path, arguments}]` — the API view of `play_processes` |
| `URL Filtering` | `(empty)` | `{}` — payload lives in `request_content` / `filter_url` instead |
| `Web Application` | `(empty)` | `{}` — payload lives in `request_content` / `filter_url` instead |
| `macOS Endpoint Scenario` | `processes` | `[{id, path, arguments}]` — the API view of `play_processes` |

Note for Endpoint authoring: Linux and Kubernetes actions set **`path: " "` (a single space)**
and put the entire command in `arguments`. Windows actions put a real binary in `path`
(`powershell.exe`) and flags in `arguments`.

---

## Action-level fields Picus uses that this skill does not document

Taken from the 13 bundled Picus YAML exports (all verified as genuine library threats):

| Field | Modules seen in | Note |
|---|---|---|
| `is_applicable_to_all_platforms` | all modules, but **not** every action | 208/249 actions (84%). Near-universal for File Download / Email / Data Exfiltration (100%), Web Application (98%), Kubernetes (92%), macOS (71%) — but only **38% for Linux Endpoint and 13% for Windows Endpoint**. Treat as optional, not mandatory. |
| `malware_family` | Email, File Download | vocabulary has **2233** valid values |
| `use_case` | Web Application | 27 valid values |
| `affected_product`, `affected_versions` | Web Application | singular, action-level — distinct from campaign `affected_products` |
| `cve`, `cwe`, `owasp` | Web Application | `cwe` is lowercase-prefixed (`cwe-89`); 98% of Web App actions set `cwe`+`owasp` |
| `is_wats_lite` | Web Application | undocumented boolean |
| `is_privileged` | macOS Endpoint | undocumented boolean |
| `comment` | Data Exfiltration, Web Application | the skill documents `comment` only at campaign level |

---

## `result_condition` — verified against real exports

The join-operator table in `SKILL.md` is **correct** for all six modules that could be checked.
What it omits is the **objective-level** operator, which mirrors the campaign operator:

| Module | Campaign | Objective | Action |
|---|---|---|---|
| Web Application | `or` | `or` | (none) |
| File Download | `or` | `or` | (none) |
| Email | `or` | `or` | (none) |
| Data Exfiltration | `or` | `or` | (none) |
| Kubernetes Endpoint | `or` | `or` | `and` |
| macOS Endpoint | `and` | `and` | `and` |

The campaign `Terms` count always equals the objective count (e.g. 21 objectives → 21 terms).

> `result_condition` is **not exposed by the API** for predefined threats — `GET
> /v1/threat-library/threats/{id}` returns no such field. The table above comes from the bundled
> YAML exports, so Windows Endpoint, Linux Endpoint and the three Cloud modules remain
> **unverified**; their rows in `SKILL.md` are plausible but untested.

---

## Vocabulary corrections

| Field | Status |
|---|---|
| `url_category` | skill lists 29 of **36**. Missing: `Ai Services - 1` … `Ai Services - 7` |
| `use_case` | skill lists 26 of **27**. Missing: `Metasploit` |
| `owasp` | 10 distinct — **skill correct** |
| Windows platforms | 13 names — **skill correct** |
| macOS platforms | 6 names — **skill correct** |
| UKC phases | **18** — `accepted-values.md` correct; `SKILL.md` lists only 16 |
| MITRE tactics | 15 incl. `TA0042` — **skill correct**, including `Stealth` and `Defense Impairment` |

Linux platforms: the skill's range notation (`Ubuntu 18.04 — Ubuntu 24.04`) hides that the
interim releases are individually valid. The full list is 13 Ubuntu versions:
18.04, 18.10, 19.04, 19.10, 20.04, 20.10, 21.04, 21.10, 22.04, 22.10, 23.04, 23.10, 24.04
(each 32-bit and 64-bit); Debian 9–12; CentOS 7–9; RHEL 7–10; Rocky 8–9; SUSE 15 and 15.1–15.7;
Alpine 3.15–3.22 (64-bit only).

---

## Reproducing this file

```bash
# 7830 predefined threats (79 pages)
GET /v1/threat-library/threats?is_predefined=true&limit=100&offset=N
# 31180 actions, 25 ids per request
GET /v1/threat-library/actions?action_ids=<id>,<id>,...
# the vocabulary (module_name is accepted but ignored — the response is identical for all 12)
GET /v1/threat-library/action-parameters?module_name=<module>
```

The refresh token needs a scope that covers the Threat Library **actions** branch; a
threat-list-only scope returns `403 {"message":"token scope not permitted"}` on
`/v1/threat-library/actions*` and `/v1/threat-library/action-parameters`.



---

## Corrections found on re-verification (2026-10-05, second pass)

### `remote_files` on-disk filename — the skill's recipe is wrong

`SKILL.md` and several module docs give:

```
files/<base64(MD5)>___<base64(UUID)>.<ext>
```

Measured over **76/76 `remote_files` entries** in genuine Picus exports, the real form is a
**single base64 blob** — the `___` separator and the extension live *inside* the encoded string:

```
files/<base64("<md5-or-name>___<uuid>.<ext>")>
```

Worked example from `BlackMatter Ransomware Campaign` (Picus-authored):

```
files/ZHVtbXlfX18xZDZkNzQ5OS05MjczLTQwZmUtODJhNy1hN2FhMWIyZDQzMTQuZXhl
  base64-decodes to:  dummy___1d6d7499-9273-40fe-82a7-a7aa1b2d4314.exe
```

The encoded form **never** contains `___` and **never** carries a dot or extension (76/76).
The plaintext is `<md5>___<uuid>.<ext>` for File Download / Email and `<name>___<uuid>[.ext]`
for Endpoint droppers. Build it as:

```python
import base64, uuid
plain = f"{md5}___{uuid.uuid4()}{ext}"   # ext includes the dot, or is "" for Endpoint droppers
name  = base64.b64encode(plain.encode()).decode()   # KEEP the "=" padding
# -> files/<name>
```

**Keep the `=` padding.** Standard base64 with padding is what Picus emits — e.g.
`files/NDEzMTI4X19fNTAzZjBmMjMtZmRhZi00MTk1LTk4YzYtNTliMjBiMjA0ZjdiLnhsc3g=` decodes to
`413128___503f0f23-fdaf-4195-98c6-59b20b204f7b.xlsx`. Do not strip it.

### `remote_files` and `success_conditions` sit on `play_processes`, not only on the action

For Endpoint modules the real nesting is **per process**:

```yaml
play_processes:
  - path: reg.exe
    arguments: add "HKCU\...\RunOnce" /v "*x" /d "%TMP%\dummy.exe" /f
    timeout: 15
    remote_files:
      - file: files/<base64 blob>
        path: '%TMP%\dummy.exe'
        is_downloaded: true
    success_conditions:
      - output: The operation completed successfully.
```

Counted over 249 actions in genuine exports, `play_processes` field combinations:

| Fields on a `play_processes` entry | n |
|---|---:|
| `arguments, path, success_conditions, timeout` | 25 |
| `arguments, remote_files` | 17 |
| `arguments, success_conditions` | 15 |
| `arguments` | 14 |
| `arguments, is_async, remote_files` | 9 |
| `arguments, remote_files, success_conditions` | 9 |
| `arguments, delay, success_conditions` | 8 |

`success_conditions` is **process-level in 68/68 cases** and its shape is almost always a single
`output:` key (`code:` appears twice, `is_inverse:` once). `path` is frequently **absent** on
Linux/Kubernetes entries — the whole command goes in `arguments`.

### Process-level fields the skill does not document

| Field | Where | n |
|---|---|---:|
| `timeout` | Windows 25, Linux 14, Kubernetes 8 | 47 |
| `is_async` | Kubernetes 14, Windows 1, Linux 1 | 16 |
| `delay` | Kubernetes 10 | 10 |

### `is_privileged` is not macOS-only

Action-level `is_privileged` appears on Windows Endpoint (16), Linux Endpoint (14) and
macOS Endpoint (4). `SKILL.md` lists it as macOS-only.

### `result_condition` — Windows and Linux Endpoint now verified

Verified from two genuine Picus exports held locally:

| Module | Source threat | Campaign | Objective | Action |
|---|---|---|---|---|
| Endpoint Scenario (Windows) | `BlackMatter Ransomware Campaign` | `and` | `and` | `and` |
| Linux Endpoint Scenario | `PUMAKIT Malware Campaign` | `and` | `and` | `and` |

Both match `SKILL.md`. Action-level conditions reference processes positionally
(`%process-1%`), as documented.

### Exporting a Picus-authored threat works

`GET /v1/threat-library/threats/{id}/export` is documented as "exports a **custom** threat", but
it returns `200 application/zip` for **predefined** Picus threats as well. This is the way to get
authoritative YAML for any module — including the three Cloud modules, which ship no bundled
example. The archive is AES-encrypted with password `picus`.

### Detection content is a separate, separately-scoped API

There is **no detection block in `threat.yaml`** — scanned 32 local YAML files and found no
`detection` / `sigma` / `rule` / `siem` / `alert` key anywhere. Per-action detection logic *is*
`keyword_queries`: Picus runs that boolean query against the integrated SIEM/EDR to decide
whether the action was logged or alerted.

Picus's shipped SIEM rules ("Detection Content") live behind
`/v1/mitigation/detection-content/*`, which needs a **Mitigation** token scope — every endpoint
under `/v1/mitigation/*` and `/v2/mitigation/*` returns
`403 {"message":"token scope not permitted"}` with a Threat-Library-scoped token.


---

## Third pass — verified against 12 fresh API exports (2026-10-05)

`GET /v1/threat-library/threats/{id}/export` was used to pull one Picus-authored threat per
module. Combined with the 13 bundled examples and local copies this gives **29 unique genuine
Picus threats / 170 actions across 9 modules**. The three Cloud modules could not be exported on
this deployment:

```
{"code":402,"error_code":1009,"message":"Your license does not include required prevention module."}
```

So **AWS / Azure / GCP Cloud Emulation remain unverified** — their rows in `SKILL.md` (including
the `steps:` / `rewind_steps:` fields) are still untested. Everything else below is measured.

### Action field matrix

| Module | actions | `title` | `ukc_phase` | `tactic` | `is_privileged` | `remote_files` on action | on process |
|---|---:|---:|---:|---:|---:|---:|---:|
| Data Exfiltration | 22 | 22 | 22 | 0 | 0 | **22** | 0 |
| Email | 8 | 8 | 8 | 0 | 0 | **8** | 0 |
| File Download | 11 | 11 | 11 | 0 | 0 | **11** | 0 |
| Web Application | 49 | 48 | 49 | 0 | 0 | 0 | 0 |
| URL Filtering | 2 | **0** | 2 | 0 | 0 | 0 | 0 |
| Endpoint Scenario | 24 | 16 | 24 | **24** | 16 | 0 | **13** |
| Linux Endpoint | 25 | 12 | 25 | **25** | 14 | 0 | **16** |
| macOS Endpoint | 12 | **0** | 12 | **12** | 4 | 0 | **5** |
| Kubernetes Endpoint | 17 | 17 | 17 | **17** | 1 | 0 | **17** |

Conclusions:

- **`ukc_phase` is set on 170/170 actions** — every module, no exceptions. Required.
- **`tactic` / `technique` / `sub_technique` only on the four Endpoint modules** (78/78 of their
  actions, 0/92 elsewhere). Matches `SKILL.md`.
- **`title` is omitted on macOS Endpoint (0/12) *and* URL Filtering (0/2)**. `SKILL.md` only
  mentioned macOS.
- **`is_privileged` is not macOS-only** — Windows 16/24, Linux 14/25, macOS 4/12, Kubernetes 1/17.
- **`remote_files` placement is module-dependent**: action level for the three file-delivery
  modules (41/41), `play_processes` level for all four Endpoint modules (51 processes, **0** at
  action level).
- `affected_product` appears on Endpoint Scenario actions too, not just Web Application.
- URL Filtering actions carry no `affected_os` — just
  `category, description, filter_url, is_applicable_to_all_platforms, is_atomic, keyword_queries, name, ukc_phase, url_category`.

### Per-module action field union

| Module | Fields |
|---|---|
| File Download | `affected_os, category, description, is_applicable_to_all_platforms, is_atomic, keyword_queries, malware_family, name, remote_files, title, ukc_phase` |
| Email | same as File Download **plus** `execution_methods` |
| Data Exfiltration | `affected_os, category, comment, country, data_type, description, is_applicable_to_all_platforms, is_atomic, keyword_queries, name, remote_files, title, ukc_phase` |
| URL Filtering | `category, description, filter_url, is_applicable_to_all_platforms, is_atomic, keyword_queries, name, ukc_phase, url_category` |
| Web Application | `affected_os, affected_platforms, affected_product, affected_versions, category, comment, cve, cwe, description, is_applicable_to_all_platforms, is_atomic, is_wats_lite, keyword_queries, name, owasp, request_content, title, ukc_phase, use_case` |
| Endpoint / Linux / Kubernetes | `affected_os, affected_platforms, category, description, is_applicable_to_all_platforms, is_atomic, is_privileged, keyword_queries, name, play_processes, result_condition, rewind_processes, sub_technique, tactic, technique, title, ukc_phase` (+ `affected_product` on Windows, `comment` on Kubernetes) |
| macOS Endpoint | as above **minus `title`** |

### `result_condition` — join operator, all 9 verifiable modules

| Module | Campaign operator observed | Threats sampled |
|---|---|---:|
| Endpoint Scenario | `and` | 1 |
| Linux Endpoint | `and` | 1 |
| macOS Endpoint | `and` | 2 |
| Kubernetes Endpoint | `or` | 2 |
| File Download | `or` | 3 |
| Email | `or` | 3 |
| Web Application | `or` | 6 |
| URL Filtering | `or` | 1 |
| Data Exfiltration | **`or` and `and`** | 2 |

`SKILL.md`'s table is correct for all of them. The one wrinkle: Data Exfiltration used `or` on a
21-objective threat and `and` on a 1-objective threat — logically identical over a single term,
so `or` stays the right default.

The objective-level operator equalled the campaign operator in **21 of 22** sampled threats; the
exception is that same single-objective Data Exfiltration threat (campaign `and`, objective `or`).
Treat "objective mirrors campaign" as the convention, not an invariant.

### URL Filtering exports as raw YAML, not a ZIP

`GET /v1/threat-library/threats/{id}/export` for a URL Filtering threat returns a bare
`campaign:` YAML document with `Content-Type: application/zip` but **no ZIP container** — the
bytes start with `campaign:`. This confirms `SKILL.md`'s note that URL Filtering threats
export/import as `.yaml` only. Every other module returns a real AES ZIP (password `picus`).

Incidentally the exported URL Filtering threat is named `Ai Services - 7` and sets
`url_category: Ai Services - 7` — one of the seven categories that were missing from
`accepted-values.md` before this pass.


---

## Fourth pass — per-module samples large enough to trust (2026-10-05)

The earlier passes leaned on one or two threats per module, which produced at least one wrong
conclusion. This pass exports **~20 Picus threats per module** (stratified by action count,
release date and category) and recounts. Sample so far:

| Module | Threats | Actions |
|---|---:|---:|
| Endpoint Scenario | 20 | 218 |
| Email | 20 | 175 |
| Data Exfiltration | 19 | 174 |
| File Download | 10 | 77 |

### Correction: Picus does not set `title` on Endpoint Scenario

**`title` is absent from 0/218 Endpoint Scenario actions** across 20 Picus threats. An earlier
figure of 16/24 in this file was wrong: that sample mixed Picus threats with locally
hand-authored ones, and the hand-authored ones supplied every `title`. Picus omits `title` on
**Endpoint Scenario** and **macOS Endpoint**, and sets it on **100%** of Email (175/175),
File Download (77/77) and Data Exfiltration (174/174) actions.

This is the sampling trap to avoid: counting actions rather than threats makes a one-threat
sample look like a 24-action one.

### Fields that are common but NOT universal — do not mark them required

| Module | Field | Present |
|---|---|---|
| Endpoint Scenario | `is_atomic` | 211/218 |
| Endpoint Scenario | `description` | 217/218 |
| Endpoint Scenario | `rewind_processes` | 161/218 |
| Endpoint Scenario | `is_privileged` | 55/218 |
| Endpoint Scenario | `sub_technique` | 59/218 |
| Endpoint Scenario | `is_applicable_to_all_platforms` | 52/218 (24%) |
| Endpoint Scenario | `affected_product` | 44/218 |
| Email | `malware_family` | 145/175 |
| Email | `comment` | 122/175 |
| File Download | `malware_family` | 65/77 |
| File Download | `comment` | 41/77 |
| Data Exfiltration | `comment` | 165/174 |
| Data Exfiltration | `tactic` | 2/174 |

Universal in their module (100%): `ukc_phase`, `category`, `affected_os` and `remote_files` for
Email / File Download / Data Exfiltration; `ukc_phase`, `category`, `affected_os` for Endpoint.

### Two more undocumented fields

| Field | Seen in | Count |
|---|---|---|
| `vulnerability_type` | Email, File Download | 3/175, 2/77 — the values are the ones already listed under *Vulnerability Types* in `accepted-values.md` |
| `user_privilege` | Endpoint Scenario | 2/218 |

### `affected_product` is not Web-Application-only

It appears on Endpoint Scenario (44/218), Email (3/175) and File Download (2/77) as well.

### Still thin

**URL Filtering: one threat / two actions.** That one threat sets neither `title` nor
`affected_os`, while `url-filtering.md` marks both required. Treated as unconfirmed, not
corrected, until the 20-threat sample for that module lands.


### Fourth pass, continued — Kubernetes and Linux Endpoint

| | Kubernetes (13 threats / 174 actions) | Linux Endpoint (11 threats / 104 actions) |
|---|---:|---:|
| `title` | **174/174** | **4/104** |
| `tactic` | 174/174 | 104/104 |
| `technique` | 161/174 | 104/104 |
| `sub_technique` | 48/174 | 42/104 |
| `is_atomic` | 173/174 | 104/104 |
| `description` | 172/174 | 103/104 |
| `is_applicable_to_all_platforms` | 146/174 | 92/104 |
| `rewind_processes` | 125/174 | 74/104 |
| `is_privileged` | 34/174 | 16/104 |
| `comment` | 5/174 | 6/104 |
| `remote_files` on the action | **0** | **0** |
| `remote_files` on a `play_process` | 133 | 81 |
| action `result_condition` operator | `and` 174/174 | `and` 104/104 |

So `title` splits the Endpoint family: **Kubernetes always sets it, the other three omit it.**
Another figure corrected — an earlier 12/25 for Linux Endpoint came from a sample mixed with
hand-authored threats.

`remote_files` on a `play_process` and never on the action is now confirmed across
**Endpoint + Kubernetes + Linux + macOS** with 0 action-level cases in any of them.

### One more undocumented field

`mitigation` — appears once in Kubernetes (1/174) and once in Linux Endpoint (1/104). Too rare
to characterise; noted so it is not mistaken for invalid if it shows up in an export.


### Fourth pass, final — URL Filtering, Web Application, macOS

**The one-threat URL Filtering sample was misleading.** With 20 threats / 1016 actions:

| Field | URL Filtering | Verdict |
|---|---:|---|
| `title` | **924/1016 (91%)** | Picus DOES set it — the earlier 0/2 reading was wrong |
| `affected_os` | **26/1016 (3%)** | Picus OMITS it — `url-filtering.md` was wrong to require it |
| `description` | 592/1016 (58%) | optional |
| `filter_url`, `url_category`, `category`, `ukc_phase`, `is_atomic`, `is_applicable_to_all_platforms`, `keyword_queries` | 1016/1016 | required |

| Field | Web Application (20 threats / 179 actions) |
|---|---:|
| `affected_os`, `category`, `description`, `is_atomic`, `is_applicable_to_all_platforms`, `keyword_queries`, `owasp`, `request_content`, `ukc_phase`, `use_case` | 179/179 |
| `title` | 178/179 |
| `affected_product`, `comment`, `cwe` | 176/179 |
| `affected_versions` | 161/179 |
| `is_wats_lite` | 138/179 |
| `cve` | 88/179 (49%) |

| Field | macOS Endpoint (7 threats / 50 actions) |
|---|---:|
| `title` | **0/50** — confirmed omitted |
| `tactic` | 50/50 |
| `technique` | 49/50 |
| `sub_technique` | 18/50 |
| `is_applicable_to_all_platforms` | 42/50 |
| `rewind_processes` | 39/50 |
| `is_privileged` | 16/50 |

### `title` — final per-module rule

| Module | Sets `title` |
|---|---|
| Kubernetes Endpoint | 174/174 |
| Email | 175/175 |
| File Download | 77/77 |
| Data Exfiltration | 174/174 |
| Web Application | 178/179 |
| URL Filtering | 924/1016 |
| **Linux Endpoint** | **4/104** |
| **Endpoint Scenario** | **0/218** |
| **macOS Endpoint** | **0/50** |

So only the three non-Kubernetes Endpoint modules omit it.
