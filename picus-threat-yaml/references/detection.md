# Detection in Picus — measured reference

Collected from the live platform on 2026-10-05. Every rule inspected here is Picus-shipped
(`"type": "predefined"`, 1000/1000 sampled, `"author": "Picus Security"`). Nothing in this file
is customer-authored content.

A Picus simulation yields **two independent verdicts per action**:

| Verdict | Values | Decided by |
|---|---|---|
| **Prevention** | `blocked` / `unblocked` | the attack itself — `play_processes`, `remote_files`, `request_content`, `filter_url` |
| **Detection** | `logged` / `not logged`, `alerted` / `not alerted` | the action's **`keyword_queries`**, run against logs pulled from each SIEM/EDR integration |

**A threat archive contains no detection rules.** Scanned 29 genuine Picus `threat.yaml` files for
any `detection` / `sigma` / `rule` / `siem` / `alert` key — none exists. When authoring a threat,
the only detection surface you control is `keyword_queries`.

Picus's **Detection Content** — ready-made SIEM/EDR rules — is a separate product area with its
own API, and it is what you reach for *after* a simulation shows an action went undetected.

---

## Detection Content catalog

`GET /v1/mitigation/detection-content/sources` — 11 vendors, with Picus's rule count each:

| Source | Rules |
|---|---:|
| `Splunk` | 717 |
| `Sigma` | 717 |
| `IBM QRadar` | 653 |
| `Microfocus ArcSight ESM` | 652 |
| `Chronicle` | 581 |
| `Microsoft Sentinel` | 575 |
| `VMware Carbon Black EDR` | 515 |
| `Microsoft Defender` | 383 |
| `SentinelOne` | 360 |
| `Palo Alto Cortex XDR` | 353 |
| `Crowdstrike` | 352 |

Total: **5858** Picus-authored detection rules.

`GET /v1/mitigation/detection-content/devices` — 13 device targets usable when creating
custom content (note this list is finer-grained than `sources`; CrowdStrike alone has three):

- `Crowdstrike Search Query`
- `Crowdstrike IOA`
- `Sigma`
- `VMware Carbon Black EDR`
- `IBM QRadar`
- `Chronicle`
- `Palo Alto Cortex XDR`
- `SentinelOne`
- `Microsoft Defender Query`
- `Crowdstrike LogScale Query`
- `Microsoft Sentinel`
- `Microfocus ArcSight ESM`
- `Splunk`

---

## Rule anatomy

A list entry from `GET /v1/mitigation/detection-content/{source}/rules`:

```json
{
  "id": "6025",
  "name": "SELinux Enforcement Disabled via Config File Command Line",
  "severity": "high",
  "type": "predefined",
  "score": 0,
  "releaseDate": 1789730965122,
  "updateDate": 1789730965122,
  "mitre": [{"mitreId": "T1685", "name": "Disable or Modify Tools",
             "url": "https://attack.mitre.org/techniques/T1685/"}],
  "actions": [{"id": 6092938, "name": "Disable SELinux Service"}]
}
```

`GET /v1/mitigation/detection-content/{source}/rules/{ruleId}` returns
`{"overview": {...}, "actions": [...]}` where `overview` adds the parts that matter:

| `overview` field | Content |
|---|---|
| `query` | **the rule itself, in the vendor's native syntax** |
| `logSource` | `{productName[], service, policies[]}` — the telemetry the rule needs, including the exact GPO / Sysmon config required |
| `falsePositives` | list of known FP causes, e.g. `["Administrative tools/scripts", "Software installation"]` |
| `description` | prose: what it detects and why an attacker does it |
| `author` | `Picus Security` on every rule sampled |
| `mitre`, `severity`, `type`, `releaseDate`, `updateDate`, `id`, `name`, `deviceName` | as in the list entry |

### The rule ↔ action link is the useful part

Every rule carries `actions[]` — the **threat-library actions it detects**, with
`{id, display_id, name, category}`. Sampled distribution over 1000 rules:

| Actions per rule | Rules |
|---|---:|
| 1 | 717 |
| 2 | 105 |
| 3 | 44 |
| 4 | 25 |
| 5 | 19 |
| 6 | 9 |
| 7 | 9 |
| 8 | 11 |

So given an action that came back *not detected*, the path is:
`action id` → find rules whose `actions[]` contains it → read that rule's `overview.query` for
your SIEM → deploy it. 20/20 sampled rule details linked to at least one action.

### Severity and score

| `severity` | Rules (of 1000) |
|---|---:|
| `medium` | 339 |
| `high` | 327 |
| `low` | 229 |
| `None` | 95 |
| `critical` | 10 |

> **`score` is account-derived, not catalog data.** 905 of
> 1000 sampled rules have `score: 0`. Every non-zero score belonged to a single vendor,
> which is the vendor the account actually has integrated — Picus only scores rules it could
> measure in your environment. Treat `score` as telling you about your deployment, not about the
> rule.

---

## One detection, ten syntaxes

Picus authors a detection once and ships it per product. **251 of 423 distinct rule names in the
sample appear under more than one vendor** — six names appear under all ten. The same logical
rule, re-expressed:

| Source | Query language |
|---|---|
| `Sigma` | Sigma YAML (`title:`/`logsource:`/`detection:` blocks) |
| `Splunk` | SPL (`sourcetype=... EventCode=1 Image IN (...)`) |
| `IBM QRadar` | AQL (`LOGSOURCETYPENAME(devicetype)='...' and Message ilike '%...%'`) |
| `Microfocus ArcSight ESM` | ArcSight filter (`deviceVendor = "Microsoft" AND externalId = 4103 AND message CONTAINS "..."`) |
| `Microsoft Sentinel` | KQL (`Event \| where EventLog =~ "..." and EventID == '13' \| parse ...`) |
| `Microsoft Defender` | KQL / Advanced Hunting (`DeviceProcessEvents \| where FolderPath endswith "\\systeminfo.exe"`) |
| `Palo Alto Cortex XDR` | XQL (`preset=xdr_process \| filter event_type = ENUM.PROCESS and ...`) |
| `SentinelOne` | Deep Visibility (`event.type = "Process Creation" AND src.process.image.path contains "..."`) |
| `VMware Carbon Black EDR` | CB query (`process_name:reg.exe AND cmdline:*add AND cmdline:\\Software\\...\\Run`) |
| `Crowdstrike` | Search Query / IOA / LogScale (three separate device targets) |

Worked example — the same Linux download-with-spoofed-UA detection:

**Sigma**
```yaml
logsource:
    product: linux
    category: process_creation
detection:
    selection_tool:
        Image|endswith: ['/curl', '/wget', '/fetch', '/lwp-download']
    selection_interpreter:
        Image|endswith: ['/python', '/python3', '/perl', '/ruby', '/busybox']
```

**Splunk**
```
((sourcetype="linux:sysmon" EventCode="1") OR (sourcetype="linux:audit:laurel" syscall IN ("execve","execveat")))
Image IN ("*/curl","*/wget","*/fetch","*/lwp-download")
OR (Image IN ("*/python","*/python3","*/perl","*/ruby","*/busybox")
    CommandLine IN ("*urllib*","*urlretrieve*","*requests.get*","*http.client*","*Net::HTTP*"))
CommandLine IN ("*Mozilla/*","*Chrome/*", ...)
```

---

## MITRE catalogs for custom detection content

These back the tactic/technique pickers when creating custom content:

| Endpoint | Entries |
|---|---:|
| `/v1/mitigation/detection-content/mitre/tactics` | 15 |
| `/v1/mitigation/detection-content/mitre/techniques` | 222 |
| `/v1/mitigation/detection-content/mitre/sub-techniques` | 475 |

Most-referenced techniques across the sampled rules:

| Technique | Rules |
|---|---:|
| `T1218` System Binary Proxy Execution | 94 |
| `T1059` Command and Scripting Interpreter | 87 |
| `T1685` Disable or Modify Tools | 80 |
| `T1082` System Information Discovery | 74 |
| `T1003` OS Credential Dumping | 58 |
| `T1574` Hijack Execution Flow | 57 |
| `T1036` Masquerading | 47 |
| `T1055` Process Injection | 46 |
| `T1047` Windows Management Instrumentation | 44 |
| `T1548` Abuse Elevation Control Mechanism | 37 |
| `T1546` Event Triggered Execution | 33 |
| `T1112` Modify Registry | 32 |

All 1000 sampled rules carry at least one MITRE mapping. Note Picus occasionally uses an id
that is not in MITRE ATT&CK Enterprise (e.g. `T1685` for *Disable or Modify Tools*, where MITRE
uses `T1562.001`) — mirroring the `Stealth` / `Defense Impairment` tactic renaming seen in the
threat library. Do not assume a Picus technique id resolves on attack.mitre.org.

---

## Writing `keyword_queries` — the part you control

This is the detection half of a threat. Measured over all 31180 Picus actions:

- In YAML each entry is a **plain string**. The `{id, query, type: "Default"}` object is the API
  representation only — `type` is always `Default` there, and must never be written into
  `threat.yaml`.
- One query per action (99.98%).
- The query must match something **uniquely attributable to this action** — a payload hash, the
  `{PICUSID}` marker, a sandbox-unique argument. A generic query makes every simulation look
  detected.
- `AND NOT (…)` suppresses Picus's own cleanup/rewind noise. Add it only for the Endpoint modules
  and Data Exfiltration; Picus uses none for File Download, Email, Web Application, URL Filtering,
  AWS or GCP.

Per-module templates and the exact `AND NOT` clauses are in
[ground-truth-library.md](ground-truth-library.md).

`POST /v1/threat-library/actions/custom-keyword` asks Picus to generate the keyword query for a
custom action from its attack module plus file hashes / filename / play-process ids / url / action
id — the fastest way to get a correctly-shaped query for a new action.

---

## API surface (all read-only except where noted)

```
GET  /v1/mitigation/detection-content/sources
GET  /v1/mitigation/detection-content/devices
GET  /v1/mitigation/detection-content/{source}/rules            # paginated
GET  /v1/mitigation/detection-content/{source}/rules/{ruleId}   # overview.query lives here
GET  /v1/mitigation/detection-content/{source}/log-sources      # ACCOUNT-SCOPED
GET  /v1/mitigation/detection-content/mitre/{tactics|techniques|sub-techniques}
GET  /v1/mitigation/detection-content/custom                    # ACCOUNT-SCOPED: your own rules
POST /v1/mitigation/detection-content/custom                    # WRITE
PUT  /v1/mitigation/detection-content/custom/{content_id}       # WRITE
DEL  /v1/mitigation/detection-content/custom/{content_id}       # WRITE
POST /v1/threat-library/actions/custom-keyword                  # generate a keyword query
```

All of these need a **Mitigation** token scope; a Threat-Library-only scope returns
`403 {"message":"token scope not permitted"}`.

`{source}` is the vendor name URL-encoded (`Microsoft%20Sentinel`). Pagination on `/rules`
returns `{"rules": [...], "pagination": {...}}` and yields `"rules": null` once past the last
page — treat that as end-of-list, not an error.

> Two endpoints are **account-scoped**, not catalog: `/log-sources` (the log sources configured
> for your account) and `/custom` (rules you wrote). Avoid them when the goal is to study Picus's
> own content.

