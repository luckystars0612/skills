# Email Module Reference

`module: Email`

**Canonical examples to use as templates:**

- [Kimwolf Botnet Email Threat](../../../Desktop/picus-threats/Kimwolf%20Botnet%20Email%20Threat/threat.yaml) — 6 variants (3 `.elf` URL, 3 `.so` URL+Attachment)
- [ChainDrop Malware Dropper Email Threat](../../../Desktop/picus-threats/ChainDrop%20Malware%20Dropper%20Email%20Threat/threat.yaml) — 1 variant (`.js` URL)

---

## Module invariants (consistent across every Email action)

| Field | Value | Notes |
|---|---|---|
| `module` | `Email` (literal) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `- Linux` *or* `- Windows` | single-element list — pick the OS that matches the malware's target |
| `is_atomic` | `true` | always on actions |
| `ukc_phase` | `Delivery` | always literal |
| `category` | `Malicious Code` | only valid category seen (`Vulnerability Exploitation` is also accepted by Picus for this module) |
| `is_applicable_to_all_platforms` | `true` | always |
| `title` (action) | `Phishing` | always literal |
| `comment` | absent | Email threats don't carry an action-level comment |

**Goal of an Email threat:** deliver a malicious payload through an email channel (attachment file OR URL-linked payload OR both). The control surface being tested is the email gateway / secure-mail-gateway, not EDR.

---

## Campaign-level shape

```yaml
campaign:
    name: <malware family> Email Threat
    description: <one-line blurb>
    module: Email
    severity: High
    affected_os:
        - <Linux|Windows>
    result_condition:            # one eq-term per objective, Operator: or
        true: unblocked
        false: blocked
        condition:
            Terms:
                - Right: {Value: unblocked}
                  Left:  {Value: '%objective-1%'}
                  Operator: eq
                # ... up to '%objective-N%'
            Operator: or
    objectives:
        # ...
```

**No `threat_actor`, `affected_products`, `comment`, or platform blocks at campaign level.** Each objective is its own single-action atomic delivery attempt.

---

## Objective-level shape

```yaml
- type: Delivery                       # always literal
  result_condition:                    # single eq-term, Operator: or
    true: unblocked
    false: blocked
    condition:
        Terms:
            - Right: {Value: unblocked}
              Left:  {Value: '%action-1%'}
              Operator: eq
        Operator: or
  actions:
    - # see below
```

**Always one action per objective** in this module — Email threats do not chain multi-step objectives.

---

## Action-level — FULL field inventory

Every Email action carries exactly these 13 fields:

| Field | Type | Example / value |
|---|---|---|
| `name` | string | `Kimwolf Botnet .ELF Email Attack Variant-1` |
| `title` | string | `Phishing` (literal) |
| `description` | string | long prose (malware intel write-up) |
| `affected_os` | list | `[<Linux|Windows>]` (duplicated from campaign) |
| `malware_family` | string | `Kimwolf`, `ChainDrop` |
| `is_atomic` | bool | `true` |
| `ukc_phase` | string | `Delivery` |
| `category` | string | `Malicious Code` |
| `is_applicable_to_all_platforms` | bool | `true` |
| `execution_methods` | list[string] | `[- URL]` or `[- URL, - Attachment]` (vocabulary: `URL`, `Attachment`) |
| `keyword_queries` | list[string] | exactly one entry — see canonical template below |
| `remote_files` | list[object] | exactly one entry — three fields (`file`, `path`, `is_downloaded`) |

**Fields that NEVER appear on an Email action:**

- No `tactic` / `technique` / `sub_technique` (MITRE mapping absent)
- No `result_condition` at action level (objective-level only)
- No `play_processes` / `rewind_processes` (no processes run)
- No `success_conditions` / `fail_conditions` (no process output to match)
- No `request_content` / `url_pattern` / `filter_url` / `url_category`
- No `affected_platforms`, `affected_product`, `cwe`, `owasp`, `cve`

---

## `execution_methods` substructure

List of bare strings — values are `URL` and/or `Attachment`:

```yaml
execution_methods:
    - URL                   # delivery is via a URL the user clicks
# and/or:
    - Attachment            # delivery is via an inline attachment
```

Pick the value(s) that match the malware's delivery vector. ELF droppers typically use `URL` only; document-based droppers typically use both.

---

## `remote_files` substructure

```yaml
remote_files:
    - file: files/<base64(MD5)>___<base64(UUID)>.<ext>     # path inside ZIP
      path: <MD5>.<ext>                                    # on-target filename
      is_downloaded: true
```

**Three fields per entry — exactly.** No `is_executable`, no `skip_zip_extract`. Every Email `remote_files` entry has `is_downloaded: true`.

**Filename encoding.** The on-disk filename in `files/` is base64-encoded to dodge filesystem encoding issues. The format is `<base64(MD5)>___<base64(UUID)>.<ext>`. Picus decodes it server-side to recover the original `<MD5>.<ext>` filename that lands on the target.

Example (real ChainDrop payload):

```yaml
remote_files:
    - file: files/ZjkyZWU5M2EwYWY5NzFhMzk2NmJmYThlZmE5YzI2MjVfX19iZTJiMTM3Yy1iMjI1LTRiMzktOTk0OC1lZTU2MzNkMDBlNzYuanM=
      path: f92ee93a0af971a3966bfa8efa9c2625.js
      is_downloaded: true
```

The MD5 in `path:` MUST match the MD5 in `keyword_queries`.

---

## `keyword_queries` canonical template

Every Email action's `keyword_queries` is a single-element list containing this exact shape:

```
(("<7-DIGIT-VECTOR-ID>" AND ("Attachment" OR "URL"))
 OR
 (("<SHA-256>" OR "<SHA-1>" OR "<MD5>")
  OR
  ("<MD5>" AND "<ext>")))
```

Three arms, all OR'd together:

1. **Vector ID arm.** A 7-digit Picus-internal numeric ID followed by `AND ("Attachment" OR "URL")`. The `"Attachment"` / `"URL"` tokens must match the values in `execution_methods`.
2. **Hash arm.** OR over the SHA-256, SHA-1, and MD5 of the payload file, in that exact order.
3. **Filename-and-ext arm.** MD5 hex followed by `AND "<ext>"`. This is redundant with the MD5 in the hash arm, but covers detectors that key on file-extension co-occurrence.

Concrete example (Kimwolf ELF Variant-1):

```yaml
keyword_queries:
    - (("5554144" AND ("Attachment" OR "URL")) OR (("406647de09a0ffa279756b4ccb344b1b76a333320c5b50fd367901fa006cf0ff" OR "2b66fb6d23be66863185cc1b67cac7410222b0b2" OR "d759364844d78a728505fb0485c3adbc") OR ("d759364844d78a728505fb0485c3adbc" AND "elf")))
```

**No AND-NOT noise filter** (unlike Data Exfiltration or Endpoint threats). Picus's email gateway detection doesn't need to filter rewind/cleanup noise because Email actions don't have a cleanup phase.

---

## Real worked example (ChainDrop)

```yaml
- name: ChainDrop Malware Dropper .JS Email Attack Variant-1
  title: Phishing
  description: ChainDrop is a JavaScript dropper …
  affected_os:
    - Windows
  malware_family: ChainDrop
  is_atomic: true
  ukc_phase: Delivery
  category: Malicious Code
  is_applicable_to_all_platforms: true
  execution_methods:
    - URL
  keyword_queries:
    - (("5526057" AND ("Attachment" OR "URL")) OR (("54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668" OR "e65b155ce74f3f81fb7d2b5b60f8e62b36e6d69c" OR "f92ee93a0af971a3966bfa8efa9c2625") OR ("f92ee93a0af971a3966bfa8efa9c2625" AND "js")))
  remote_files:
    - file: files/ZjkyZWU5M2EwYWY5NzFhMzk2NmJmYThlZmE5YzI2MjVfX19iZTJiMTM3Yy1iMjI1LTRiMzktOTk0OC1lZTU2MzNkMDBlNzYuanM=
      path: f92ee93a0af971a3966bfa8efa9c2625.js
      is_downloaded: true
```

---

## Authoring checklist

When hand-authoring an Email threat:

- [ ] `module: Email` at campaign level
- [ ] `severity: High`, `category: Malicious Code`, `ukc_phase: Delivery`, `is_atomic: true`, `is_applicable_to_all_platforms: true` — copy verbatim
- [ ] `title: Phishing` on every action
- [ ] `execution_methods` is `[- URL]` or `[- URL, - Attachment]`
- [ ] `remote_files` has exactly one entry with `file` / `path` / `is_downloaded`
- [ ] On-disk filename in `files/` matches `remote_files[].file` (base64-encoded)
- [ ] `keyword_queries` is one entry, three-arm OR, MD5 matches `path:`
- [ ] Objective `result_condition` references `%action-1%`
- [ ] Campaign `result_condition` references `%objective-N%` for every objective, `Operator: or`
- [ ] No MITRE `tactic` / `technique` fields
- [ ] ZIP password: `picus` (use `7z -mem=AES256 -tzip`, system `zip -P` is ZipCrypto and will fail)
</content>
</invoke>