# Data Exfiltration Module Reference

`module: Data Exfiltration`

**Canonical example to use as a template:**

- [PDF Format Data Exfiltration Campaign](../../../Desktop/picus-threats/PDF%20Format%20Data%20Exfiltration%20Campaign/threat.yaml) — 21 actions, one per country/data-type combo, each with a sample PDF in `files/`

---

## Module invariants (consistent across every Data Exfiltration action)

| Field | Value | Notes |
|---|---|---|
| `module` | `Data Exfiltration` (literal) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `[Windows, macOS, Linux]` (all three) | always |
| `is_atomic` | `true` | always |
| `ukc_phase` | `Exfiltration` | always |
| `category` | `Data Exfiltration` | always literal |
| `title` (action) | `Exfiltration` | always literal |
| `comment` | `auto-migrated` | always literal — the literal string `auto-migrated` |
| `is_applicable_to_all_platforms` | `true` | always |
| `country` | string | see Country table |
| `data_type` | string | see Data Type table |
| `remote_files` | one entry | PDF sample |
| `keyword_queries` | one entry | see canonical template below |

**Goal of a Data Exfiltration threat:** simulate uploading a sensitive document to an external server and verify that the security control (DLP / file-upload filter / sandbox) detects and blocks it. **"unblocked" = the data leaked** (FAIL — bad); "blocked" = the control stopped it (PASS).

---

## Campaign-level shape

```yaml
campaign:
    name: <Format> Data Exfiltration Campaign
    description: This campaign includes exfiltrating documents with <Format> format.
    module: Data Exfiltration
    severity: High
    affected_os:
        - Windows
        - macOS
        - Linux
    result_condition:                       # Operator: or (any leak = campaign leaked)
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

**No `threat_actor`, `affected_products`, `comment` at campaign level.**

---

## Objective-level shape

```yaml
- type: Exfiltration                   # always literal
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
    - # ...
```

**Always one action per objective.**

---

## Action-level — FULL field inventory

| Field | Type | Required | Example / value |
|---|---|---|---|
| `name` | string | yes | `Brazil CPF Number Exfiltration PDF Format (10 Records)` |
| `title` | string | yes | `Exfiltration` (literal) |
| `description` | string | yes | `'This attack includes uploading a document that contains...'` (single-quoted because contains `:`, `\n`, etc.) |
| `comment` | string | yes | `auto-migrated` (literal string, always) |
| `affected_os` | list | yes | `[Windows, macOS, Linux]` (all three) |
| `country` | string | yes | see Country table |
| `data_type` | string | yes | see Data Type table |
| `is_atomic` | bool | yes | `true` |
| `ukc_phase` | string | yes | `Exfiltration` |
| `category` | string | yes | `Data Exfiltration` |
| `is_applicable_to_all_platforms` | bool | yes | `true` |
| `keyword_queries` | list[string] | yes | one entry — see canonical template below |
| `remote_files` | list[object] | yes | one PDF entry — `file` (base64), `path` (numeric_id.pdf), `is_downloaded: true` |

**Notably absent** (vs. Endpoint/File Download):

- No `tactic` / `technique` / `sub_technique` (MITRE absent)
- No `malware_family`
- No `play_processes` / `rewind_processes`
- No `success_conditions` / `fail_conditions`
- No `cwe` / `owasp` / `cve`

---

## `country` — accepted values

Single string. Observed values:

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
| `United State of America` (sic — typo preserved) |

---

## `data_type` — accepted values

Single string. Observed values:

| Data type |
|---|
| `IBAN` |
| `ITIN` |
| `NINO` |
| `Other` |
| `PCI` |
| `PII` |
| `SAM` |
| `SIN` |
| `Source Code` |
| `SSN` |
| `TFN` |
| `UTR` |

The canonical PDF campaign uses the verbose forms `PCI (Payment Card Industry)`, `PII (Personally Identifiable Information)`, `NINO (National Insurance Number)` — both short and verbose forms appear in different campaigns.

---

## `remote_files` substructure

```yaml
remote_files:
    - file: files/<base64(NUMERIC_ID)>___<base64(UUID)>.pdf
      path: <NUMERIC_ID>.pdf
      is_downloaded: true
```

**Two fields per entry — exactly.** No `is_executable`, no `skip_zip_extract`. Every Data Exfiltration `remote_files` entry has `is_downloaded: true`.

**Filename encoding.** Same base64 convention as File Download / Email. On-disk filename in `files/` is base64-encoded; `path:` is the plain numeric ID + `.pdf` extension. Picus decodes server-side.

Real examples from the canonical campaign:

```yaml
# UAE Financial Data
remote_files:
    - file: files/MjI3NDQ4X19fMzZkNWQ1MzctYzc5NC00ZDgzLTg4NDMtNGVmNzJkNDhlODAzLnBkZg==
      path: 227448.pdf
      is_downloaded: true

# Brazil CPF
remote_files:
    - file: files/MjQ4NTU4X19fY2RmYzU3OGMtMDgyMS00NjBjLWI0NmYtYTg0MTQzNDRjZDgxLnBkZg==
      path: 248558.pdf
      is_downloaded: true
```

---

## `keyword_queries` canonical template

Every Data Exfiltration action's `keyword_queries` is a single-element list containing this shape:

```yaml
keyword_queries:
    - (((("act_id" AND "<ACT_ID>") OR "-<ACT_ID>-" OR "|<ACT_ID>|")
        OR
        (("<SHA-256>" OR "<SHA-1>" OR "<MD5>")
         OR
         ("<NUMERIC_ID>" AND "pdf")))
       AND NOT ("picexfil" AND "short-url"))
```

Three arms (top-level OR'd):

1. **Picus-internal act_id arm:** `("act_id" AND "<5-digit-id>") OR "-<id>-" OR "|<id>|"` — covers different ways the Picus backend tags the action in logs.
2. **Hash arm:** SHA-256 / SHA-1 / MD5 of the PDF, in that exact order.
3. **Filename-and-ext arm:** numeric ID followed by `AND "pdf"`. Redundant with the hash arm, but covers detectors that key on the numeric ID + extension co-occurrence.

Wrapped in **`AND NOT ("picexfil" AND "short-url")`** — this is the Data-Exfiltration-specific noise filter. `picexfil` is the Picus-internal exfil-vector token; `short-url` is a common evasion (URL shortener) that Picus telemetry picks up. Filtering both prevents false positives from the simulation infrastructure itself.

Concrete example (Brazil CPF):

```yaml
keyword_queries:
    - (((("act_id" AND "21419") OR "-21419-" OR "|21419|") OR (("704b1ee938e73f06a758bc4cc9b42de90c6ce15b" OR "dd8853f88be63e88e006e71999e40a503d7b8afe77e101019ee713fbb04a2fb7" OR "dde0d56c598af7c390e74a3df257a929") OR ("248558" AND "pdf"))) AND NOT ("picexfil" AND "short-url"))
```

---

## Real worked example (PCI, UAE)

```yaml
- name: United Arab Emirates Financial Data Information Exfiltration PDF Format (25 records)
  title: Exfiltration
  description: 'This attack includes uploading a document that contains the following Financial Data Information specialized for United Arab Emirates in .pdf format: Name Surname, Emirates ID, IBAN, Credit Card Number. Sample data: Name Surname:Assad Alim, Emirates ID:784-1950-9455365-1, IBAN:AE110354547093502959052, Credit Card Number: 4612541421548467.'
  comment: auto-migrated
  affected_os:
    - Windows
    - macOS
    - Linux
  country: United Arab Emirates
  data_type: PCI (Payment Card Industry)
  is_atomic: true
  ukc_phase: Exfiltration
  category: Data Exfiltration
  is_applicable_to_all_platforms: true
  keyword_queries:
    - (((("act_id" AND "21442") OR "-21442-" OR "|21442|") OR (("8e3db48339a77fe8f196f404557b90cc416bd74b" OR "fd77ed25f2345c1d23cf18f059dd1073b149ef0152bbc1e03fd167146d1d01eb" OR "5cbdbc2d195832262eadff65e390bfbf") OR ("227448" AND "pdf"))) AND NOT ("picexfil" AND "short-url")
  remote_files:
    - file: files/MjI3NDQ4X19fMzZkNWQ1MzctYzc5NC00ZDgzLTg4NDMtNGVmNzJkNDhlODAzLnBkZg==
      path: 227448.pdf
      is_downloaded: true
```

---

## PDF payload conventions

Sample PDFs follow a consistent pattern:

- PDF 1.3 format
- A4 portrait (`/MediaBox [0 0 595 842]`)
- Generated by an XSL-FO stylesheet (e.g. `ARAB10.xslx` for Arabic / UAE templates)
- Fonts: Calibri + Calibri-Bold (TrueType, subset)
- 1 page per document
- Stream filter: FlateDecode (deflate)

The PDF is real and contains synthetic but realistic-looking data (Name, IBAN, NINO, Credit Card, Address, etc.) — Picus uses the file content to test DLP detectors.

---

## Difference vs. File Download

| Aspect | Data Exfiltration | File Download |
|---|---|---|
| `module` | `Data Exfiltration` | `File Download` |
| Objective `type` | `Exfiltration` | `Delivery` |
| Action `title` | `Exfiltration` | `Download` |
| Action `ukc_phase` | `Exfiltration` | `Delivery` |
| Action `category` | `Data Exfiltration` | `Malicious Code` |
| Action `comment` | `auto-migrated` | absent |
| `country`, `data_type` | **PRESENT** (required) | absent |
| `malware_family` | absent | **PRESENT** |
| Description start | `"This attack includes uploading a document..."` | threat-actor narrative |
| `affected_os` | `[Windows, macOS, Linux]` | narrower — typically single OS |
| `keyword_queries` AND-NOT | `AND NOT ("picexfil" AND "short-url")` | none |
| File extension in `keyword_queries` | `"pdf"` | `"exe"` / `"dll"` / `"elf"` / `"so"` |

---

## Authoring checklist

- [ ] `module: Data Exfiltration` at campaign level
- [ ] `affected_os: [- Windows, - macOS, - Linux]` (all three)
- [ ] Every action has `country` and `data_type` set from the accepted-values tables
- [ ] `comment: auto-migrated` (literal string) on every action
- [ ] `category: Data Exfiltration`, `ukc_phase: Exfiltration`, `title: Exfiltration` — copy verbatim
- [ ] `remote_files` has exactly one entry with `file` (base64), `path` (numeric_id.pdf), `is_downloaded: true`
- [ ] A real PDF (with realistic-looking data) exists in `files/` matching `remote_files[].file`
- [ ] `keyword_queries` ends with `AND NOT ("picexfil" AND "short-url")`
- [ ] `keyword_queries` numeric ID matches `remote_files[].path` (sans `.pdf`)
- [ ] Objective `result_condition` references `%action-1%`, Operator `or`
- [ ] Campaign `result_condition` references `%objective-N%` for every objective, Operator `or`
- [ ] No MITRE `tactic` / `technique`, no `play_processes`, no `rewind_processes`, no `success_conditions`
- [ ] ZIP password: `picus` (AES-256 via `7z -mem=AES256 -tzip`)
</content>
</invoke>