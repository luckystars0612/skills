# File Download Module Reference

`module: File Download`

**Canonical examples to use as templates:**

- [CRPX0 Ransomware Download Threat](../../../Desktop/picus-threats/CRPX0%20Ransomware%20Download%20Threat/threat.yaml) — 4 variants (3 `.exe`, 1 `.dll`)
- [Kimwolf Botnet Download Threat](../../../Desktop/picus-threats/Kimwolf%20Botnet%20Download%20Threat/threat.yaml) — 6 variants (3 `.elf`, 3 `.so`)

---

## Module invariants (consistent across every File Download action)

| Field | Value | Notes |
|---|---|---|
| `module` | `File Download` (literal) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | single-element list | typically `[Windows]` (CRPX0) or `[Linux]` (Kimwolf); also `[macOS]` is accepted |
| `is_atomic` | `true` | always |
| `ukc_phase` | `Delivery` | always |
| `category` | `Malicious Code` | only canonical category seen (`Vulnerability Exploitation` also accepted) |
| `is_applicable_to_all_platforms` | `true` | always |
| `title` (action) | `Download` | always literal |
| `comment` | absent | File-Download threats don't carry an action-level comment |

**Goal of a File Download threat:** deliver a malicious binary through a network download channel and verify that the binary is *not* blocked by network / file-download controls. There is no execution — just delivery. The control surface is NGFW / IPS / file-sandbox.

---

## Campaign-level shape

```yaml
campaign:
    name: <Malware Family> Download Threat
    description: <one-line blurb>
    module: File Download
    severity: High
    affected_os:
        - <Windows|Linux|macOS>            # pick the OS the malware targets
    result_condition:                       # one eq-term per objective, Operator: or
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

**No `threat_actor`, `affected_products`, `comment`, or `affected_platforms` block.** File Download doesn't scope to OS distros — just `affected_os`.

---

## Objective-level shape

```yaml
- type: Delivery
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

**Always one action per objective** — File Download is a single-shot delivery test per variant.

---

## Action-level — FULL field inventory

Every File Download action carries exactly these fields:

| Field | Type | Example / value |
|---|---|---|
| `name` | string | `CRPX0 Ransomware .EXE File Download Variant-1` |
| `title` | string | `Download` (literal) |
| `description` | string | long prose (malware intel write-up) |
| `affected_os` | list | `[<Windows|Linux|macOS>]` (duplicated from campaign) |
| `malware_family` | string | `CRPX0`, `Kimwolf` |
| `is_atomic` | bool | `true` |
| `ukc_phase` | string | `Delivery` |
| `category` | string | `Malicious Code` |
| `is_applicable_to_all_platforms` | bool | `true` |
| `keyword_queries` | list[string] | exactly one entry — see canonical template below |
| `remote_files` | list[object] | exactly one entry — three fields (`file`, `path`, `is_downloaded`) |

**Fields that NEVER appear on a File Download action:**

- No `tactic` / `technique` / `sub_technique` (MITRE absent)
- No `play_processes` / `rewind_processes` (no execution)
- No `success_conditions` / `fail_conditions` (no process output)
- No `steps` / `rewind_steps` (cloud-only)
- No `request_content` (web-only), `execution_methods` (email-only)
- No `filter_url` / `url_category` (URL Filtering), `country` / `data_type` (Data Exfiltration)
- No `affected_platforms` (OS distro scoping absent for this module)

---

## `remote_files` substructure

```yaml
remote_files:
    - file: files/<base64(MD5)>___<base64(UUID)>.<ext>     # path inside ZIP
      path: <MD5>.<ext>                                    # on-target filename
      is_downloaded: true
```

**Three fields per entry — exactly.** No `is_executable` (the binary's executability is implied by the file type), no `skip_zip_extract` (File Download payloads are flat binaries, not nested archives).

**Filename encoding.** On-disk filename in `files/` is base64-encoded. Format: `<base64(MD5)>___<base64(UUID)>.<ext>`. Picus decodes server-side.

Real variants from CRPX0 (note the consistent pattern):

```yaml
# .EXE Variant-1
remote_files:
    - file: files/MmZmODZhNGZkZmVjLLY3ZjQ5ZDU1NDVmOWE2MmVjNGNfX18wZmIwM2U4Yi03NzU2LTQ3Y2YtOTQ5Zi0zN2NiMGU0MTdiNmQuZXhl
      path: 2ff86a4fdfec4a5b49d5545f9a62ec4c.exe
      is_downloaded: true

# .EXE Variant-2
remote_files:
    - file: files/Y2MyYzhhYzVhZWE4ZDdjMzZlOTE2MWQ1NGU0MjU1ZjNfX19hNWM5MDAzOC02YmFlLTRkNjgtYWE2Yy1iMTY4ZGEyZmM2NWEuZXhl
      path: cc2c8ac5aea8d7c36e9161d54e4255f3.exe
      is_downloaded: true

# .DLL Variant-1
remote_files:
    - file: files/YThlOWE2MzhhYTllMWMyZDczZjM0MzJiOTk3ZDdhN2ZfX18wYTI3YTc3Yy01NWRmLTQwMzItOWEwNC1kOGRlZDY0ODE4NDAuZGxs
      path: a8e9a638aa9e1c2d73f3432b997d7a7f.dll
      is_downloaded: true
```

The MD5 in `path:` MUST match the MD5 in `keyword_queries`. The extension (`.exe`, `.dll`, `.elf`, `.so`, `.bin`, …) goes into both fields.

---

## `keyword_queries` canonical template

Every File Download action's `keyword_queries` is a single-element list containing this exact shape:

```
(("<SHA-256>" OR "<SHA-1>" OR "<MD5>") OR ("<MD5>" AND "<file_extension>"))
```

Two arms, both OR'd together:

1. **Hash arm.** OR over the SHA-256, SHA-1, and MD5 of the payload file, in that exact order.
2. **Filename-and-ext arm.** MD5 hex followed by `AND "<ext>"`. Redundant with the hash arm, but covers detectors that key on file-extension co-occurrence.

Concrete example (CRPX0 .EXE Variant-1):

```yaml
keyword_queries:
    - (("28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11" OR "3c92be8d6c8380bb7122a80aa3f9880fa81e64ec" OR "2ff86a4fdfec4a5b49d5545f9a62ec4c") OR ("2ff86a4fdfec4a5b49d5545f9a62ec4c" AND "exe"))
```

**No AND-NOT noise filter, no 7-digit vector ID** (unlike Email). Just the binary fingerprint.

---

## Real worked example (CRPX0 .EXE Variant-1)

```yaml
- name: CRPX0 Ransomware .EXE File Download Variant-1
  title: Download
  description: CRPX0 is a newly emerged cybercriminal group that transitioned from running cryptocurrency scams to operating a full Ransomware-as-a-Service…
  affected_os:
    - Windows
  malware_family: CRPX0
  is_atomic: true
  ukc_phase: Delivery
  category: Malicious Code
  is_applicable_to_all_platforms: true
  keyword_queries:
    - (("28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11" OR "3c92be8d6c8380bb7122a80aa3f9880fa81e64ec" OR "2ff86a4fdfec4a5b49d5545f9a62ec4c") OR ("2ff86a4fdfec4a5b49d5545f9a62ec4c" AND "exe"))
  remote_files:
    - file: files/MmZmODZhNGZkZmVjLLY3ZjQ5ZDU1NDVmOWE2MmVjNGNfX18wZmIwM2U4Yi03NzU2LTQ3Y2YtOTQ5Zi0zN2NiMGU0MTdiNmQuZXhl
      path: 2ff86a4fdfec4a5b49d5545f9a62ec4c.exe
      is_downloaded: true
```

---

## Difference vs. Email

| Aspect | File Download | Email |
|---|---|---|
| Delivery vector | network (NGFW / sandbox sees it) | email gateway (secure-mail-gateway sees it) |
| `execution_methods` field | absent | `[- URL]` and/or `[- Attachment]` |
| `keyword_queries` arms | SHA-256 / SHA-1 / MD5 / `<MD5> AND <ext>` | adds a 7-digit vector-ID arm: `("<VID>" AND ("Attachment" OR "URL"))` |
| Affected OS scope | `[Windows]` / `[Linux]` / `[macOS]` | typically `[Linux]` or `[Windows]` |
| `affected_platforms` block | absent | absent |
| Payload on-target filename | base64(MD5).ext | base64(MD5).ext (same convention) |

---

## Authoring checklist

When hand-authoring a File Download threat:

- [ ] `module: File Download` at campaign level
- [ ] `severity: High`, `category: Malicious Code`, `ukc_phase: Delivery`, `title: Download` — copy verbatim
- [ ] Pick `affected_os` to match the malware's target (`[Windows]` / `[Linux]` / `[macOS]`)
- [ ] `remote_files` has exactly one entry per action: `file` (base64), `path` (MD5.ext), `is_downloaded: true`
- [ ] On-disk filename in `files/` matches `remote_files[].file`
- [ ] `keyword_queries` is one entry, two-arm OR (SHA-256 / SHA-1 / MD5 / `<MD5> AND <ext>`)
- [ ] MD5 in `path:` matches MD5 in `keyword_queries`
- [ ] Objective `result_condition` references `%action-1%`, Operator `or`
- [ ] Campaign `result_condition` references `%objective-N%` for every objective, Operator `or`
- [ ] No MITRE `tactic` / `technique`, no `play_processes`, no `rewind_processes`
- [ ] ZIP password: `picus` (AES-256 via `7z -mem=AES256 -tzip`)
</content>
</invoke>