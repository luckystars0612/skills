# Web Application Module Reference

`module: Web Application`

**Canonical examples to use as templates:**

- [Generic XSS Evasion Web Attack Campaign - 14](../../../Desktop/picus-threats/Generic%20XSS%20Evasion%20Web%20Attack%20Campaign%20-%2014/threat.yaml) — 7 XSS actions
- [Microsoft Sharepoint Web Attack Campaign](../../../Desktop/picus-threats/Microsoft%20Sharepoint%20Web%20Attack%20Campaign/threat.yaml) — 14 SharePoint CVE actions

---

## Module invariants (consistent across every Web Application action)

| Field | Value | Notes |
|---|---|---|
| `module` | `Web Application` (literal) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `[Windows, Linux, macOS]` (all three) | per-action can be narrower |
| `is_atomic` | `true` | always |
| `ukc_phase` | `Exploitation` | always |
| `category` | `Web Application` | always literal |
| `title` (action) | `Exploitation` | always literal |
| `keyword_queries` | one entry, single parenthesized Picus page id | NOT hash-based |
| `request_content` | one path inside the ZIP | one `.req` file per action |

**Goal of a Web Application threat:** simulate a single HTTP request against a web application. The control surface being tested is the WAF / IPS — not the application itself. **"unblocked" = the WAF let the request through** (PASS); "blocked" = the WAF stopped it (FAIL).

---

## Campaign-level shape

```yaml
campaign:
    name: <Vulnerability Class> Web Attack Campaign
    description: This campaign includes <Vulnerability Class> vulnerabilities. The purpose of the campaign is to cover <Vulnerability Class>'s web attacks.
    module: Web Application
    severity: High
    affected_os:
        - Windows
        - Linux
        - macOS
    affected_products:        # optional — used to scope by product family
        - Microsoft SharePoint
        # OR
        - Dynamic Web Applications
    result_condition:          # Operator: or across all objectives
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

---

## Objective-level shape

```yaml
- type: Exploitation                     # always literal
  result_condition:                      # single eq-term, Operator: or
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

**Almost always one action per objective** — Web Application threats are single-shot HTTP requests, not multi-step kill chains.

---

## Action-level — FULL field inventory

| Field | Type | Required | Example / value |
|---|---|---|---|
| `name` | string | yes | `Generic Reflected XSS Onslotchange Bypass Vulnerability Variant-1` |
| `title` | string | yes | `Exploitation` (literal) |
| `description` | string | yes | long prose describing the attack |
| `comment` | string | optional | `verified by evren`, `wats-auto-migrated`, `verified by rapid7` |
| `affected_os` | list | yes | action-level — can be narrower than campaign |
| `affected_product` *or* `affected_products` | string / list | optional | `Microsoft SharePoint`, `Dynamic Web Applications` |
| `affected_versions` | list | optional | `Microsoft .NET Framework 2.0 - 4.7.2, SharePoint Server 2010 - 2016` |
| `cve` | string | optional | `CVE-2021-31181` |
| `cwe` | string | optional | `CWE-79`, `CWE-94`, `CWE-502`, … |
| `owasp` | string | optional | `Injection`, `Software and Data Integrity Failures`, `Cryptographic Failures` |
| `use_case` | string | optional | `WebServer Attack - XSS`, `WebServer Attack - RCE`, `Known Vulnerability`, … |
| `is_atomic` | bool | yes | `true` |
| `ukc_phase` | string | yes | `Exploitation` |
| `category` | string | yes | `Web Application` |
| `is_applicable_to_all_platforms` | bool | usually | `true` |
| `is_wats_lite` | bool | optional | `true` if eligible for the lighter WATS-Lite simulator |
| `affected_platforms` | list | rare | alternative to `is_applicable_to_all_platforms` |
| `keyword_queries` | list[string] | yes | single entry `("page<digits>")` |
| `request_content` | string | yes | `files/<digits>.req` |

**Notably absent** (vs. Endpoint modules):

- No `play_processes` / `rewind_processes` (no process tree)
- No `success_conditions` (no process output)
- No `remote_files` (the request itself is the attack)
- No `tactic` / `technique` (MITRE absent — CVE/CWE used instead)
- No action-level `result_condition` (objective-level only)

---

## Web-specific field vocabulary

### `cwe` — MITRE CWE catalog number

Common values seen:

- `CWE-79` — Cross-site Scripting (XSS)
- `CWE-94` — Code Injection
- `CWE-20` — Improper Input Validation
- `CWE-346` — Origin Validation Error
- `CWE-347` — Improper Verification of Digital Signature
- `CWE-434` — Unrestricted Upload of File with Dangerous Type
- `CWE-502` — Deserialization of Untrusted Data

### `owasp` — OWASP Top 10 category label

Common values seen:

- `Injection`
- `Vulnerable and Outdated Components`
- `Software and Data Integrity Failures`
- `Cryptographic Failures`

### `use_case` — Picus internal use-case bucket

Common values seen:

- `WebServer Attack - XSS`
- `WebServer Attack - RCE`
- `WebServer Attack - Deserialization`
- `WebServer Attack - Unauthorized Access`
- `Known Vulnerability`

### `is_wats_lite`

- `true` — eligible for the lighter WATS-Lite simulator (faster run, smaller payload)
- absent / `false` — requires the full Web Application simulator
- Convention: newer auto-migrated actions carry `is_wats_lite: true`; older verified-by-human actions may omit it

---

## `request_content` and the `.req` file

`request_content` is a single string — a path inside the ZIP. Format:

```yaml
request_content: files/<digits>.req
```

The `.req` file itself is a raw HTTP request in plain text:

```
GET /page{PICUSID}/?p=x%3Ctemplate%20shadowrootmode%3Dopen%3E%3Cslot%20onsslotchange%3Dalert()%3E HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate

```

**Format invariants:**

- First line: `<METHOD> /page{PICUSID}/<rest-of-path> HTTP/1.1` — the `{PICUSID}` placeholder is **mandatory**; Picus substitutes it at replay time with the simulated session-specific page id.
- Subsequent lines: HTTP headers, one per line.
- **NEVER emit a `Host:` header.** The target host and port are supplied by the Picus assessment configuration at replay time, not by the `.req` file. Adding `Host:` conflicts with that injection and is wrong. None of the canonical examples contain a `Host:` line — the request line is followed directly by `User-Agent`. This applies even when the attack targets a specific host or a non-standard port (e.g. SAP on `:50000`): the host/port belongs in the assessment target, not the request file. Do not add `Host:` "to be safe" or because a captured request had one.
- The only headers to include are the ones the attack actually needs: `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`, plus `Authorization` / `Content-Type` / `Content-Length` / `Cookie` when the request body or auth requires them. No `Host`, and no invented headers.
- Blank line terminates headers.
- Optional body follows the blank line (URL-encoded or raw XML depending on `Content-Type`).
- Trailing blank line at end of file.

**POST example:**

```
POST /page{PICUSID}/_vti_bin/webpartpages.asmx HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: SOAPAction: http://microsoft.com/sharepoint/webpartpages/ValidateWorkflowMarkupAndCreateSupportObjects
Content-Type: text/xml; charset=utf-8
Content-Length: 1287

%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22utf-8%22%3F%3E%3Csoap%3AEnvelope%20...%3E
```

---

## `keyword_queries` — Picus page-id form

Every Web Application action's `keyword_queries` is a single-element list containing a single parenthesized string:

```yaml
keyword_queries:
    - ("page5356229")
```

The number `5356229` is a Picus-internal page/asset ID that matches the `.req` file. This is only a tracking key — no detection logic. Use the bare `("page<digits>")` form **only** when the threat will be graded purely by an inline WAF that inspects the request; it is **not** searchable in downstream logs (see next section).

---

## `keyword_queries` — content-based, log-resilient form (recommended for SIEM/Splunk detection)

When the goal is to **find this action's request in collected logs** (Splunk, Sentinel, Elastic, a WAF/proxy SIEM feed) — not just inline WAF grading — the page-id form does not work, and a naive single `AND` chain is fragile. Build a **resilient OR-of-arms** query instead. Two facts drive this:

1. **`page<PICUSID>` is unpredictable.** `{PICUSID}` in the `.req` is a macro Picus fills at replay time with its own session/asset id. You cannot know that number when authoring, so a hardcoded `("page1234")` will not match the logged URL. Never rely on it for log search.
2. **Every WAF/proxy/LB vendor logs a different subset of the request.** F5 BIG-IP ASM, Cloudflare, Check Point, Akamai, Imperva, nginx, mod_security each export different fields: some log the full URI with query string, some only the decoded path, some strip the query, **most do NOT log the request body**, few log arbitrary headers, and percent-encoding/case varies. A single `AND` chain that assumes one field misses on any device that logged a different one.

**Rule: write the query as an OR of self-sufficient arms — one per field the request touches — so whichever field a given device logged still produces a hit.** "Not this one, then that one."

```
(
     ( <arm keyed on the URL path> )
  OR ( <arm keyed on a query-string param/value> )
  OR ( <arm keyed on a request-body field/value> )
  OR ( <arm keyed on a distinctive header value> )
)
```

Rules for the arms:

- **Anchor on the path first.** The URL path (or a distinctive path segment) is the most universally logged artifact. Always include at least one **path-only** arm so the query still fires on devices that strip the query string and body.
- **Each arm must be self-sufficient.** `AND` only tokens that co-occur *in the same field*. Never `AND` a path token with a body token inside one arm — if that device didn't log the body, the whole arm fails. Split them into separate OR arms instead.
- **Body arms are fallbacks, never the sole anchor.** Most WAFs don't log the body. If the only thing separating the attack from benign traffic lives in the body (e.g. `has_admin_role:true`), still add the best path/query arm you have and accept that body-less loggers can only see "a request to this endpoint."
- **Cover encoding variants.** If a token contains characters a device may percent-encode, OR the decoded and encoded forms: `("../" OR "%2e%2e%2f")`, `("<script" OR "%3Cscript")`, `("UNION SELECT" OR "UNION%20SELECT")`. A space (`%20`) leaves words intact, but quotes, commas, slashes and angle brackets do not.
- **Prefer stable, attack-specific tokens** the request actually carries: the endpoint path, a distinctive query `param=value`, an injected payload string, a leaked-token prefix (`glpat-`), a unique username you created, a UUID that appears in both the URL and the body. Avoid generic single words (`password`, `admin`, `GET`) as a lone token.
- Add a trailing `AND NOT (...)` only when a specific benign source is known to collide.
- Every token you write must appear verbatim in the `.req` file. Verify before shipping.

**Worked examples** (every token is present in the actual request):

Zero-to-admin (`POST /api/users`, body `has_admin_role:true`) — body arms add precision, path arm survives body-less logging:
```
(("api/users" AND "has_admin_role") OR ("has_admin_role" AND "true") OR ("/api/users"))
```

SQL injection (`GET /api/v2.0/scans/.../log?sql=1 UNION SELECT ...`) — payload lands in the query, which many devices log:
```
(("api/v2.0/scans" AND "sql=") OR ("UNION" AND "SELECT") OR ("UNION%20SELECT") OR ("harbor_user"))
```

Repo dump with a leaked token in a header (`GET /api/v4/projects/.../repository/archive`, `PRIVATE-TOKEN: glpat-...`):
```
(("repository/archive") OR ("api/v4/projects" AND "archive.tar.gz") OR ("glpat-"))
```

App-specific POST envelope (`POST /RESTAdapter/snap-in/smcapp`, body carries a marker string):
```
(("RESTAdapter/snap-in/smcapp") OR ("RESTAdapter" AND "smcapp") OR ("SEND NOTIFICATIONS FROM SAP"))
```

The path arm carries most vendors; the query/body/header arms raise precision where those fields exist. Choose the content-based form whenever the threat's results will be reviewed in a SIEM; keep the `("page<digits>")` form only for pure inline-WAF grading.

---

## Real worked example (Generic XSS Variant-1)

```yaml
- name: Generic Reflected XSS Onslotchange Bypass Vulnerability Variant-1
  title: Exploitation
  description: This attack includes a GET request to Reflected Cross-Site Scripting attack. It could allow an attacker to inject JavaScript into the web application by bypassing filters via onslotchange method
  comment: verified by evren
  affected_os:
    - Windows
    - Linux
    - macOS
  affected_product: Dynamic Web Applications
  cwe: CWE-79
  owasp: Injection
  use_case: WebServer Attack - XSS
  is_atomic: true
  ukc_phase: Exploitation
  category: Web Application
  is_applicable_to_all_platforms: true
  is_wats_lite: true
  keyword_queries:
    - ("page5356229")
  request_content: files/5990.req
```

## Real worked example (SharePoint RCE with CVE)

```yaml
- name: Microsoft SharePoint Remote Code Execution Vulnerability
  title: Exploitation
  description: This attack includes a payload that exploits a critical remote code execution vulnerability in Microsoft SharePoint…
  comment: wats-auto-migrated
  affected_os:
    - Windows
  affected_platforms:
    - name: Windows 10
      architecture: 64-bit
  affected_versions:
    - 2013 SP1, 2016, 2019
  cve: CVE-2021-31181
  cwe: CWE-94
  owasp: Injection
  use_case: WebServer Attack - RCE
  is_atomic: true
  ukc_phase: Exploitation
  category: Web Application
  keyword_queries:
    - ("page594271")
  request_content: files/23.req
```

---

## Difference vs. Endpoint modules

| Aspect | Web Application | Endpoint Scenario |
|---|---|---|
| Action-level execution primitive | `request_content: files/<id>.req` (HTTP request replay) | `play_processes: [{path, arguments}]` (process tree) |
| Cleanup | none — request leaves no artifact | `rewind_processes: [...]` |
| Per-platform targeting | `is_applicable_to_all_platforms: true` (no distro block) | 16-Linux or 6-Windows distro block |
| Hash-based detection | no — just a Picus page-id `("page<digits>")` | SHA-256/SHA-1/MD5 of droppers in `keyword_queries` |
| Result-condition semantics | `unblocked` = WAF let the request through (PASS) | `unblocked` = the malicious command ran (PASS) |
| success / fail expression | none — outcome is binary "blocked vs not" | `success_conditions: [{output: "<substring>"}]` |
| Remote files / payload delivery | none — the `.req` file IS the request body | `remote_files: [...]` writes payload to disk first |
| Module-specific metadata | `cwe`, `owasp`, `use_case`, `is_wats_lite` | `affected_platforms`, `is_privileged` |
| Vulnerability tracking | `cve`, `cwe` central to the threat | optional |
| Per-action objective cardinality | almost always exactly 1 | variable (1–5+) |
| `result_condition` at action level | none | `%process-N%` |

---

## Authoring checklist

- [ ] `module: Web Application` at campaign level
- [ ] `severity: High`, `category: Web Application`, `ukc_phase: Exploitation`, `title: Exploitation` — copy verbatim
- [ ] `affected_os: [- Windows, - Linux, - macOS]` (or narrower per-action)
- [ ] Each action has `cwe`, `owasp`, `use_case` set from the vocabulary tables
- [ ] Each action's `keyword_queries` is content-based and log-resilient: an **OR of self-sufficient arms** (path arm + query/body/header arms), every token present verbatim in the `.req`, at least one **path-only** arm — NOT a bare `("page<digits>")` unless grading is pure inline-WAF (page ids are unpredictable at replay and unsearchable in logs)
- [ ] Each action has `request_content: files/<digits>.req` and a matching `.req` file exists in `files/`
- [ ] The `.req` file's first line uses `/page{PICUSID}/…` (mandatory placeholder)
- [ ] The `.req` file has **NO `Host:` header** (target host/port comes from the assessment config, not the request file) — the request line is followed directly by `User-Agent`
- [ ] If `cve` is set, add it; if `cwe` is set, validate against the CWE catalog
- [ ] Objective `result_condition` references `%action-1%`, Operator `or`
- [ ] Campaign `result_condition` references `%objective-N%` for every objective, Operator `or`
- [ ] No `play_processes` / `rewind_processes` / `success_conditions` / `remote_files` / `tactic` / `technique`
- [ ] ZIP password: `picus` (AES-256 via `7z -mem=AES256 -tzip`)
</content>
</invoke>