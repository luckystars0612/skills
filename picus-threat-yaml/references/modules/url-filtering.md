# URL Filtering Module Reference

`module: URL Filtering`

> **No canonical example exists under `~/Desktop/picus-threats/`.** This reference is
> compiled from the Picus module vocabulary and the bundled template doc. For exact
> keyword-queries syntax, cross-check a fresh export from Picus SCV when available.

---

## Module invariants

| Field | Value | Notes |
|---|---|---|
| `module` | `URL Filtering` (literal) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `[Windows]` or `[Linux, macOS]` | per action |
| `is_atomic` | `true` | always |
| `ukc_phase` | `Command & Control`, `Exfiltration` | varies |
| `category` | `URL Filtering` | always literal |
| `title` (action) | `URL Visit` | common form |
| `filter_url` | string | the URL the action will request |
| `url_category` | string | Picus URL category bucket |
| `comment` | optional | `auto-migrated` common |

**Goal of a URL Filtering threat:** have the simulated target visit a URL and verify
that the URL filtering control blocks (or allows) the request.

**Packaging:** URL Filtering threats export as `.yaml` only — no `files/` directory,
no remote files, no ZIP encryption required.

---

## Campaign-level shape

```yaml
campaign:
    name: <URL Filtering Campaign>
    description: <one-line blurb>
    module: URL Filtering
    severity: High
    affected_os:
        - <Windows | Linux | macOS>
    result_condition:                    # Operator: or
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

## Action-level — minimal field inventory

| Field | Type | Required | Example |
|---|---|---|---|
| `name` | string | yes | `URL Filtering - Phishing URL Variant-1` |
| `title` | string | yes | `URL Visit` |
| `description` | string | yes | short description |
| `comment` | string | optional | `auto-migrated` |
| `affected_os` | list | yes | per-action OS list |
| `is_atomic` | bool | yes | `true` |
| `ukc_phase` | string | yes | `Command & Control` / `Exfiltration` |
| `category` | string | yes | `URL Filtering` |
| `filter_url` | string | yes | `https://example.com/malicious-path` |
| `url_category` | string | yes | see vocabulary below |
| `keyword_queries` | list[string] | yes | one entry, OR'd over URL fragments |

**No `remote_files`, `play_processes`, `rewind_processes`, MITRE fields.**

---

## `url_category` — accepted values

Picus ships a fixed vocabulary of URL categories. Observed values include:

- `Phishing`, `Malware`, `Command and Control`, `Botnets`, `Spam`
- `Adult Content`, `Gambling`, `Dating`, `Social Networking`
- `Newly Registered Domains`, `Newly Observed Domains`
- `Parked Domains`, `Unreachable`, `Uncategorized`
- `Search Engines`, `Web Hosting`, `Webmail`, `Online Storage`

Use the exact spelling / casing Picus expects — wrong value → validation error on import.

---

## `keyword_queries` canonical template

The keyword query for URL Filtering actions is typically an OR over the hostname and
URL path fragments. There is no Picus page-id form (that's Web Application) and no
hash form (no payload).

```yaml
keyword_queries:
    - ("<hostname>" OR "<hostname>" AND "<path-fragment>")
```

Concrete example:

```yaml
keyword_queries:
    - ("malicious-domain.example" OR "malicious-domain.example" AND "/login")
```

**No AND-NOT noise filter** — URL Filtering doesn't share the rewind/process noise of
Endpoint modules.

---

## Result-condition semantics

- Campaign `Operator: or` (any URL visited = campaign visited)
- Action-level: not used (single-step URL visit)
- "unblocked" = the URL fetch went through (PASS — control failed to block)
- "blocked" = the control stopped the request

---

## Authoring checklist

- [ ] `module: URL Filtering` at campaign level
- [ ] `category: URL Filtering` on every action
- [ ] Every action has `filter_url` (full URL including scheme) and `url_category` from the vocabulary
- [ ] `keyword_queries` OR's over hostname / path fragments
- [ ] No `remote_files`, no `play_processes`, no MITRE fields
- [ ] No `files/` directory — `.yaml`-only export
</content>
</invoke>