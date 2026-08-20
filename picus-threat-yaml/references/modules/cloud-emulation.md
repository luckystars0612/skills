# Cloud Emulation Module Reference

`module: Azure Cloud Emulation` / `AWS Cloud Emulation` / `GCP Cloud Emulation`

> **No canonical example exists under `~/Desktop/picus-threats/`.** This reference is
> compiled from the bundled template doc and Picus module vocabulary. Cloud Emulation
> differs from Endpoint modules in that the execution primitive is `steps:` (not
> `play_processes:`) and the unit being tested is the cloud control plane, not an
> on-host EDR.

---

## Module invariants (common across Azure / AWS / GCP)

| Field | Value | Notes |
|---|---|---|
| `module` | `Azure Cloud Emulation` / `AWS Cloud Emulation` / `GCP Cloud Emulation` | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `[- Azure]` / `[- AWS]` / `[- GCP]` | always matches the cloud |
| `is_atomic` | `true` | always |
| `category` | per-module — see below | |
| `steps` | list[step] | execution primitive (replaces `play_processes`) |
| `rewind_steps` | list[step] | cleanup (replaces `rewind_processes`) |

**Goal:** simulate a multi-step cloud attack (e.g. Recon → Exploit → Persistence →
Impact) against the cloud control plane; the simulated target is the cloud tenant.

---

## Module → Valid categories

| Module | Valid categories |
|---|---|
| `Azure Cloud Emulation` | `Azure ARM`, `Azure Entra ID`, `Azure m365` |
| `AWS Cloud Emulation` | `AWS` |
| `GCP Cloud Emulation` | `GCP` |

**Three Azure categories** map to three product surfaces:

- `Azure ARM` — Azure Resource Manager (compute, network, storage, IAM)
- `Azure Entra ID` — Entra ID (formerly Azure AD) tenant / identity
- `Azure m365` — Microsoft 365 workloads (Exchange, SharePoint, OneDrive, Teams)

---

## Action-level — minimal field inventory

| Field | Type | Required | Example |
|---|---|---|---|
| `name` | string | yes | `Recon: List Azure Resource Groups` |
| `description` | string | yes | threat-actor narrative |
| `affected_os` | list | yes | `[- Azure]` / `[- AWS]` / `[- GCP]` |
| `tactic` | string | optional | `TA0007` etc. |
| `technique` | string | optional | `T1087` etc. |
| `is_atomic` | bool | yes | `true` |
| `ukc_phase` | string | yes | `Reconnaissance`, `Execution`, … |
| `category` | string | yes | see table above |
| `steps` | list[step] | yes | one or more cloud actions |
| `rewind_steps` | list[step] | optional | cleanup |
| `keyword_queries` | list[string] | yes | one entry — boolean expression |

**No `play_processes`, no `remote_files`, no on-host execution primitives.**

---

## `steps` step shapes

A cloud step is a single cloud API call or a small group of related calls. Each step
carries:

| Step key | Type | Notes |
|---|---|---|
| `name` | string | step display name |
| `type` | string | the API/category — e.g. `Reconnaissance`, `Discovery`, `Exploitation` |
| `command` | string | the cloud CLI / API call (e.g. `az group list`) |
| `arguments` | list[string] | CLI flag-style arguments |
| `output` | string | expected output to feed `success_conditions` |
| `success_conditions` | list[cond] | see below |

**Concrete Azure ARM example:**

```yaml
steps:
  - name: List Azure Resource Groups
    type: Reconnaissance
    command: az group list
    arguments: []
    output: name
    success_conditions:
      - output: name
```

**Concrete Azure Entra ID example:**

```yaml
steps:
  - name: List Entra ID Users
    type: Discovery
    command: az ad user list
    arguments:
      - --query
      - "[].displayName"
    output: displayName
    success_conditions:
      - output: displayName
```

---

## `rewind_steps` substructure

Mirror of `steps`, but for cleanup (delete created resources, remove IAM grants, drop
created objects). Same shape; typically a subset of the `steps` operations run in
reverse order.

```yaml
rewind_steps:
  - name: Delete Resource Group Created Earlier
    type: Cleanup
    command: az group delete
    arguments:
      - --name
      - picus-test-rg
      - --yes
      - --no-wait
    success_conditions:
      - code: 0
```

**`success_conditions` in rewind steps often use `code: 0`** (cleanup is allowed to
silently succeed even if the resource doesn't exist), whereas the main `steps` use
`output: <substring>` (the actual exfiltration / persistence signal).

---

## Result condition

Cloud actions use `%step-N%` references in `result_condition`, where `N` is the
1-indexed position in `steps`.

```yaml
result_condition:
    true: unblocked
    false: blocked
    condition:
        Terms:
            - Right: {Value: unblocked}
              Left:  {Value: '%step-1%'}
              Operator: eq
        Operator: and
```

---

## `keyword_queries` canonical template

The keyword query for cloud actions is OR'd over:

1. The Picus 7-digit vector ID (analogous to Email) when auto-migrated
2. The CLI command / API verb
3. The step output fragment

```yaml
keyword_queries:
    - ("<vector-id>" OR ("<command>" AND "<output-fragment>"))
```

**No AND-NOT noise filter** is standard for cloud modules.

---

## MITRE mapping notes

Cloud Emulation threats map differently from Endpoint. Some Azure-arm categories don't
have a clean MITRE mapping, so tactic / technique are often omitted. When present,
common values:

- Reconnaissance: `TA0043` / `T1595` / `T1589`
- Discovery: `TA0007` / `T1087` / `T1069`
- Persistence: `TA0003` / `T1098`
- Privilege Escalation: `TA0004` / `T1078.004` (cloud accounts)
- Impact: `TA0040` / `T1485` / `T1486`

---

## Authoring checklist

- [ ] `module` set to `Azure Cloud Emulation` / `AWS Cloud Emulation` / `GCP Cloud Emulation` (exact spelling)
- [ ] `affected_os` matches: `[- Azure]` / `[- AWS]` / `[- GCP]`
- [ ] `category` from the per-module valid-categories table
- [ ] At least one `steps` entry
- [ ] `success_conditions` references `output:` (main steps) or `code: 0` (cleanup)
- [ ] `result_condition` references `%step-N%`, Operator `and`
- [ ] No `play_processes` / `rewind_processes` / `remote_files` (cloud doesn't use them)
- [ ] ZIP password: `picus` (AES-256 via `7z -mem=AES256 -tzip`)
</content>
</invoke>