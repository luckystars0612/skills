# Web Application / Cloud / URL Filtering / Data Exfiltration Module Reference

---

## Web Application Module

**Valid categories:** `Web Application`

Simulates HTTP-based attacks against web applications. Each action must reference
an HTTP request file stored inside the ZIP archive.

### Web Application Action Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `request_content` | **Yes** | String | Path to an HTTP request file inside the ZIP (e.g., `files/request.req`). File must exist. |

### HTTP Request File Format

The request file is a raw HTTP request stored as a plain text file:

```
POST /login HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything
```

### Web Application Campaign Example

```yaml
campaign:
  name: SQL Injection Login Bypass
  module: Web Application
  severity: High
  description: Simulates SQL injection attack targeting login form.
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Web Attack
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
          Operator: and
      actions:
        - name: sqli_login_bypass
          title: SQL Injection Login Bypass
          description: Attempts login bypass using classic SQL injection payload
          is_atomic: true
          ukc_phase: Exploitation
          category: Web Application
          tactic: TA0001
          technique: T1190
          owasp: Injection
          use_case: WebServer Attack - SQL Injection
          cve: CVE-2021-44228
          cwe: CWE-89
          keyword_queries:
            - (("sql injection" OR "login bypass"))
          request_content: files/sqli_login.req

        - name: xss_reflected
          title: Reflected XSS in Search Parameter
          is_atomic: true
          ukc_phase: Exploitation
          category: Web Application
          tactic: TA0001
          owasp: Injection
          use_case: WebServer Attack - XSS
          request_content: files/xss_search.req
```

---

## Data Exfiltration Module

**Valid categories:** `Data Exfiltration`

Simulates data theft scenarios. Can optionally include remote file payloads.

### Data Exfiltration Action Fields

| Field | Required | Type | Max Length | Description |
|---|---|---|---|---|
| `country` | No | String | 255 | Target country (from accepted Countries list). |
| `data_type` | No | String | 255 | Type of data being exfiltrated (from Data Types list). |
| `remote_files` | No | List | — | File payloads for the exfiltration simulation. |

### Accepted Countries
`Australia` · `Brazil` · `Canada` · `Generic` · `Germany` · `India` · `Italy` ·
`Malaysia` · `Mexico` · `Qatar` · `Singapore` · `Spain` · `Turkey` ·
`United Arab Emirates` · `United Kingdom` · `United State of America`

### Accepted Data Types
`IBAN` · `ITIN` · `NINO` · `Other` · `PCI` · `PII` · `SAM` · `SIN` ·
`Source Code` · `SSN` · `TFN` · `UTR`

### Data Exfiltration Campaign Example

```yaml
campaign:
  name: PII Data Exfiltration Simulation
  module: Data Exfiltration
  severity: Critical
  description: Simulates exfiltration of PII data to external server.
  affected_os:
    - Windows
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Exfiltration
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
          Operator: and
      actions:
        - name: exfil_pii
          title: Exfiltrate Customer PII Dataset
          description: Exfiltrates a mock PII dataset to a simulated C2 server
          is_atomic: true
          ukc_phase: Exfiltration
          category: Data Exfiltration
          tactic: TA0010
          technique: T1041
          country: United State of America
          data_type: PII
          keyword_queries:
            - (("data exfiltration" OR "customer data" OR "PII"))
          remote_files:
            - file: files/customer_data.csv
              path: customer_data.csv
              is_downloaded: true
```

---

## URL Filtering Module

**Valid categories:** `URL Filtering`

Tests URL category filtering. No remote files needed — exports/imports as `.yaml` only.

### URL Filtering Action Fields

| Field | Required | Type | Max Length | Description |
|---|---|---|---|---|
| `filter_url` | No | String | 255 | The URL to test against filtering controls. |
| `url_category` | No | String | 255 | Category of the URL (from URL Categories list). |

### URL Categories (full list)
`Abuse` · `Ads` · `Adult` · `Chat` · `Command & Control` · `Crypto` · `Dating` ·
`Drugs` · `Economy` · `Education` · `Entertainment` · `Fraud` · `Gambling` · `Games` ·
`Hacking` · `Jobsearch` · `Malware` · `News` · `Piracy` · `Redirect` · `Scam` ·
`Shopping` · `Socialmedia` · `Sports` · `Storage` · `Torrent` · `Tracking` ·
`Travelling` · `Weapons`

### URL Filtering Campaign Example

```yaml
campaign:
  name: C2 URL Category Filtering Test
  module: URL Filtering
  severity: Medium
  description: Tests whether URL filtering blocks known C2 infrastructure categories.
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Command and Control
      result_condition:
        "true": unblocked
        "false": blocked
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
          Operator: or
      actions:
        - name: c2_url_test
          title: Test C2 Category URL Access
          is_atomic: true
          ukc_phase: Command & Control
          category: URL Filtering
          tactic: TA0011
          filter_url: http://malware-c2.example.com/beacon
          url_category: Command & Control

        - name: malware_url_test
          title: Test Malware Distribution URL
          is_atomic: true
          ukc_phase: Delivery
          category: URL Filtering
          tactic: TA0001
          filter_url: http://malware-download.example.com/payload.exe
          url_category: Malware
```

---

## Cloud Emulation Modules (Azure / AWS / GCP)

### Azure Cloud Emulation
**Valid categories:** `Azure ARM`, `Azure Entra ID`, `Azure m365`

### AWS Cloud Emulation
**Valid categories:** `AWS`

### GCP Cloud Emulation
**Valid categories:** `GCP`

### Cloud Action Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `steps` | No | List | Attack commands to execute. Each item is a command string. |
| `rewind_steps` | No | List | Cleanup commands to reverse the attack. Each item is a command string. |

### Azure Cloud Campaign Example

```yaml
campaign:
  name: Azure Privilege Escalation Simulation
  module: Azure Cloud Emulation
  severity: High
  description: Simulates Azure Entra ID privilege escalation via role assignment abuse.
  affected_os:
    - Azure
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Privilege Escalation
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
          Operator: and
      actions:
        - name: azure_role_escalation
          title: Assign Global Administrator Role
          description: Attempts to assign Global Admin role to a compromised account
          is_atomic: true
          ukc_phase: Privilege Escalation
          category: Azure Entra ID
          tactic: TA0004
          technique: T1098
          keyword_queries:
            - (("role assignment" OR "Global Administrator" OR "privilege escalation"))
          steps:
            - "az login --service-principal -u $APP_ID -p $SECRET --tenant $TENANT_ID"
            - "az role assignment create --assignee $TARGET_USER --role 'Global Administrator'"
          rewind_steps:
            - "az role assignment delete --assignee $TARGET_USER --role 'Global Administrator'"

### AWS Cloud Campaign Example

```yaml
campaign:
  name: AWS S3 Data Exfiltration Simulation
  module: AWS Cloud Emulation
  severity: High
  description: Simulates unauthorized access and exfiltration of S3 bucket contents.
  affected_os:
    - AWS
  objectives:
    - type: Exfiltration
      actions:
        - name: s3_exfil
          title: Enumerate and Download S3 Bucket
          is_atomic: true
          ukc_phase: Exfiltration
          category: AWS
          tactic: TA0010
          technique: T1530
          steps:
            - "aws s3 ls s3://target-bucket/"
            - "aws s3 cp s3://target-bucket/ /tmp/exfil/ --recursive"
          rewind_steps:
            - "rm -rf /tmp/exfil/"
```
