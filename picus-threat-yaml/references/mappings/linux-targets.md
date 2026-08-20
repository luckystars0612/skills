# Linux Target File → MITRE / UKC / Output Mapping

The single source of truth for translating a sensitive file path or pattern into a
Picus action. The parser scripts and the `build_threat.py` orchestrator both consult
this table via the `_TARGET_TABLE` Python dict in `scripts/build_threat.py`.

Each row has these fields:

| Field | Meaning |
|---|---|
| `target_regex` | The file pattern from the SPL / Sigma / goal input. Used as lookup key. |
| `canonical_path` | The canonical absolute path that will be substituted into the `cat` argument. May use `$HOME` for user-relative paths. |
| `display_name` | Human-readable label embedded in the action `name` and `title`. |
| `tactic` | MITRE ATT&CK tactic ID (e.g. `TA0006`). |
| `technique` | MITRE ATT&CK technique ID (e.g. `T1003`). |
| `sub_technique` | Sub-technique ID or empty string if none. |
| `ukc_phase` | One of the values from `references/accepted-values.md` § UKC Phases. |
| `is_privileged` | True if the file is only readable as root. |
| `expected_output` | The substring that `cat <file>` will reliably print on a healthy agent — used as the `success_conditions.output` match. |
| `module` | `Linux Endpoint Scenario` (default for every row here). |

---

## Table

| target_regex | canonical_path | display_name | tactic | technique | sub | ukc_phase | is_priv | output |
|---|---|---|---|---|---|---|---|---|
| `/etc/shadow` | `/etc/shadow` | Read /etc/shadow | TA0006 | T1003 | T1003.008 | Credential Access | true | `root:` |
| `/etc/passwd` | `/etc/passwd` | Read /etc/passwd | TA0007 | T1083 | — | Discovery | false | `root:` |
| `/etc/gshadow` | `/etc/gshadow` | Read /etc/gshadow | TA0006 | T1003 | T1003.008 | Credential Access | true | `:` |
| `/etc/sudoers` | `/etc/sudoers` | Read /etc/sudoers | TA0004 | T1548 | T1548.001 | Privilege Escalation | true | `root` |
| `/etc/sudoers.d/` | `/etc/sudoers.d/` | List /etc/sudoers.d | TA0004 | T1548 | T1548.001 | Privilege Escalation | true | `ALL` |
| `/proc/net/tcp` | `/proc/net/tcp` | Read /proc/net/tcp | TA0007 | T1016 | — | Discovery | false | `sl` |
| `/proc/net/tcp6` | `/proc/net/tcp6` | Read /proc/net/tcp6 | TA0007 | T1016 | — | Discovery | false | `sl` |
| `/proc/net/arp` | `/proc/net/arp` | Read /proc/net/arp | TA0007 | T1018 | — | Discovery | false | `flags` |
| `/proc/net/` | `/proc/net/tcp` | Enumerate /proc/net | TA0007 | T1016 | — | Discovery | false | `sl` |
| `authorized_keys` | `$HOME/.ssh/authorized_keys` | Read SSH authorized_keys | TA0003 | T1098 | T1098.004 | Persistence | false | `ssh-` |
| `id_rsa` | `$HOME/.ssh/id_rsa` | Read SSH private key | TA0006 | T1552 | T1552.004 | Credential Access | false | `PRIVATE KEY` |
| `id_ed25519` | `$HOME/.ssh/id_ed25519` | Read SSH private key | TA0006 | T1552 | T1552.004 | Credential Access | false | `PRIVATE KEY` |
| `\.ssh/` | `$HOME/.ssh/` | List SSH directory | TA0007 | T1083 | — | Discovery | false | `id_` |
| `.bash_history` | `$HOME/.bash_history` | Read bash history | TA0006 | T1552 | T1552.003 | Credential Access | false | ` ` |
| `.bashrc` | `$HOME/.bashrc` | Read .bashrc | TA0003 | T1546 | T1546.004 | Persistence | false | `export` |
| `/etc/crontab` | `/etc/crontab` | Read /etc/crontab | TA0003 | T1053 | T1053.003 | Persistence | true | `SHELL=` |
| `/var/spool/cron/` | `/var/spool/cron/` | List cron spool | TA0003 | T1053 | T1053.003 | Persistence | true | `SHELL=` |
| `/etc/passwd-` | `/etc/passwd-` | Read /etc/passwd- | TA0006 | T1003 | T1003.008 | Credential Access | false | `root:` |
| `/etc/shadow-` | `/etc/shadow-` | Read /etc/shadow- | TA0006 | T1003 | T1003.008 | Credential Access | true | `root:` |
| `/etc/hosts` | `/etc/hosts` | Read /etc/hosts | TA0007 | T1016 | — | Discovery | false | `localhost` |
| `/etc/issue` | `/etc/issue` | Read /etc/issue | TA0007 | T1082 | — | Discovery | false | `Linux` |
| `/etc/os-release` | `/etc/os-release` | Read /etc/os-release | TA0007 | T1082 | — | Discovery | false | `NAME=` |

---

## Fallback row (when no row matches)

```yaml
tactic: TA0007
technique: T1083
sub_technique: ""
ukc_phase: Discovery
is_privileged: false
expected_output: " "              # any non-empty stdout
```

The skill emits a warning when the fallback is used so the user can extend the table.

---

## Pattern matching rules

The lookup is performed in this order:

1. **Exact match** on the literal token extracted from the SPL/Sigma/goal (e.g.
   `/etc/shadow`).
2. **Substring match** — if no exact match, look for any row whose `target_regex`
   appears as a substring of the input (e.g. `/proc/net/` matches `/proc/net/tcp`).
3. **Regex match** — if the input contains `\.`, treat it as a regex and search for
   any row whose `target_regex` matches as a regex.
4. **Fallback** — Discovery / T1083 / not privileged.

When multiple rows match in step 2, the **longest** `target_regex` wins.
