# success_conditions.output — Pattern Catalog

The substring expected to appear in the action's stdout once the simulated attack
has run successfully. The skill's `build_threat.py` selects one of these per action
based on the target file. The catalog mirrors what the working samples use.

---

## File-type → output pattern

| Category | Output pattern | Why |
|---|---|---|
| `/etc/shadow`, `/etc/passwd`, `/etc/passwd-`, `/etc/shadow-` | `root:` | First line of all four files starts with `root:` |
| `/etc/gshadow` | `:` | Group shadow file lists `groupname:!::` — the colon is the most reliable byte |
| `/etc/sudoers` | `root` | sudoers begins with `root ALL=(ALL:ALL) ALL` |
| `/etc/sudoers.d/` | `ALL` | Files in `sudoers.d` contain `ALL=` rules |
| `/proc/net/tcp`, `/proc/net/tcp6` | `sl` | `/proc/net/tcp` columns start with header line `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt` |
| `/proc/net/arp` | `flags` | `/proc/net/arp` columns include `flags` |
| `/proc/net/` (generic) | `sl` | Defaults to the TCP column header |
| `authorized_keys` | `ssh-` | Each line starts with `ssh-rsa `, `ssh-ed25519 `, etc. |
| `id_rsa`, `id_ed25519` | `PRIVATE KEY` | PEM header `-----BEGIN ... PRIVATE KEY-----` |
| `\.ssh/` | `id_` | Directory listing contains `id_rsa`, `id_ed25519`, etc. |
| `.bash_history` | ` ` (single space) | Any non-empty line — fall back to a single space as the wildcard |
| `.bashrc` | `export` | Most .bashrc files contain `export PATH=` or `export ` at least once |
| `/etc/crontab` | `SHELL=` | System crontab starts with `SHELL=/bin/bash` |
| `/var/spool/cron/` | `SHELL=` | spool files contain the user's preferred shell path |
| `/etc/hosts` | `localhost` | Default hosts file has `127.0.0.1 localhost` |
| `/etc/issue` | `Linux` | Default issue banner contains `Linux` |
| `/etc/os-release` | `NAME=` | systemd os-release has `NAME="Ubuntu"` etc. |

---

## Fallback output

When the target is unknown, use:

```yaml
success_conditions:
  - output: " "          # single space — matches any non-empty stdout
```

This is the weakest assertion — it only proves the process produced output —
but it is portable across all targets.

---

## Negative checks (`is_inverse: true`)

Used in PUMAKIT once, to assert that the rewind **removed** a file:

```yaml
success_conditions:
  - output: removeself
    is_inverse: true
```

The skill does not emit these by default.

## Why `output:` and not `code: 0`?

The broken sample uses `code: 0` (exit-code) plus `is_inverse: false`. This passes
on every successful `cat` — but the same `code: 0` happens when the action is
blocked at the network level (connection timeout). The `output:` substring check
is content-aware: the agent must have actually emitted the expected bytes for the
action to count as "unblocked". PUMAKIT and Kubernetes C2 use this style and
their actions are correctly graded by the Picus validator.
