# Kubernetes Endpoint Scenario Module Reference

`module: Kubernetes Endpoint Scenario`

**Canonical example to use as a template:**

- [Command and Control Kubernetes Micro Emulation Plan](../../../Desktop/picus-threats/Command%20and%20Control%20Kubernetes%20Micro%20Emulation%20Plan/threat.yaml) — 13 actions, MITRE TA0011 micro emulation, all Linux process execution

---

## Module invariants (consistent across every Kubernetes Endpoint action)

| Field | Value | Notes |
|---|---|---|
| `module` | `Kubernetes Endpoint Scenario` (literal) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `[- Linux]` | always Linux (the threat simulates attacker foothold on a K8s node) |
| `affected_platforms` | 15–16 entry Linux block | RHEL 8/9/10, Rocky 8/9, Ubuntu 20.04/22.04/24.04, CentOS 8/9, Debian 10/11/12, Alpine 3.21/3.22, SUSE 15.6/15.7 — see `references/mappings/linux-platforms.md` |
| `is_atomic` | `true` | always |
| `category` | `Attack Scenario` | always literal |
| `title` (action) | `Kubernetes Attack` | **always literal on every action** |
| `is_privileged` | never used | absent on every action |
| `sub_technique` | optional | only set when the technique has a meaningful `.NNN` child |
| `result_condition` join at action level | `Operator: and` | always intersection of step success |
| `result_condition` join at campaign level | `Operator: or` | **NB:** opposite of Linux Endpoint — K8s uses `or` |

**Important:** the canonical K8s threat contains **zero kubectl / kubeconfig / pod / namespace / cluster references**. The `module: Kubernetes Endpoint Scenario` tag is metadata — the actual play_processes are pure Linux process execution on a node. The Picus scheduling routes these to K8s node agents.

---

## Module structure

```yaml
campaign:
    name: <Tactic> Kubernetes Micro Emulation Plan         # literal phrase pattern
    description: 'This threat contains a micro emulation plan for MITRE Tactic: <TAxxxx> - <Tactic Name>. …'
    module: Kubernetes Endpoint Scenario
    severity: High
    affected_os:
        - Linux
    result_condition:                       # Operator: or across all objectives
        true: unblocked
        false: blocked
        condition:
            Terms:
                - {Right: {Value: unblocked}, Left: {Value: '%objective-1%'}, Operator: eq}
                # ... up to '%objective-N%'
            Operator: or
    objectives:                             # one action per objective (atomic)
        - type: <umbrella category>         # see "Objective type" below
          # ...
```

---

## Objective type — umbrella category

K8s objectives use an **umbrella category** rather than the raw MITRE tactic:

- `Command and Control` — for any C2-related action (even ones that map to MITRE `TA0002` Execution)
- `Execution` — for actions whose raw MITRE tactic is Execution

The raw MITRE `tactic` / `technique` / `sub_technique` only appear at the action level.

The objective-level `result_condition` always references `%action-1%` with `Operator: or` (single-term `or` is degenerate but that's the canonical form).

---

## Action-level — FULL field inventory

| Field | Type | Required | Example / value |
|---|---|---|---|
| `name` | string | yes | `Test Initial Connection via Melofee Malware Implant` |
| `title` | string | yes | **`Kubernetes Attack`** (literal on every action) |
| `description` | string | yes | `In this action, an attacker is trying to …` |
| `tactic` | string | yes | `TA0011`, `TA0002` |
| `technique` | string | yes | `T1095`, `T1571`, `T1105`, `T1090`, `T1041`, `T1059` |
| `sub_technique` | string | optional | `T1059.004`, `T1090.001` |
| `affected_os` | list | yes | `[- Linux]` |
| `affected_platforms` | list[object] | yes | 15–16 entry Linux distro block (see linux-platforms.md) |
| `is_atomic` | bool | yes | `true` |
| `ukc_phase` | string | yes | `Command & Control`, `Execution` |
| `category` | string | yes | `Attack Scenario` |
| `is_applicable_to_all_platforms` | bool | usually | `true` |
| `result_condition` | object | yes | `%process-N%` references, Operator `and` |
| `play_processes` | list[step] | yes | 2–4 sequential shell steps |
| `rewind_processes` | list[step] | yes | cleanup commands |
| `keyword_queries` | list[string] | yes | exactly one boolean expression |

**Notably absent** (vs. Linux Endpoint):

- No `is_privileged` ever
- No per-action descriptive string for `title` — every `Action is the literal `Kubernetes Attack`

---

## `play_processes` step substructure

Each step is one of these shapes:

| Shape | Example |
|---|---|
| Pure command | `- arguments: echo "Successfully" > "$WORKDIR"/tmp.txt` |
| Async + timeout | `- arguments: nc -lvnp 16789 > "$WORKDIR"/s.txt`<br>`  is_async: true`<br>`  timeout: 5000` |
| Delayed verification | `- arguments: ss -tulnp \| grep 0.0.0.0:1234`<br>`  delay: 3000`<br>`  success_conditions:`<br>`    - output: LISTEN` |
| Interpreter + arguments | `- path: /bin/sh`<br>`  arguments: '"$WORKDIR"/dummy_downloader.sh $remotefile11673'` |
| Download-and-execute | `- arguments: '"$WORKDIR"/TinyShell_host -s PicusPicusPicus -p 1234'`<br>`  remote_files:`<br>`    - file: files/<base64-name>`<br>`      path: TinyShell_host`<br>`      is_executable: true`<br>`      is_downloaded: true` |
| Final success check | `- arguments: cat "$WORKDIR"/output.txt`<br>`  delay: 5000`<br>`  success_conditions:`<br>`    - output: root` |

**Step keys in use:** `arguments` (always), `path`, `is_async`, `timeout` (ms), `delay` (ms), `remote_files`, `success_conditions`.

**`"$WORKDIR"`** is the Picus working-directory placeholder — quoted in the argument string, expanded at execution time.

**`$remotefile<digits>`** is a Picus-injected URL placeholder for wget/sh-script downloader actions (only seen in `T1105`-style file-transfer actions).

**`remote_files[].path`** is a bare filename (no directory prefix) — it lands directly under `$WORKDIR`. Multiple `remote_files` per step are allowed (action 8 has 2 — payload + wrapper script).

---

## `rewind_processes` substructure

Flat list of `{arguments: <cleanup command>}` items. Canonical pattern:

```yaml
rewind_processes:
    - arguments: kill -9 $(ss -tulnp | grep 4444 | grep -o 'pid=[0-9]*' | cut -d= -f2)
    - arguments: pkill -9 test_client_melofee
    - arguments: pkill -9 implant
    - arguments: rm -rf "$WORKDIR"/test_client* "$WORKDIR"/implant
    - arguments: rm -rf /tmp/implant_relay.sock
```

The consistent idea: kill the running binary/process by name or by listening port, then `rm -rf` the staged artifacts from `$WORKDIR` and any `/tmp/*` scratch.

---

## `result_condition` at action level

References `%process-N%` (1-indexed by position in `play_processes`). Always `Operator: and` (intersection of step success).

```yaml
result_condition:
    true: unblocked
    false: blocked
    condition:
        Terms:
            - {Right: {Value: unblocked}, Left: {Value: '%process-1%'}, Operator: eq}
            - {Right: {Value: unblocked}, Left: {Value: '%process-2%'}, Operator: eq}
        Operator: and
```

Common variations: 1-process (most actions), 2-process (default), 3-process (exfil actions). Use as many terms as you have meaningful steps; the last `%process-N%` is usually the success-check step.

---

## `keyword_queries` canonical template

```yaml
keyword_queries:
    - ( (<DETECT-OR> ) AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf")) )
```

**`DETECT-OR`** is OR'd over any of three flavours:

1. **Basename + UUID tag:** `("rekoobe_host" OR "rekoobe_host___ebc6d5dd-2305-405a-b015-159a6d9dc05b")`
2. **Hash triple:** `("sha256-hex" OR "sha1-hex" OR "md5-hex")`
3. **Command-line fingerprint:** `("token1" AND "token2" AND "token3")` — AND-joined fragments of the command line that uniquely identify the attack

Concrete example (action 9 — pure command-token query):

```yaml
keyword_queries:
    - (( ("echo" AND "Successfully" AND "/tmp.txt") OR ("nc" AND "-lvnp" AND "16789") OR ("nc" AND "127.0.0.1" AND "16789") OR ("cat" AND "/s.txt") ) AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf")))
```

---

## Real worked example (action 1 — Melofee + implant + ping)

```yaml
- name: Test Initial Connection via Melofee Malware Implant
  title: Kubernetes Attack
  description: In this action, an attacker is trying to check Melofee Malware's initial connection via ICMP protocol.
  tactic: TA0011
  technique: T1095
  affected_os:
    - Linux
  affected_platforms:                          # 16-entry Linux distro block
    - {name: Red Hat Enterprise Linux 10, architecture: 64-bit}
    - {name: Rocky Linux 9, architecture: 64-bit}
    - {name: Ubuntu 22.04, architecture: 64-bit}
    - {name: CentOS 8, architecture: 64-bit}
    - {name: Red Hat Enterprise Linux 8, architecture: 64-bit}
    - {name: Alpine 3.22, architecture: 64-bit}
    - {name: SUSE 15.7, architecture: 64-bit}
    - {name: Alpine 3.21, architecture: 64-bit}
    - {name: SUSE 15.6, architecture: 64-bit}
    - {name: CentOS 9, architecture: 64-bit}
    - {name: Debian 12, architecture: 64-bit}
    - {name: Ubuntu 24.04, architecture: 64-bit}
    - {name: Red Hat Enterprise Linux 9, architecture: 64-bit}
    - {name: Debian 11, architecture: 64-bit}
    - {name: Debian 10, architecture: 64-bit}
    - {name: Ubuntu 20.04, architecture: 64-bit}
  is_atomic: true
  ukc_phase: Command & Control
  category: Attack Scenario
  result_condition:
    true: unblocked
    false: blocked
    condition:
        Terms:
            - {Right: {Value: unblocked}, Left: {Value: '%process-3%'}, Operator: eq}
        Operator: and
  play_processes:
    - arguments: '"$WORKDIR"/test_client_melofee'
      is_async: true
      remote_files:
        - file: files/dGVzdF9jbGllbnRfbWVsb2ZlZV9fXzkzODFlMWZhLTM1ODctNDU3Yy05Nzk1LWUwMzBiNmU2NWFmYg==
          path: test_client_melofee
          is_executable: true
          is_downloaded: true
    - arguments: '"$WORKDIR"/implant'
      is_async: true
      remote_files:
        - file: files/aW1wbGFudF9fXzZjNWRhMzIzLTkwYWUtNDgwMy04MGUyLTQ0NzE5M2VjN2Y0ZA==
          path: implant
          is_executable: true
          is_downloaded: true
    - arguments: '"$WORKDIR"/test_client_melofee ping'
      success_conditions:
        - output: pong
  rewind_processes:
    - arguments: kill -9 $(ss -tulnp | grep 4444 | grep -o 'pid=[0-9]*' | cut -d= -f2)
    - arguments: pkill -9 test_client_melofee
    - arguments: pkill -9 implant
    - arguments: rm -rf "$WORKDIR"/test_client* "$WORKDIR"/implant
    - arguments: rm -rf /tmp/implant_relay.sock
  keyword_queries:
    - (( ((("test_client_melofee" OR "test_client_melofee___9381e1fa-3587-457c-9795-e030b6e65afb")) OR ("0e03833076cf658b83f6d64129bcfe42e344c5e3d2fa2357619b95accb531117" OR "42c37b6d2d1dccae0c6c852ace9f2730900571d4" OR "03e19c6b083ab5157952843e64eb5ab9")) OR ((("implant" OR "implant___6c5da323-90ae-4803-80e2-447193ec7f4d")) OR ("725936f74554320a478d8a10cd6b2fd1c09190bc94a9a961cced4483292b9585" OR "78eb5e832f7e9e50bd8d5b16fbb72183195ec819" OR "bbfa606f6996a58aa99417510e776c25")) OR ("ping" AND "/test_client_melofee") ) AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf")))
```

---

## Difference vs. Linux Endpoint Scenario

| Aspect | Kubernetes Endpoint | Linux Endpoint |
|---|---|---|
| `module` value | `Kubernetes Endpoint Scenario` | `Linux Endpoint Scenario` |
| Campaign-level result-condition join | **`or`** | `and` |
| Objective `type` | umbrella (`Command and Control`, `Execution`) | raw MITRE tactic |
| Action `title` | always `Kubernetes Attack` | descriptive string per action |
| `is_privileged` field | never set | often `true` on credential-access actions |
| `play_processes` keys | same set | same set |
| `play_processes` shell pattern | `"$WORKDIR"/<binary>` direct invocation | `/bin/sh -c "<cmd>"` shell wrapper |
| Affected platforms block | 15–16 entry Linux distro list | 16-distro Linux list (same list, slightly different ordering) |

**Practical implication:** authoring a K8s threat is essentially "author a Linux Endpoint threat, then change five things":

1. Set `module: Kubernetes Endpoint Scenario`
2. Change campaign `result_condition.condition.Operator` from `and` to `or`
3. Set every action `title: Kubernetes Attack`
4. Set every objective `type: <umbrella category>` (e.g. `Command and Control`)
5. Drop any `is_privileged: true` lines

---

## Authoring checklist

- [ ] `module: Kubernetes Endpoint Scenario` at campaign level
- [ ] `affected_os: [- Linux]` and full 15-16 entry Linux distro block
- [ ] Campaign `result_condition` uses `Operator: or`
- [ ] Every action `title: Kubernetes Attack` (literal)
- [ ] Every objective `type` is umbrella (`Command and Control`, `Execution`, etc.) — NOT raw MITRE
- [ ] Action-level `result_condition` uses `%process-N%` with `Operator: and`
- [ ] No `is_privileged` anywhere
- [ ] `play_processes` step keys: `arguments` (required), optionally `path`/`is_async`/`timeout`/`delay`/`remote_files`/`success_conditions`
- [ ] `rewind_processes` cleans up `$WORKDIR/<binary>` and `/tmp/*` scratch
- [ ] `keyword_queries` is one expression: `(detect-OR) AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf"))`
- [ ] ZIP password: `picus` (AES-256 via `7z -mem=AES256 -tzip`)
</content>
</invoke>