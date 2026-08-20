# Linux Affected Platforms — Canonical Block

The exact YAML block the skill must emit on every Linux action in `affected_platforms`.
Extracted empirically from the working samples (`PUMAKIT Malware Campaign`,
`Command and Control Kubernetes Micro Emulation Plan`, `Realst Infostealer Campaign`
macOS substitution).

This is the **16-distro block** that exercises the maximum coverage on Linux
agent hosts. Do not modify the order — it is the order that the import validator
expects.

```yaml
affected_platforms:
  - {name: "Red Hat Enterprise Linux 10", architecture: "64-bit"}
  - {name: "Rocky Linux 9",                architecture: "64-bit"}
  - {name: "Ubuntu 22.04",                 architecture: "64-bit"}
  - {name: "CentOS 8",                     architecture: "64-bit"}
  - {name: "Red Hat Enterprise Linux 8",   architecture: "64-bit"}
  - {name: "Alpine 3.22",                  architecture: "64-bit"}
  - {name: "SUSE 15.7",                    architecture: "64-bit"}
  - {name: "Alpine 3.21",                  architecture: "64-bit"}
  - {name: "SUSE 15.6",                    architecture: "64-bit"}
  - {name: "CentOS 9",                     architecture: "64-bit"}
  - {name: "Debian 12",                    architecture: "64-bit"}
  - {name: "Ubuntu 24.04",                 architecture: "64-bit"}
  - {name: "Red Hat Enterprise Linux 9",   architecture: "64-bit"}
  - {name: "Debian 11",                    architecture: "64-bit"}
  - {name: "Debian 10",                    architecture: "64-bit"}
  - {name: "Ubuntu 20.04",                 architecture: "64-bit"}
```

## When to use a narrower list

For actions that explicitly target a single distribution (e.g. "SHELL=" checks on
crontab may behave differently on BusyBox `/bin/sh` vs. `bash`), the user may
truncate the list — but **the default for the skill is the full 16-entry block**.

## macOS substitution

For `macOS Endpoint Scenario` threats, the macOS list in the working Realst sample is:

```yaml
affected_platforms:
  - {name: "MacOS 26 Tahoe",   architecture: "64-bit"}
  - {name: "MacOS 15 Sequoia",  architecture: "64-bit"}
  - {name: "MacOS 14 Sonoma",   architecture: "64-bit"}
  - {name: "MacOS 13 Ventura",  architecture: "64-bit"}
  - {name: "MacOS 12 Monterey", architecture: "64-bit"}
```

## Windows substitution

For `Endpoint Scenario` (Windows) threats, the list mirrors BlackMatter:

```yaml
affected_platforms:
  - {name: "Windows Server 2022", architecture: "64-bit"}
  - {name: "Windows 11",          architecture: "64-bit"}
  - {name: "Windows Server 2019", architecture: "64-bit"}
  - {name: "Windows Server 2025", architecture: "64-bit"}
  - {name: "Windows Server 2016", architecture: "64-bit"}
  - {name: "Windows 10",          architecture: "64-bit"}
```

Alternatively, if the action is OS-agnostic, omit `affected_platforms` and set
`is_applicable_to_all_platforms: true` on the action — the validator accepts either.
