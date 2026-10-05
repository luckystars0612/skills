# Platforms — exact list

> Pulled from `GET /v1/threat-library/action-parameters` on the live platform, 2026-10-05.
> Picus **validates these on import** — a value outside the list is rejected. The endpoint
> accepts a `module_name` query parameter but ignores it: the response is byte-identical for
> all 12 modules, so one list serves every module.

Used in the action-level `affected_platforms` field.

**92 platform entries.** In `threat.yaml` these are split into `name` + `architecture`:

```yaml
affected_platforms:
  - name: "Windows 10"
    architecture: "64-bit"
```

The API returns them as one combined string (`Windows 10 64-bit`); the YAML form splits it.
Real Picus actions also carry an `os` sub-field, which uses `MacOS` (capital O) while the
action's own `affected_os` uses `macOS` — Picus is internally inconsistent here.


## Windows (18 entries, 13 names)

| `name` | `architecture` |
|---|---|
| `Windows 10` | `32-bit`, `64-bit` |
| `Windows 11` | `64-bit` |
| `Windows 7` | `32-bit`, `64-bit` |
| `Windows 8.1` | `32-bit`, `64-bit` |
| `Windows Server` | `64-bit` |
| `Windows Server 2008` | `32-bit`, `64-bit` |
| `Windows Server 2008 R2` | `32-bit`, `64-bit` |
| `Windows Server 2012` | `64-bit` |
| `Windows Server 2012 R2` | `64-bit` |
| `Windows Server 2016` | `64-bit` |
| `Windows Server 2019` | `64-bit` |
| `Windows Server 2022` | `64-bit` |
| `Windows Server 2025` | `64-bit` |

## macOS (6 entries, 6 names)

| `name` | `architecture` |
|---|---|
| `MacOS 11 Big Sur` | `64-bit` |
| `MacOS 12 Monterey` | `64-bit` |
| `MacOS 13 Ventura` | `64-bit` |
| `MacOS 14 Sonoma` | `64-bit` |
| `MacOS 15 Sequoia` | `64-bit` |
| `MacOS 26 Tahoe` | `64-bit` |

## Ubuntu (26 entries, 13 names)

| `name` | `architecture` |
|---|---|
| `Ubuntu 18.04` | `32-bit`, `64-bit` |
| `Ubuntu 18.10` | `32-bit`, `64-bit` |
| `Ubuntu 19.04` | `32-bit`, `64-bit` |
| `Ubuntu 19.10` | `32-bit`, `64-bit` |
| `Ubuntu 20.04` | `32-bit`, `64-bit` |
| `Ubuntu 20.10` | `32-bit`, `64-bit` |
| `Ubuntu 21.04` | `32-bit`, `64-bit` |
| `Ubuntu 21.10` | `32-bit`, `64-bit` |
| `Ubuntu 22.04` | `32-bit`, `64-bit` |
| `Ubuntu 22.10` | `32-bit`, `64-bit` |
| `Ubuntu 23.04` | `32-bit`, `64-bit` |
| `Ubuntu 23.10` | `32-bit`, `64-bit` |
| `Ubuntu 24.04` | `32-bit`, `64-bit` |

## Debian (8 entries, 4 names)

| `name` | `architecture` |
|---|---|
| `Debian 10` | `32-bit`, `64-bit` |
| `Debian 11` | `32-bit`, `64-bit` |
| `Debian 12` | `32-bit`, `64-bit` |
| `Debian 9` | `32-bit`, `64-bit` |

## CentOS (6 entries, 3 names)

| `name` | `architecture` |
|---|---|
| `CentOS 7` | `32-bit`, `64-bit` |
| `CentOS 8` | `32-bit`, `64-bit` |
| `CentOS 9` | `32-bit`, `64-bit` |

## Red Hat Enterprise Linux (8 entries, 4 names)

| `name` | `architecture` |
|---|---|
| `Red Hat Enterprise Linux 10` | `32-bit`, `64-bit` |
| `Red Hat Enterprise Linux 7` | `32-bit`, `64-bit` |
| `Red Hat Enterprise Linux 8` | `32-bit`, `64-bit` |
| `Red Hat Enterprise Linux 9` | `32-bit`, `64-bit` |

## Rocky Linux (4 entries, 2 names)

| `name` | `architecture` |
|---|---|
| `Rocky Linux 8` | `32-bit`, `64-bit` |
| `Rocky Linux 9` | `32-bit`, `64-bit` |

## SUSE (9 entries, 8 names)

| `name` | `architecture` |
|---|---|
| `SUSE 15` | `64-bit` |
| `SUSE 15.1` | `64-bit` |
| `SUSE 15.2` | `64-bit` |
| `SUSE 15.3` | `64-bit` |
| `SUSE 15.4` | `64-bit` |
| `SUSE 15.5` | `64-bit` |
| `SUSE 15.6` | `64-bit` |
| `SUSE 15.7` | `64-bit` |

## Alpine (8 entries, 8 names)

| `name` | `architecture` |
|---|---|
| `Alpine 3.15` | `64-bit` |
| `Alpine 3.16` | `64-bit` |
| `Alpine 3.17` | `64-bit` |
| `Alpine 3.18` | `64-bit` |
| `Alpine 3.19` | `64-bit` |
| `Alpine 3.20` | `64-bit` |
| `Alpine 3.21` | `64-bit` |
| `Alpine 3.22` | `64-bit` |
