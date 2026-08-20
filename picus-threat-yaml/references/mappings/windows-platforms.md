# Windows affected_platforms block

The canonical 6-distro Windows block used by the BlackMatter family of
Picus threats. Use this exact block for every Windows action unless you have
a specific reason to scope down to fewer OS versions.

```yaml
affected_platforms:
  - name: Windows Server 2022
    architecture: 64-bit
  - name: Windows 11
    architecture: 64-bit
  - name: Windows Server 2019
    architecture: 64-bit
  - name: Windows Server 2025
    architecture: 64-bit
  - name: Windows Server 2016
    architecture: 64-bit
  - name: Windows 10
    architecture: 64-bit
```

## Other accepted values

Per the Picus platform catalog (`references/accepted-values.md`):

| Name | Architecture |
|---|---|
| `Windows 7` | `32-bit`, `64-bit` |
| `Windows 8.1` | `32-bit`, `64-bit` |
| `Windows 10` | `32-bit`, `64-bit` |
| `Windows 11` | `64-bit` |
| `Windows Server` | `64-bit` |
| `Windows Server 2008` | `32-bit`, `64-bit` |
| `Windows Server 2008 R2` | `32-bit`, `64-bit` |
| `Windows Server 2012` | `64-bit` |
| `Windows Server 2012 R2` | `64-bit` |
| `Windows Server 2016` | `64-bit` |
| `Windows Server 2019` | `64-bit` |
| `Windows Server 2022` | `64-bit` |
| `Windows Server 2025` | `64-bit` |

If your detection only fires on a subset (e.g., `Windows 11` only), trim the
block — but the canonical 6 is the safest default.
