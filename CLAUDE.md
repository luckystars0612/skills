# Security Research Toolkit

## Purpose and Authorization

This repository is a collection of Claude Code skills and automation for **authorized security research** exclusively within:

- **Public bug bounty programs** (Bugcrowd, HackerOne, Intigriti, vendor-run programs)
- **Coordinated vulnerability disclosure** (CVE assignment, vendor notification, responsible timelines)
- **Capture-the-flag competitions** (CTF events, wargames, training platforms)
- **Academic security research** (published at BlackHat, DEF CON, HITB, OffensiveCon, IEEE S&P, USENIX Security, CCS, NDSS)
- **Authorized penetration testing** (with written scope and rules of engagement)

All testing is performed in **isolated virtual machines** owned by the researcher, with snapshot rollback. No techniques in this repository target production systems, third-party infrastructure, or real users without explicit authorization.

## Rules

1. **VM-only execution** — all exploit testing occurs in isolated VMs the researcher owns
2. **No real malware** — use EICAR test strings or benign simulators only for EDR/AV trigger testing
3. **Reproduced or it didn't happen** — every finding must be demonstrated with a working PoC, not assumed
4. **VERIFIED vs INFERRED** — mark every claim with its evidence level
5. **Responsible disclosure** — the researcher decides when and how to disclose; never auto-submit to any platform
6. **Prefer Rust** for new tooling unless the user specifies otherwise
7. **Use available MCP tools** — IDA Pro (`ida-pro-mcp`), WinDbg (`mcp-windbg`), x64dbg, REverie when connected
8. **Persist findings immediately** — after discovering any offset, protocol detail, or dead end, write it to a memory file. Context compaction will lose it otherwise.
9. **Update `RESEARCH_STATE.md` before ending any session** — this file is auto-injected on session start and after compaction by the hook system. Keep it concise: current status, dead ends, viable approaches, key technical facts.

## Skills

### Vulnerability Research
| Skill | Purpose |
|---|---|
| `win-lpe-hunt` | Hunt Windows LPE in SYSTEM services, AV/EDR agents, updaters, drivers |
| `bin-vuln-hunt` | Hunt new CVEs in Windows drivers, PE files, software bundles |
| `cve-hunt` | Variant analysis, incomplete-fix bypass, patch diffing; reproduced in Docker |
| `vm-escape-hunt` | Guest-to-host escapes in VMware, VirtualBox, QEMU, Hyper-V |
| `fw-iot-hunt` | IoT/OT firmware bugs: routers, NAS, cameras, gateways, PLCs |
| `analyze-firmware` | Robot firmware: ROS/ROS2, RTOS, motor controllers, DDS/MQTT/CAN/Modbus |
| `vuln-audit` | Binary audit: buffer overflows, format strings, integer issues, memory safety |
| `byovd-killer` | Reverse a vulnerable signed driver for BYOVD-based EDR/AV termination |
| `browser-bug-hunting` | Browser engine vulnerability research |

### Reverse Engineering
| Skill | Purpose |
|---|---|
| `generic-re` | General-purpose binary analysis: architecture, behavior, data structures |
| `driver-analysis` | Windows kernel driver: DriverEntry, dispatch table, IOCTL handlers |
| `deobfuscation` | String decryption, CFF, opaque predicates, MBA simplification |
| `ctf` | Capture-the-flag reverse engineering challenges |

### Malware Analysis
| Skill | Purpose |
|---|---|
| `malware-analysis` | Windows PE malware: kill chain, IOCs, MITRE ATT&CK mapping |
| `linux-malware` | ELF malware: packing, persistence, C2, rootkits, Go/Rust/Mirai |

### Tooling and Automation
| Skill | Purpose |
|---|---|
| `ida-scripting` | Write and execute IDAPython scripts (full API reference included) |
| `binja-scripting` | Write and execute Binary Ninja Python scripts (full API reference included) |
| `smart-patch-ida` | Patch binary code in IDA Pro from natural language |
| `smart-patch-binja` | Patch binary code in Binary Ninja from natural language |
| `modify` | Modify binary behavior from natural-language description |

### Detection Engineering
| Skill | Purpose |
|---|---|
| `picus-threat-yaml` | Author custom threat YAML for Picus SCV, SPL/Sigma conversion |

## Context Persistence (Hooks)

This repo includes a hook system that automatically restores research state across Claude Code sessions and after context compaction. This prevents loss of reverse engineering findings, dead-end records, and protocol details.

### How it works
1. Each project has a `RESEARCH_STATE.md` in its root (written by Claude before session end, per rule 9)
2. On **session start** and **after compaction**, the hook reads `RESEARCH_STATE.md` + all memory files and injects them into Claude's context
3. Projects without `RESEARCH_STATE.md` are silently skipped

### Files
- `hooks/inject_state.py` — the injection script (generic, works on any project)
- `install-hooks.ps1` — Windows installer (`-DryRun`, `-Uninstall`)
- `install-hooks.sh` — Linux/Mac installer (`--dry-run`, `--uninstall`)

### Setup on a new host
```
# Windows
.\install-hooks.ps1

# Linux/Mac
./install-hooks.sh
```

Then add rule 9 to each project's CLAUDE.md and restart Claude Code.

## Installers

| Script | Purpose |
|---|---|
| `install.ps1` / `install.sh` | Install all skills into Claude Code |
| `install-hooks.ps1` / `install-hooks.sh` | Install context persistence hooks |
| `install-mcode.ps1` / `install-mcode.sh` | Install mcode tooling |
