---
name: byovd-killer
description: Reverse a Windows driver into a BYOVD process/EDR killer — screen imports for all seven primitive classes, map the IOCTL dispatch chain, extract device path + IOCTL + PID buffer offset, beat the load/caller-validation gates, classify the class, and emit a byovd-lib DriverConfig (or a standalone memory / kernel-call / file-op / teardown PoC). With no driver given, recommends which driver type to hunt next. Validate on a VM.
argument-hint: "[.sys path | driver/product name | LOLDrivers entry | \"what next?\"] [optional: IOCTL/subsystem]"
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, WebSearch, WebFetch, Agent, Skill, mcp__plugin_ida-pro-mcp_idalib__idb_open, mcp__plugin_ida-pro-mcp_idalib__survey_binary, mcp__plugin_ida-pro-mcp_idalib__imports, mcp__plugin_ida-pro-mcp_idalib__imports_query, mcp__plugin_ida-pro-mcp_idalib__decompile, mcp__plugin_ida-pro-mcp_idalib__xrefs_to, mcp__plugin_ida-pro-mcp_idalib__xref_query, mcp__plugin_ida-pro-mcp_idalib__trace_data_flow, mcp__plugin_ida-pro-mcp_idalib__find_regex, mcp__plugin_ida-pro-mcp_idalib__search_text, mcp__plugin_ida-pro-mcp_idalib__list_funcs, mcp__plugin_ida-pro-mcp_idalib__func_query, mcp__plugin_ida-pro-mcp_idalib__entity_query, mcp__plugin_ida-pro-mcp_idalib__disasm, mcp__plugin_ida-pro-mcp_idalib__get_string, mcp__plugin_ida-pro-mcp_idalib__callgraph, mcp__plugin_mcp-windbg_mcp-windbg__open_kd_session, mcp__plugin_mcp-windbg_mcp-windbg__run_kd_command
---

# /byovd-killer

Reverse a vulnerable Windows kernel driver into a working BYOVD process/EDR killer. Target from
the user: `$ARGUMENTS`

Load and follow the **byovd-killer** skill now:

1. Call `Skill(byovd-killer)` and follow `SKILL.md`.
2. Phase 0: confirm authorization + the detonation VM, the OS build (HVCI/VBS matters), get the
   `.sys` on disk, record SHA256, check LOLDrivers / MS block list. One line.
2b. No specific driver given (the ask is "which driver next?" / "find a target"): work
   `references/TARGET_SELECTION.md` instead — saturation check, freshness gate, and recommend a
   missing primitive class plus concrete hunting grounds. Don't open IDA for this.
3. Phase 1: `idb_open` + `imports` — screen for **all seven** classes: terminate pair, handle-stomp,
   physical-memory map, kernel-VA R/W, buffer-controlled call target, kernel file ops, kernel
   registry write, callback teardown (score against `references/KILL_PRIMITIVES.md`; the grep table
   in `references/TARGET_SELECTION.md` does it in one command). Record every class found, not just
   the first. No hit ⇒ say "not a killer" and stop.
4. Phase 2: reverse the dispatch chain (`references/DRIVER_ANATOMY.md`) and extract the three
   facts VERIFIED — **device path `\\.\X`**, **IOCTL/command code**, **input-buffer PID
   offset/width/encoding** — plus the auth gap. Record in `templates/DRIVER_PROFILE.md`.
5. Phase 3: classify — Tier 1 direct kill IOCTL / Tier 2 handle-stomp / Tier 3 memory R/W
   (physical, kernel-VA 3l, or PCI→DMA 3m; data-only SSDT vs shellcode) / Tier 4 controlled kernel
   call / Tier 5 kernel file delete-rename / Tier 6 kernel registry write / Tier 7 callback
   teardown. The class decides the PoC shape — and Tiers 4–7 are usually *cheaper* than Tier 3.
   Work the five load/auth gates in `references/LOAD_AND_AUTH_BYPASS.md` before calling a driver
   unusable (caller image-hash checks fall to handle theft; address blocklists to map-from-zero).
6. Phase 4: build it — Tier 1 = thin `byovd-lib` `DriverConfig` from `templates/killer_main.rs`
   (wire the workspace member); Tier 2/3 = standalone crate with the primitive + kill layer from
   `references/KILL_PRIMITIVES.md`.
7. Phase 5: validate on the VM — `sc create`/`sc start`, kill `notepad.exe` first, then the
   EDR/Defender target; confirm with WinDbg if available. Report PPL/HVCI behavior honestly.
8. Phase 6: per-killer README + top-level POC-list entry. VERIFIED vs INFERRED on every claim.

Be ruthlessly honest: reproduced-or-it-didn't-happen, the PID offset must be exact or there's no
kill, and detonate the driver + killer only in an isolated VM the user owns — this tool disables
security software.
