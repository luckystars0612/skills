---
name: win-lpe-hunt
description: Hunt Windows LPE in a target binary/product — generate multiple falsifiable hypotheses (privileged op × redirect × race-win × SYSTEM conversion), validate with idalib + Procmon.
argument-hint: "[binary path | product name | \"survey my box\"] [optional: subsystem/DLL]"
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, WebSearch, WebFetch, Agent, Skill, mcp__plugin_ida-pro-mcp_idalib__survey_binary, mcp__plugin_ida-pro-mcp_idalib__idb_open, mcp__plugin_ida-pro-mcp_idalib__decompile, mcp__plugin_ida-pro-mcp_idalib__imports_query, mcp__plugin_ida-pro-mcp_idalib__xrefs_to, mcp__plugin_ida-pro-mcp_idalib__xref_query, mcp__plugin_ida-pro-mcp_idalib__trace_data_flow, mcp__plugin_ida-pro-mcp_idalib__find_regex, mcp__plugin_ida-pro-mcp_idalib__search_text, mcp__plugin_ida-pro-mcp_idalib__list_globals, mcp__plugin_ida-pro-mcp_idalib__func_query, mcp__plugin_ida-pro-mcp_idalib__list_funcs, mcp__plugin_ida-pro-mcp_idalib__entity_query, mcp__plugin_ida-pro-mcp_idalib__disasm, mcp__plugin_ida-pro-mcp_idalib__callgraph
---

# /win-lpe-hunt

Hunt Windows local privilege escalation in a SYSTEM/admin binary by generating and killing
many hypotheses. Target from the user: `$ARGUMENTS`

Load and follow the **win-lpe-hunt** skill now:

1. Call `Skill(win-lpe-hunt)` and follow `SKILL.md`.
2. Phase 0: confirm authorization + the target's privilege level and low-priv entry points (one line).
3. Phase 1: open the binary with idalib, `survey_binary`, then map the surface — privileged file/registry
   ops, the **presence/absence of impersonation** around each (the fastest tell), attacker-input data-flow
   to path sinks, and weak-DACL named sections. Hand kernel drivers to the `driver-analysis` skill first.
4. Phase 2: emit **at least 5–8 falsifiable hypotheses** in the `references/HYPOTHESIS_TEMPLATE.md` format,
   each pairing privileged-op × redirect × race-win × SYSTEM-conversion, with an evidence line, a kill
   condition, the cheapest disproof, and a rank. Fan out subagents per subsystem to draft; you rank.
5. Phase 3: kill the cheap ones statically with one `decompile`/`trace_data_flow` each. Report the dead.
6. Phase 4: on the user's VM, confirm survivors with Procmon (PID filter; op/path/token). Prefer the
   **cfapi FETCH_DATA oracle** over oplocks. Prove the primitive (arbitrary write/delete/read as SYSTEM).
7. Phase 5–6: convert to SYSTEM, run `triage-validation` gates, then `report-writing`. Never auto-submit.

Be ruthlessly honest: reproduced-or-it-didn't-happen, VERIFIED vs INFERRED on every claim, cheapest
disproof first, and detonate weaponized artifacts only in an isolated VM the user owns.
