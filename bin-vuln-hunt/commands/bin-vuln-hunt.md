---
name: bin-vuln-hunt
description: Hunt new CVEs and 0-days in Windows kernel drivers, PE binaries, and software bundles using REverie + IDA/WinDbg/x64dbg MCP — map attack surface, screen for vulnerable patterns, generate ranked hypotheses, confirm or kill with binary evidence, write vendor-ready advisories, and distill findings into the knowledge base.
argument-hint: "[.sys/.exe/.dll path | driver/product name | directory] [optional: specific subsystem or bug class to focus on]"
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, WebSearch, WebFetch, Agent, Skill, mcp__plugin_ida-pro-mcp_idalib__idb_open, mcp__plugin_ida-pro-mcp_idalib__survey_binary, mcp__plugin_ida-pro-mcp_idalib__imports, mcp__plugin_ida-pro-mcp_idalib__imports_query, mcp__plugin_ida-pro-mcp_idalib__decompile, mcp__plugin_ida-pro-mcp_idalib__xrefs_to, mcp__plugin_ida-pro-mcp_idalib__xref_query, mcp__plugin_ida-pro-mcp_idalib__trace_data_flow, mcp__plugin_ida-pro-mcp_idalib__find_regex, mcp__plugin_ida-pro-mcp_idalib__search_text, mcp__plugin_ida-pro-mcp_idalib__list_funcs, mcp__plugin_ida-pro-mcp_idalib__func_query, mcp__plugin_ida-pro-mcp_idalib__entity_query, mcp__plugin_ida-pro-mcp_idalib__disasm, mcp__plugin_ida-pro-mcp_idalib__get_string, mcp__plugin_ida-pro-mcp_idalib__callgraph, mcp__plugin_mcp-windbg_mcp-windbg__open_kd_session, mcp__plugin_mcp-windbg_mcp-windbg__run_kd_command, mcp__plugin_mcp-windbg_mcp-windbg__open_session, mcp__plugin_mcp-windbg_mcp-windbg__run_command
---

# /bin-vuln-hunt

Hunt new CVEs and 0-days in a Windows binary target using REverie + IDA/WinDbg/x64dbg.
Target from the user: `$ARGUMENTS`

Load and follow the **bin-vuln-hunt** skill now:

1. Call `Skill(bin-vuln-hunt)` and follow `SKILL.md`.
2. Phase 0: confirm authorization. Create a REverie `Package` (single binary or multi-
   component bundle). Run `reverie info` / `recon.pe_info` for triage. Query
   `knowledge.search` + `knowledge.suggest_leads_for` for prior findings in the same
   vendor/product. One line on authorization.
3. Phase 1: `idb_open` + `survey_binary` + `imports` — map every input boundary into a
   ranked attack-surface table (boundary → reach → trust → handler → priority). See
   `references/ATTACK_SURFACE.md`.
4. Phase 2: pattern screening — for each high-priority boundary, screen imports and shallow
   decompilation for known-vulnerable patterns (`references/BUG_CLASSES.md`). Generate
   hypotheses as REverie `Hypothesis` objects with `BugClass`, spawn
   `InvestigationThread`s. Seed from `KnowledgeLeadGenerator` for knowledge-based leads.
5. Phase 3: deep analysis — take each hypothesis top-down, `decompile` + `trace_data_flow`
   the handler chain from input to sink. Is the data attacker-controlled at the sink? Is
   the path reachable? What's the consequence? Mark CONFIRMED / KILLED / INFERRED.
   Promote confirmed hypotheses to `Finding`s.
6. Phase 4 (optional): dynamic validation on a VM — use `dynamic.run_poc` (lab harness) or
   WinDbg/x64dbg MCP to load the driver, craft malformed input, trigger the predicted
   path, observe the crash. Correlate kernel effects with `correlate_kernel_effect`.
7. Phase 5: severity assessment (CVSS via `Cvss::from_vector`, CWE) + write-up via
   `report.write_advisory` (vendor-ready) and `templates/VULN_REPORT.md` (internal record).
   VERIFIED vs INFERRED on every claim. The researcher decides disclosure.
8. Phase 6 (bonus): variant analysis — same bug in other IOCTLs? Other versions? Sibling
   binaries? Cross-component `Chain` if impact composes.
9. Phase 7: distill — `GrowingDistiller` folds findings into the knowledge base (mint
   `Technique` + `Skill`, reinforce leads, grow `PlatformModel`). Persist with
   `engine.persist()`.

Be ruthlessly honest: no finding is confirmed without binary evidence, severity must match
the actual impact (not the scariest possible interpretation), and dynamic testing happens
only in an isolated VM the user owns. No weaponization — hand off to `byovd-killer` or
`win-lpe-hunt` if the user wants to build on a finding.
