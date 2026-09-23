---
name: vm-escape-hunt
description: Hunt a hypervisor guest-to-host escape in a VMM's device emulation — generate multiple falsifiable hypotheses (device × bug primitive × info-leak × control-flow hijack), validate with idalib + WinDbg, chain leak+corruption to host RCE.
argument-hint: "[vmware-vmx / device module / product+version | device name (PVSCSI, vmxnet3, UHCI...) | VMSA/CVE to diff | \"survey vmware-vmx\"] [optional: device backend]"
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, WebSearch, WebFetch, Agent, Skill, mcp__plugin_ida-pro-mcp_idalib__survey_binary, mcp__plugin_ida-pro-mcp_idalib__idb_open, mcp__plugin_ida-pro-mcp_idalib__decompile, mcp__plugin_ida-pro-mcp_idalib__imports_query, mcp__plugin_ida-pro-mcp_idalib__xrefs_to, mcp__plugin_ida-pro-mcp_idalib__xref_query, mcp__plugin_ida-pro-mcp_idalib__trace_data_flow, mcp__plugin_ida-pro-mcp_idalib__find_regex, mcp__plugin_ida-pro-mcp_idalib__search_text, mcp__plugin_ida-pro-mcp_idalib__list_globals, mcp__plugin_ida-pro-mcp_idalib__func_query, mcp__plugin_ida-pro-mcp_idalib__list_funcs, mcp__plugin_ida-pro-mcp_idalib__entity_query, mcp__plugin_ida-pro-mcp_idalib__disasm, mcp__plugin_ida-pro-mcp_idalib__callgraph, mcp__plugin_ida-pro-mcp_idalib__search_structs, mcp__plugin_ida-pro-mcp_idalib__read_struct, mcp__plugin_mcp-windbg_mcp-windbg__open_cdb_remote, mcp__plugin_mcp-windbg_mcp-windbg__open_cdb_dump, mcp__plugin_mcp-windbg_mcp-windbg__run_cdb_command
---

# /vm-escape-hunt

Hunt a hypervisor guest-to-host escape in a VMM's virtual-device emulation by generating
and killing many hypotheses. Target from the user: `$ARGUMENTS`

Load and follow the **vm-escape-hunt** skill now:

1. Call `Skill(vm-escape-hunt)` and follow `SKILL.md`.
2. Phase 0: confirm authorization + the hypervisor build, and pick mode — device-audit or
   patch-diff (VMSA/CVE). All guest detonation runs in an isolated guest on a research host
   the user owns; a working escape executes on the *host*. One line.
3. Phase 1: open the VMM binary with idalib, `survey_binary`, scope to one device backend,
   and map the four ingredients — guest→host entry point (PIO/MMIO/DMA/backchannel), the
   sized/indexed memory op, the missing/incorrect bound, and any leak/lifetime bug.
   Use `references/ATTACK_SURFACE.md` for the device taxonomy and exact idalib queries.
4. Phase 2: emit **at least 5–8 falsifiable hypotheses** in the
   `references/HYPOTHESIS_TEMPLATE.md` format, each pairing device × bug-primitive ×
   info-leak × control-flow-hijack, with an evidence line, a kill condition, the cheapest
   disproof, and a rank. Fan out subagents per device backend to draft; you rank.
5. Phase 3: kill the cheap ones statically — one `decompile`/`trace_data_flow` on the size
   check per hypothesis. A *weak* primitive isn't dead (device algorithms launder it);
   only a fired kill-condition is. Report the dead.
6. Phase 4: on the user's research host, confirm survivors — drive the device from a guest
   driver and break in WinDbg on the handler; prove the primitive and identify the heap/LFH
   bucket of the corrupted chunk.
7. Phase 5: build the chain with `references/EXPLOIT_PRIMITIVES.md` — leak (defeat ASLR) →
   LFH grooming (shaders/URBs, ping-pong, backdoor timing oracle) → callback-pointer hijack
   → CFG-whitelisted-gadget → WinExec. Prove a popped host process, first-try from clean state.
8. Phase 6: report impact-first with decompiled evidence and the guest→host path; diff
   against the nearest VMSA/CVE (shipped / incomplete-fix / adjacent / new — borrow
   `cve-hunt` for patch-bypass framing). The host RCE lands as the VMX process — chain
   `win-lpe-hunt` for SYSTEM. Never auto-submit; the researcher decides disclosure.

Be ruthlessly honest: reproduced-or-it-didn't-happen, VERIFIED vs INFERRED on every claim,
two-bugs-not-one (leak + corruption), cheapest disproof first, and detonate escapes only on
an isolated research host the user owns.
