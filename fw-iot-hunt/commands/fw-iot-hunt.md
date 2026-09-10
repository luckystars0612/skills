---
name: fw-iot-hunt
description: Hunt high/critical bugs in IoT/OT firmware — extract the rootfs, map the privileged network daemons and input→sink taint with idalib, generate falsifiable hypotheses, disclosure-check, then confirm on an emulated device (FirmAE / qemu-user+chroot).
argument-hint: "[firmware file/URL | vendor+model | rootfs path | \"find a firmware to audit\"] [optional: daemon/component]"
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, WebSearch, WebFetch, Agent, Skill, mcp__plugin_ida-pro-mcp_idalib__survey_binary, mcp__plugin_ida-pro-mcp_idalib__idb_open, mcp__plugin_ida-pro-mcp_idalib__decompile, mcp__plugin_ida-pro-mcp_idalib__imports_query, mcp__plugin_ida-pro-mcp_idalib__xrefs_to, mcp__plugin_ida-pro-mcp_idalib__xref_query, mcp__plugin_ida-pro-mcp_idalib__trace_data_flow, mcp__plugin_ida-pro-mcp_idalib__find_regex, mcp__plugin_ida-pro-mcp_idalib__search_text, mcp__plugin_ida-pro-mcp_idalib__list_funcs, mcp__plugin_ida-pro-mcp_idalib__func_query, mcp__plugin_ida-pro-mcp_idalib__list_globals, mcp__plugin_ida-pro-mcp_idalib__disasm, mcp__plugin_ida-pro-mcp_idalib__callgraph
---

# /fw-iot-hunt

Hunt high/critical vulnerabilities in IoT/OT firmware. Target from the user: `$ARGUMENTS`

Load and follow the **fw-iot-hunt** skill now:

1. Call `Skill(fw-iot-hunt)` and follow `SKILL.md`.
2. Phase 0: confirm authorization + pick/confirm a **LATEST or LTS** target (never EOL);
   prefer less-fuzzed / newer surface over saturated flagship web stacks. Note arch + OS model.
3. Phase 1: extract the rootfs per `references/EXTRACTION.md` (SquashFS/UBI/JFFS2, vendor
   obfuscation, obfuscated Lua, RTOS monolith, update-vs-factory). Confirm the version.
4. Phase 2: with idalib, map the root network daemons — input sources, privileged sinks
   (cmd-exec / overflow / format-string / file-write / SSRF), input→sink taint, and
   **auth reachability** (missing-return, per-controller gap, trust-on-first-use). Fan out
   subagents per daemon; you rank.
5. Phase 3: emit **5–8+ falsifiable hypotheses** (`references/HYPOTHESIS_TEMPLATE.md`) —
   claim, evidence (VERIFIED/INFERRED), kill condition, cheapest test, rank.
6. Phase 4 (MANDATORY): **disclosure-check before claiming novelty** — borrow the `cve-hunt`
   skill's reality-check gate. Novel vs known-unpatched-in-latest vs duplicate. Per-primitive.
7. Phase 5: kill cheap hypotheses statically; confirm survivors on a running device
   (`references/EMULATION.md` + `templates/stack_emulate.sh`) — prove the primitive (root
   marker / controlled crash / on-disk artifact). Distinguish harness artifact from a real guard.
8. Phase 6: write the advisory (`templates/ADVISORY.md` + `report-writing`), a REPRODUCE.md,
   and a PoC/re-test script. Compute CVSS honestly. **Never auto-submit** — the human files it.

Be ruthlessly honest: latest/LTS only, disclosure-check before reproducing,
reproduced-or-it-didn't-happen, VERIFIED vs INFERRED on every claim, cheapest disproof first.
Emulation is local/safe; only touch a physical/networked device the user owns or is authorized to test.
