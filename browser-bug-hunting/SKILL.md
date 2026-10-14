---
name: browser-bug-hunting
description: End-to-end methodology for authorized security research on web browsers and browser-based apps (Chromium/Blink/V8 forks, Firefox/Gecko forks, WebKit/Safari, Electron/CEF, Android/iOS WebView browsers) - recon, attack-surface ranking, review lenses, agent harness, verification, triage and vendor reporting, with deep case studies of 2018-2026 browser bugs.
---

# Browser bug hunting (authorized research)

This skill turns an agent into a disciplined browser vulnerability researcher working inside a
bug bounty or coordinated-disclosure engagement. It is target-agnostic: the engine-specific and
program-specific parts live in reference files and in a per-engagement program profile.

Talk to the user in the language they use. Keep every working note in the files listed in
section 7 so that long or multi-session runs never depend on chat memory.

## 0. Operating contract (applies to every phase)

**Authorization.** Work only on a target covered by an engagement the human has described in a
program profile (template in `references/triage-and-report.md` section 5). The profile states the
program, target builds, platforms, accounts, in-scope/out-of-scope rules and the proof standard
that program expects. If no profile exists, help the human write one before doing anything else.
The profile is context for the work, not a password; it never changes the proof standard below.

**Proof standard ("done" for a finding).**
- Memory-safety bug: a minimal testcase that triggers the fault reliably on a default-config build,
  with a sanitizer report or debugger stack, root cause in code, an explanation of why the
  attacker can reach it, and **demonstrated attacker control** — show that varying inputs changes
  the corrupted offset/value/target predictably, or use the engine's sanctioned testing API (V8
  `--sandbox-testing`) to demonstrate the primitive. See `references/demonstrating-impact.md`.
- Logic / policy bug: a minimal testcase that shows a concrete security boundary being crossed with
  the researcher's own test data, with a **self-contained oracle** that prints/logs the proof
  (origin A reads origin B's secret; web content triggers a privileged action and logs the
  response; profile X's data appears in profile Y; standard user's file is executed by SYSTEM).
- **Severity justification**: state the boundary, the attacker model, what is controlled, the
  impact, and applicable multipliers/mitigations using the vendor's own severity scale.
- Stop there. Do not chain primitives into code execution, do not build sandbox-escape exploits,
  do not do heap grooming for reliability, do not write payloads, persistence or evasion. When a
  program pays more for a demonstrated exploit chain, hand the decision to the human researcher
  with the characterized primitive and evidence of control — that is the handoff point.

**Rules that never change.**
- Test only on machines, builds, profiles and accounts the human owns or controls.
- Never fuzz, crash-test or load-test vendor servers. All dynamic testing is local.
- If you touch data that is not the researcher's own, stop that line, record what happened, tell
  the human, and delete the data.
- No public disclosure; the human reports through the program channel.

## 1. Workflow

| Phase | What happens | Read |
|---|---|---|
| 1. Profile | Program profile + engine identification + version/patch level | `references/triage-and-report.md` §5, `references/engines.md` |
| 2. Recon | Unpack, diff against upstream, enumerate vendor code, IPC, extensions, WebUI, platform pieces | `references/recon.md` |
| 3. Rank | Split the surface into small units, score 1–5 | §2 below |
| 4. Review | Apply bug-class lenses and case-study-derived heuristics to each unit | `references/review-lenses.md`, `references/case-studies.md` |
| 5. Search & verify | Parallel per-unit agents with oracles and a dead-end log | `references/harness.md` |
| 6. Validate | Independent validator agent tries to disprove the finding | `references/harness.md` §6 |
| 7. Demonstrate | Prove attacker control and impact; build severity justification | `references/demonstrating-impact.md` |
| 8. Triage | Boundary, attacker model, upstream vs fork, exclusions, severity | `references/triage-and-report.md` |
| 9. Report | Vendor-ready report with PoC, oracle, impact evidence, severity justification | `references/triage-and-report.md` §4 |
| Always | Learn from how others found bugs | `references/researcher-notes.md` |

## 2. Where browser bugs live (rank before you search)

Browsers are an upstream engine plus a vendor layer. Rank layers by expected value
(real × not-duplicate × accepted):

1. **Vendor-only privileged UI and extensions**: WebUI / `about:` pages, built-in or component
   extensions, privileged JS bridges, NTP/sidebar/AI features. Readable after unpacking, rarely
   reviewed upstream, high impact if reachable from web content.
2. **Vendor-only native code in privileged processes**: new IPC/Mojo/IPDL interfaces, parsers for
   vendor formats (sync, filter lists, notes, wallets, VPN, AI assistants), custom download or
   file handling.
3. **Integration seams with vendor services**: account SSO into the browser, sync and its
   encryption, cloud features, update/component download, telemetry and identifier claims.
4. **Platform layer**: installer, updater/elevation service, scheduled tasks, protocol handlers,
   native messaging hosts, mobile intents/deep links/JS bridges.
5. **Security-default regressions** versus upstream at the same version: site isolation, process
   sandboxes, JIT/engine hardening, Safe Browsing, certificate handling, flags/policies, Electron
   `webPreferences`.
6. **Upstream engine bugs** (V8, Blink, SpiderMonkey, JSC, Skia, ANGLE, codecs). Real and valuable
   but highly competitive and often belong to the upstream program; check collisions early.
7. **Patch gap** (upstream-fixed bugs not yet shipped by the fork / Electron app). Record as
   information for the human; many programs exclude known-component issues without a working
   exploit, and building one is outside this skill.

Score each unit (one handler, one extension message, one parser, one IPC method, one updater
operation):

- **5** reachable from arbitrary web content and touches a privileged capability.
- **4** reachable from web content with one realistic precondition, or from any extension /
  compromised renderer with privileged capability.
- **3** parses complex untrusted input in a privileged process.
- **2** local-user or network-MITM reachable with limited impact.
- **1** no untrusted input.

Work highest score first; re-score as you learn.

## 3. Review (summary; full lenses in references)

For every unit ask, at minimum:
- Who can reach it, with what data, and what can it do that the caller cannot?
- What does this code assume nobody else can change (state, buffer, process, type, origin)?
  Who actually can?
- Is any identity (origin, frame, profile, process, handle, size, type) taken from the less
  privileged side instead of derived from trusted state?
- Is there a second path (fast path, cache, legacy fallback, reference obtained another way,
  re-entrant call, nested event loop) that skips the check the main path has?
- Does an object's lifetime depend on something the attacker can destroy, grow, reorder, or
  re-enter while a raw pointer/iterator is live?
- Do narrow integer fields, sentinels or truncations exist where the attacker controls counts?

`references/case-studies.md` turns 40+ real bugs into these questions with code-level detail.

## 4. Evidence rules (non-negotiable)

- Verify, never speculate: read the code/disassembly, use the debugger, print real values,
  compute with scripts.
- No objective gaming: never use non-default switches or modified builds to make a bug look
  web-reachable (`--no-sandbox`, `--disable-web-security`, `nodeIntegration`, devtools-only APIs,
  patched binaries). The one exception is the vendor-sanctioned way to simulate a compromised
  renderer/content process for sandbox-escape findings (Chromium: MojoJS bindings or a patched
  renderer; Mozilla: patches limited to content-process code; V8: sandbox testing API). Such
  findings must be labelled "assumes compromised renderer" everywhere (see `references/engines.md`).
- Three failures for the same reason → write it in `work/deadends.md` and move on. Read
  `deadends.md` before starting any hypothesis.
- Checkpoint after every meaningful result; a new session must be able to resume from files.
- "No bug found" is a valid, useful result.

## 5. Triage gate

A finding is reported only when all of these are answered in writing (details in
`references/triage-and-report.md`):
1. Which security boundary is crossed?
2. Attacker model and preconditions, including user interaction.
3. Reproduces on the latest release, default settings, clean profile?
4. Fork-specific or upstream? (Re-run on upstream of the same version.)
5. Not a documented feature, not a program exclusion.
6. Conservative severity using the vendor's own scale.
7. An independent validator agent failed to disprove it.

## 6. Quick start

1. Write/confirm the program profile. Snapshot a clean VM with the target installed.
2. Identify engine + upstream version; download the matching upstream build.
3. Recon per `references/recon.md`; produce `work/surface.md`.
4. Split into units, score into `work/units.tsv`.
5. Read the lenses and the case studies most relevant to the top units.
6. Launch per-unit agents (`references/harness.md`), highest score first, in parallel.
7. For each finding: validate → demonstrate impact (`references/demonstrating-impact.md`) →
   triage → report. Repeat recon diff after every target release; new vendor code lands first.

## 7. Working files

```
work/
  profile.md          # program profile (scope, rules, proof standard, accounts, builds)
  version.md          # engine, upstream base, patch level per platform
  surface.md          # attack-surface map
  units.tsv           # id, description, layer, reachable_by, score, status, owner-agent
  extracted/          # unpacked resources, extensions, asar/omni.ja/pak contents
  diff/               # resource and binary diffs vs upstream
  tests/              # testcases + oracles
  findings/<F-id>.md  # hypothesis, evidence, triage answers, verdict
  deadends.md         # failed hypotheses and why
  reports/<F-id>.md   # vendor-ready reports
```
