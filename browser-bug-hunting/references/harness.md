# Agent harness: running the search and verifying findings

This file is how to drive one or many agents through the units in `work/units.tsv` so they find
real, verified issues instead of re-finding shallow ones or hallucinating. It reflects what worked
for the public 2026 browser-research efforts (Mozilla's pipeline, Anthropic's zero-day scaffold,
Hacktron's hands-on run): a narrow per-unit task, a runnable oracle, strict evidence rules, a
dead-end log, and a separate validator.

The proof standard in SKILL.md §0 applies to everything here: stop at a reliable trigger + root
cause (memory bugs) or a demonstrated boundary crossing with your own test data (logic bugs). Do
not weaponize.

---

## 1. One agent, one unit

Give each agent a single unit and a tight brief. Broad prompts ("find bugs in this browser") burn
budget re-finding the same shallow issues; narrow prompts on ranked units find distinct ones.

Template:
```
Engagement: <program profile summary; what is authorized>.
Unit: <unit_id> — <component, file/handler/function/address>, engine layer <layer>,
reachable by <actor>.
Task: Assume there is a security bug in THIS unit. Read the code (or the decompiled function),
form explicit hypotheses, and test each by building a minimal testcase on the local default-config
install. 
Proof standard: a reliable trigger (sanitizer/debugger) for a memory bug, or an observable
security-boundary crossing with my own test data for a logic bug. Then STOP — do not build an
exploit, chain, or sandbox escape.
Rules: default configuration only; never use non-default switches or modified builds to make a bug
look web-reachable (the only exception is the vendor-sanctioned compromised-renderer simulation,
which must be labelled as such). Verify every offset/format/behaviour against the code or debugger;
never assume. If three attempts on a hypothesis fail the same way, log it to work/deadends.md and
move on. Checkpoint results to work/findings/<F-id>.md after every step.
Output: either a finding file with evidence, or an honest "no bug found" with what you ruled out.
```

Run several agents in parallel, one unit each, in separate profiles/VMs, highest score first.
Read `work/deadends.md` before starting a hypothesis so you never repeat a dead end.

---

## 2. Evidence rules (enforced; see also SKILL.md §4)

- **Verify, don't speculate.** Read the code/disassembly, use the debugger, print real values,
  compute with scripts. No offset/layout/format assumed.
- **No objective gaming.** No `--no-sandbox`, `--disable-web-security`, `nodeIntegration`,
  devtools-only APIs, or patched binaries to fake reachability. Compromised-renderer simulation is
  allowed only in the vendor-sanctioned form and only for bugs that legitimately assume it, always
  labelled.
- **Stop at the proof standard.** A reliable trigger + root cause is the deliverable. If the agent
  starts building primitives, grooming the heap, or writing a payload, that is out of scope — stop
  and hand the decision to the human.
- **Watch for the model cheating the objective.** Models that cannot solve the real task may
  silently change it (enable a flag, mock a component, satisfy the oracle a trivial way). Review
  transcripts for this; a "success" that used a disallowed shortcut is not a finding.
- **Checkpoint.** Every meaningful result updates the finding file and `units.tsv`. A fresh session
  must resume from files alone.

---

## 3. Oracles (how an agent knows a test succeeded)

The oracle is the difference between a verified finding and a guess. Build it into the testcase.

- **Logic / boundary bugs.** Plant known test data on the side that should be protected and detect
  it on the side that should not reach it. Examples: a secret string in origin B that a page on
  origin A prints; a file with known contents in a path the page should not read; a pref value
  that flips; a privileged handler that logs the call; data created in profile X that appears in
  profile Y. Automate with the browser's own automation surface on a dedicated test profile
  (Chromium: CDP over `--remote-debugging-port` with Playwright/Puppeteer; Firefox: Marionette/
  remote protocol; WebKit: WebDriver) so the test is repeatable and diffable.
- **Memory-safety bugs.** Prefer a vendor/upstream sanitizer build (Chromium and Firefox publish
  ASan builds) and capture the sanitizer report. Without one, run under a debugger (WinDbg/x64dbg/
  lldb/gdb), capture the faulting instruction, registers and stack, and explain the root cause.
  Note that Chromium/Firefox use custom allocators (PartitionAlloc / mozjemalloc), so OS page-heap
  tools miss most allocations — rely on the sanitizer build or the crash plus root-cause analysis.
  Minimize the testcase and confirm it reproduces on a fresh default profile.
- **Engine sandbox properties.** Use the engine's sanctioned sandbox-testing API (V8's
  memory-corruption testing API in `d8`) to demonstrate that a property can be violated — enough to
  characterize the bug, not to escape.

A finding without a runnable oracle is a hypothesis, not a finding.

---

## 4. Parallelism and deduplication

- Assign each agent a different file/function/unit so parallel agents find different bugs rather
  than the same one many times (Anthropic's and Mozilla's pipelines both do this).
- Before promoting a finding, deduplicate against: known upstream bugs (same version), already-filed
  findings in `work/findings/`, and public trackers. Collisions are common when many people point
  models at the same popular code; a quick collision check saves a wasted report.

---

## 5. Budget discipline for long autonomous runs

- Rank before searching (SKILL.md §2); start on the units most likely to matter.
- Give agents high-quality context: the surface map, the extracted vendor code, the relevant
  review lenses and case studies. Models follow good examples closely.
- Harness quality (environment, test profiles, automation, debugger integration, dead-end log,
  checkpoints) matters more than prompt wording.
- Kill sessions that spin; models often do not self-recover once stuck. Restart the unit with a
  narrower hypothesis or hand it to the human.

---

## 6. The validator pass (separate agent)

Before any finding reaches the human, a fresh agent that did **not** produce it gets:
```
I received this bug report: <finding file + testcase>. Independently try to reproduce it on the
latest release with default settings and a clean profile. Then argue, as hard as you can, that it
is NOT a security bug: that it is intended behavior, documented, an upstream issue not specific to
this target, a program exclusion, or that the testcase relied on a disallowed non-default setting.
Report: reproduced yes/no, strongest argument it is not a finding, and a verdict.
```
Only findings that survive this pass are promoted to triage (`references/triage-and-report.md`).
The validator's job is to be the skeptical vendor triager, so a weak finding dies here instead of
in the vendor's queue.
