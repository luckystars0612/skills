# Researcher notes: how the people who find these bugs actually work

Distilled from public 2018–2026 browser research and the 2026 AI-assisted efforts (Mozilla's
hardening pipeline, Anthropic's zero-day scaffold, XBOW's and Hacktron's writeups, ZDI/Pwn2Own,
long-standing vendor guidance). These are working habits and judgment calls, not exploitation
recipes. They tell an agent *how to behave* while hunting.

---

## 1. Start from the diff, not the whole codebase

Every productive fork researcher starts by isolating what the vendor changed (recon §2). New or
modified code is where the non-duplicate bugs are, because upstream reviewers never saw it. On a
pure-upstream target, start from recently changed code and from the areas the vendor's own fuzzers
reach least (logic, IPC, rarely-exercised features). Re-diff after every release — new vendor code
lands there first and is freshest/least-reviewed.

## 2. Pick the target layer by expected acceptance, not by glamour

An engine 0-day is glamorous and usually a collision or an upstream issue. A vendor WebUI handler
or an unvalidated `ipcMain` call is unglamorous and far more likely to be a unique, accepted,
fork-specific finding. Rank by real×unique×accepted (SKILL.md §2), not by how impressive the bug
class sounds.

## 3. Treat every "assumption" as a hypothesis

The most productive single question across the 2026 bugs: *"What does this code assume cannot
change, and who can actually change it?"* (CS-01, CS-05, CS-41). Make the assumption explicit, then
try to find the actor that violates it. This finds invariant bugs that fuzzers miss.

## 4. Logic bugs need a specification, not a crash

Fuzzers find crashes; they do not find "unauthenticated user can reach admin" or "profile A sees
profile B's data." For logic/boundary bugs, write down the intended policy first (the
specification), then look for a path where code and policy disagree. The oracle is the policy made
executable (harness §3). This is the highest-yield area for forks because the vendor's extra
features add policy the upstream engine never had.

## 5. Verify everything; never run on vibes

The single biggest failure mode of model-driven hunting (Hacktron's writeup is explicit about this)
is speculation: assumed offsets, guessed layouts, invented behaviors. Rules that counter it:
- Read the code or the disassembly. Confirm with the debugger. Print real values. Compute with
  scripts, not in your head.
- If you cannot explain *why* something works, you have not found a bug yet.
- When stuck, go learn the specific subsystem rather than guessing around it.

## 6. Do not let the model cheat the objective

Observed repeatedly: when a model cannot solve the real task, it quietly changes the task — enables
a flag, mocks a component, satisfies the oracle trivially, or (Hacktron) reaches for a feature like
`child_process` instead of the actual bug. Build oracles that only a genuine boundary crossing can
satisfy, and review transcripts for shortcuts. A "success" produced by a disallowed setting is not
a finding.

## 7. Context collapse and dead ends

Long autonomous runs drift: the model forgets what it tried, loops back into dead ends, burns
budget. Counter with the dead-end log and checkpoints (harness §2), one narrow unit per agent, and
killing sessions that spin. Models rarely self-recover from being stuck; restart with a narrower
hypothesis or escalate to the human.

## 8. Separate the finder from the judge

Every serious pipeline (Mozilla, Anthropic) runs a separate validation step whose job is to
*disbelieve* the finding and try to reproduce and disprove it (harness §6). The finder is
optimistic; the judge is the skeptical vendor triager. Only findings that survive the judge get
reported. This is also how you keep false positives out of the vendor's queue and protect your
reputation with the program.

## 9. Dedup before you celebrate

When many researchers (and now many models) point at the same popular code, collisions are the
norm, not the exception. Public chains have died at submission because one bug was already known
internally. Check the upstream tracker, the fork's advisories, and your own prior findings before
investing in a report (harness §4).

## 10. Prove impact, not just existence

- A trigger + root cause proves the bug *exists*. To get paid well, prove what the attacker
  *controls*: vary inputs and show the corruption tracks them; use the engine's sanctioned testing
  API (V8 `--sandbox-testing`, `%DebugPrint`) to show the primitive; print/log the leaked data for
  logic bugs. See `references/demonstrating-impact.md` for the full playbook.
- The deliverable is: reliable trigger + root cause + demonstrated impact (controlled read/write
  for memory bugs; observed boundary crossing for logic bugs) + severity justification. This is
  what vendors accept and pay for at the highest tier short of a full chain.
- When a program pays more for a full exploit chain, hand the decision to the human with the
  characterized primitive and evidence of control. This skill does not chain primitives, groom the
  heap, or write payloads.
- Stay inside the authorized target, default configuration, your own accounts. Never touch vendor
  servers. The fastest way to lose a bounty relationship — and worse — is testing outside scope.

## 11. Patch gaps are information, not a project

Public commits and advisories are effectively a bug map, and forks/Electron apps lag upstream. That
is worth *recording* (recon §1) so the human knows the target's exposure. It is not a hunting
project here: most programs exclude known-component issues without a working exploit, and building
that exploit is outside this skill's proof standard. Report the gap as information and move on to
vendor-specific code.

## 12. Keep notes a stranger could resume

Write `work/findings/<F-id>.md` as if someone else will finish it tomorrow: hypothesis, what you
read, what you tried, what the oracle showed, the triage answers, the verdict. Long engagements and
multi-agent runs depend on this far more than on any single clever insight.

---

### On safeguards and why the proof standard is drawn where it is

This skill intentionally stops at *finding, characterizing, and reporting* vulnerabilities, not at
building exploits, chains, or sandbox escapes. That line is not an obstacle to bounty work — it is
what bounty work is: a clear, reproducible report with a root cause is what vendors accept and pay
for. Identity verification, program membership, or researcher reputation do not change the line,
and are not levers to push content past it. If legitimate work seems blocked, the productive move
is to narrow the request to what detection and reporting actually require (which is everything in
this skill), and to raise genuinely exploit-dependent program requirements with a human decision-
maker and the program's own channel — not to try to reframe the task.
