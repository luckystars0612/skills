# Triage and reporting

This is the gate between "I think I found something" and a submitted report. It exists to solve the
two hardest parts of bounty work: deciding whether a finding is a real, in-scope bug or intended
behavior, and writing it so a vendor accepts it. It ends with the program-profile template
(section 5) that every engagement starts from.

---

## 1. Triage questions (answer all, in writing, in the finding file)

A finding is not reportable until 1–7 are answered. A "no"/"unknown" on 1–5 blocks the report.

1. **Which security boundary is crossed?** Pick one from the cheat-sheet in `engines.md` §7. If
   none applies, it is not a vulnerability (maybe a quality bug or a privacy note).
2. **Attacker model and preconditions.** Who is the attacker (malicious web page; page on a
   specific origin; installed extension and its permissions; local unprivileged user; network
   MITM; another local app)? What must be true (user gesture, specific setting, being signed in)?
   How much user interaction? Fewer preconditions = higher severity.
3. **Reproduces on the latest release, default settings, clean profile?** If it needs a
   non-default flag or a stale version, it is likely out of scope (most programs exclude "does not
   affect the latest version" and "non-default configuration").
4. **Fork-specific or upstream?** Re-run the same testcase on upstream of the same base version. If
   it reproduces upstream, it is an upstream-engine issue: it belongs to the upstream program
   (Chrome VRP, Mozilla, Apple), not the fork — unless the fork makes an otherwise-unreachable
   upstream bug reachable, or ships it late in a way the fork program accepts. Record which.
5. **Documented feature or accepted risk?** Check the vendor's help docs and settings UI. "Runs as
   SYSTEM", "privileged user can run scripts", and similar are usually intended.
6. **Program exclusion?** Check the live program policy (it changes). Common browser-relevant
   exclusions: self-XSS; issues needing physical access; social engineering; missing security
   headers/cookie flags without direct impact; open redirect / tabnabbing; clickjacking without a
   significant state-changing action; logout/unauthenticated CSRF; unvalidated scanner output;
   known-vulnerable component without a working exploit or evidence of exploitability; third-party
   0-days within N days of disclosure; rooted/jailbroken-only issues; pure fingerprinting;
   non-sensitive info disclosure; rate-limiting without a security impact; Unicode/RTLO phishing.
7. **Severity.** Use the vendor's own scale conservatively (Chromium
   `docs/security/severity-guidelines.md`; Mozilla sec-critical/high/moderate/low; Apple/program
   equivalents), adjusted down for preconditions. Over-claiming costs credibility.

Record a verdict: `REPORT`, `REPORT-AS-CHAIN-LINK` (needs another bug for impact — note the
precondition), `UPSTREAM`, `INFO-ONLY`, or `DROP`, with confidence.

---

## 2. Common false positives in browser research

- Identical behavior in upstream at the same version (it is the engine's design or the engine's
  bug, not the fork's).
- "Bypasses" that require pasting code into DevTools or the address bar.
- Extension findings where the extension already holds the permission it "abuses".
- Local attacks where the attacker already has the victim's privileges.
- Crashes that are null-dereferences or safe release-mode `CHECK`/`MOZ_RELEASE_ASSERT` aborts
  (intentional termination, not memory corruption) — report only if a meaningful DoS is in scope.
- Fingerprinting/tracking without a specific stated guarantee being broken.
- Mixed content / TLS warnings that are working as designed.

---

## 3. Upstream vs fork routing

- Pure upstream bug → upstream program, with the reproduction on an upstream build. Do not send it
  to the fork.
- Fork-only code (vendor WebUI, extensions, native features, services, modified defaults) → fork
  program.
- Fork makes an upstream bug reachable (e.g. a relaxed default exposes it) → report to the fork the
  *reachability change*, and the underlying bug upstream.
- Patch-gap (upstream-fixed, not yet shipped by the fork) → information for the human; usually
  excluded as a known-component issue, and building an exploit for it is out of scope here.

---

## 4. Report template (`work/reports/<F-id>.md`)

```
Title: <component>: <bug class> lets <attacker> <impact>
Affected: <product> <version> (<engine> <base version>), <platform/OS build>, default settings
Not affected: upstream <engine> <version> (tested <date>)   # proves fork-specific, if applicable
Summary: 2–3 sentences — what, where, why it matters.
Security boundary crossed: <from triage Q1>
Attacker model & preconditions: <from triage Q2>
Reproduction (default config, clean profile):
  1. ...
  2. serve poc.html from <origin> / run <steps>
  3. ...
Expected vs actual: <what should happen> vs <what happens> — with oracle output / screenshot / video
Root cause: <file/resource/function or disassembly address; explanation of the flaw>
Attacker control: <what the attacker controls — offset, value, target, size, timing — with
  evidence: "varying input X from A to B changes the corrupted offset from C to D" or
  "the oracle prints the leaked secret from origin B">
Impact: <concrete; conservative; state any precondition or chain dependency>
Severity (self-assessed, vendor scale): <tier + justification per demonstrating-impact.md §3>
Suggested fix: <the check/ownership/lifetime/origin validation to add>
Attachments: minimal poc, video, logs, sanitizer/crash output (memory bugs)
```

Keep the PoC minimal and the impact claim honest. Submit through the program's channel; keep the
issue confidential until the vendor has fixed it and agreed to disclosure. If the program would pay
more for a demonstrated exploit beyond the proof standard, raise that with the human rather than
building one inside this skill.

---

## 5. Program profile template (`work/profile.md`) — fill at the start of every engagement

```
Program: <name + policy URL>
Legal basis: <public bounty / private invite / written authorization>; eligibility confirmed: <y/n>
In scope: <products, components, platforms, versions/channels>
Out of scope: <components, vuln classes the program excludes — copy the live list>
Targets under test: <product + exact version(s)>, <engine + base version>, <platform/OS build>
Accounts: <only the researcher's own / explicitly consented test accounts>
Hard rules: no testing against vendor servers; no DoS/load testing; stop on access to others' data;
            no public disclosure before fix.
Proof standard the program expects: <reproduction + PoC only / demonstrated exploit for higher tier>
  (This skill produces up to reliable-trigger + root cause; anything beyond is a human decision.)
Reward tiers / severity scale: <link or summary>
Submission channel: <URL / email>
Disclosure policy: <timeline>
Notes: <release cadence, patch-gap stance, anything program-specific>
```

If any field is unknown, resolve it (read the live policy, ask the human) before dynamic testing.
