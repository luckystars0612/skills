# Example program profile — a Chromium-based browser fork with a bug bounty

This is a filled-in example of the template in references/triage-and-report.md §5. Copy it to
work/profile.md for a real engagement and replace every value with facts verified against the
live program policy and the installed build. Nothing here overrides the proof standard in
SKILL.md §0.

```
Program: <Vendor> Bug Bounty / VRP  (policy URL: <live link>)
Legal basis: public bounty program; eligibility confirmed against the live rules: <yes/no>
In scope: <vendor>-branded browser and vendor-owned assets, per the policy's scope section
Out of scope (copy the live list): e.g. self-XSS; HTML injection; open redirect / tabnabbing;
  clickjacking without a significant state-changing action; logout/unauthenticated CSRF; missing
  headers/cookie flags without direct impact; unvalidated scanner output; issues not affecting the
  latest version; attacks needing physical access; social engineering; known-vulnerable component
  without a working exploit; third-party 0-days within N days of disclosure; rooted/jailbroken-only
  issues; Unicode/RTLO phishing; rate-limiting without security impact; intended behaviors such as
  "runs as SYSTEM"
Targets under test: <product> <exact version>, Chromium <base version>, <platform/OS build>
Accounts: my own test account(s) only
Hard rules: no testing against vendor servers; no DoS/load testing; stop on access to others' data;
  no public disclosure before fix
Proof standard the program expects: reproduction + PoC
  (This skill delivers up to reliable-trigger + root cause; higher tiers are a human decision.)
Reward tiers / severity scale: <link or summary>
Submission channel: <URL / email>
Disclosure policy: <timeline>
Notes:
  - Release cadence and patch-gap stance: record the actual upstream lag you measure in
    work/version.md; treat patch-gap as information only (triage §3), not a hunting project.
  - Focus areas for a fork: vendor-only WebUI/extensions, vendor native features and their IPC,
    account/sync/update integration, installer/updater, and any security defaults weakened vs
    upstream (review-lenses L1–L10).
```
