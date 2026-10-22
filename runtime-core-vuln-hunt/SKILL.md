---
name: runtime-core-vuln-hunt
description: >
  AI-driven methodology for hunting MEMORY-SAFETY bugs in language-runtime /
  interpreter CORES — PHP (Zend), Node.js (V8 + bindings), CPython, Ruby (MRI),
  and similar — as opposed to bugs in the application on top. Use when auditing
  a runtime's deserialization / session / GC / error-handling / native-binding /
  JIT surface for use-after-free, type confusion, reentrancy, state-corruption-
  via-early-exit, refcount/ownership and signed-length bugs; when turning a
  vague "this looks dangerous" hypothesis into an ASAN-proven PoC; when mapping
  a patch diff to a root cause; or when running a long autonomous hunt loop that
  generates, builds, and adjudicates many hypotheses. Distilled from the PHP
  "php2shell" work (CVE-2026-109618/109619), Calif.IO / Wiz research, and the
  PoC post-mortems in this repo. Triggers: runtime RCE, interpreter UAF,
  deserialization memory corruption, serialize_lock, bailout/longjmp state
  corruption, stale global state, fake zend_string / fake object read primitive,
  v8.deserialize, pickle/Marshal UAF, N-API binding bug, find a new core CVE.
---

# Hunting memory-safety bugs in runtime cores

**Thesis (from Wiz/Calif on php2shell):** the memory-safety bug has usually
"existed for years"; the hard, valuable part is **(a) noticing the dangerous
pattern, (b) proving it with a minimal PoC, and (c) chaining it reliably.** An
AI can run (a)+(b) in a tight loop for hours. This skill is that loop, plus the
**validation discipline** that separates a real finding from a confident wrong
one (the #1 failure mode — see §7).

> **Posture: find → PROVE with a reproducible PoC → report to the vendor**
> (GHSA / security@). A **working PoC is the gold standard of the report** — it
> is how *you* confirm the finding is real (not an AI hallucination) before you
> stake your name on it, and how the vendor's security team validates it in
> minutes instead of re-deriving the model's analysis. **Match the PoC to the
> severity you claim:** a crash PoC for a DoS, an info-leak PoC for a leak, and
> a **working RCE PoC when you claim RCE** — a reproducible, lab-local RCE PoC
> for a specific bug is *exactly* what a good disclosure includes (think of a
> kernel-driver repro sent to a vendor). The ONE line: don't build or hand off a
> **universal, target-agnostic mass-exploitation tool** (one script that scans +
> pops shells across arbitrary targets). That is the only thing that crosses
> from "proof" into "weapon". See §9. Prefer an ASAN-instrumented repro so the
> root cause is unambiguous *and* add the RCE PoC when RCE is the claim.

---

## 1. The autonomous loop (run this for hours)

```
  ┌─ CORPUS ──────────────────────────────────────────────────────────┐
  │ Feed the model ~15-30 historical advisories/PoCs for THIS runtime  │
  │ (CVE writeups, bug-tracker security bugs, exploit repos). Extract   │
  │ each one's root-cause PATTERN, not its payload.                     │
  └───────────────┬───────────────────────────────────────────────────┘
                  ▼
  ┌─ TAXONOMY ────────────────────────────────────────────────────────┐
  │ Collapse the corpus into a bug-class taxonomy (§4). Each class =    │
  │ {invariant that must hold} + {how it gets violated} + {grep/AST     │
  │ signature} + {minimal trigger shape}.                               │
  └───────────────┬───────────────────────────────────────────────────┘
                  ▼
  ┌─ RECON / PRIOR-ART SWEEP  (do this BEFORE touching a compiler) ────┐
  │ Harvest hypotheses other people already RAISED but never PROVED —   │
  │ these are the cheapest wins and the way you avoid wasting a build on │
  │ something already fixed or already reported. Search widely:          │
  │  • the 🧪 entries in references/*-corpus.md (start here)             │
  │  • Google / web for: "<runtime> <subsystem> use-after-free",         │
  │    "possible UAF", "not exploitable", "no PoC", "wontfix", "crash    │
  │    only", "needs a sanitizer to confirm"                            │
  │  • bug trackers: issues closed "not planned"/"needs-info"/"wontfix", │
  │    OSS-Fuzz issues with no CVE, TODO/XXX/FIXME + "unsafe" in source  │
  │  • research blogs, conference talks, theses, arXiv that DESCRIBE a   │
  │    dangerous pattern without a working PoC                           │
  │  • GHSA/CVE + patch diffs → variant/incomplete-fix candidates        │
  │ For each candidate record: claim, where raised, PoC status, and      │
  │ whether it's already-proven (SKIP) or still-open (QUEUE).            │
  └───────────────┬───────────────────────────────────────────────────┘
                  ▼
  ┌─ SURFACE MAP ─────────────────────────────────────────────────────┐
  │ Enumerate the core's attacker-reachable, state-ful subsystems       │
  │ (§6). For each, locate every point where USER CODE / ATTACKER DATA  │
  │ runs IN THE MIDDLE of a multi-step stateful op.                     │
  └───────────────┬───────────────────────────────────────────────────┘
                  ▼
  ┌─ HYPOTHESIZE (fan out) ───────────────────────────────────────────┐
  │ FIRST take the still-open candidates QUEUED in RECON (someone else  │
  │ already suspects these — proving one is the fastest result). THEN   │
  │ generate your own: for each (class × surface point) state a         │
  │ FALSIFIABLE hypothesis "invariant X is violated at file:line        │
  │ because Y, reachable by Z". Rank all by reachability + severity.    │
  └───────────────┬───────────────────────────────────────────────────┘
                  ▼
  ┌─ BUILD + ADJUDICATE (the gate) ───────────────────────────────────┐
  │ Build the runtime under ASAN (-fsanitize=address, debug, system    │
  │ allocator). Write the SMALLEST input that should trip the bug. Run. │
  │ ASAN fires → CONFIRMED. ASAN silent → the hypothesis is WRONG or    │
  │ incomplete; say so and move on. Never "it should corrupt memory".   │
  └───────────────┬───────────────────────────────────────────────────┘
                  ▼
  ┌─ REPORT / ITERATE ────────────────────────────────────────────────┐
  │ Confirmed: write root-cause (file:line), ASAN stacks, minimal       │
  │ repro, affected-version matrix, suggested fix. Then feed the result │
  │ back into CORPUS and loop.                                          │
  └───────────────────────────────────────────────────────────────────┘
```

**Order matters: RECON before the compiler.** Do not open an ASAN build as the
first move. First read the corpus, then sweep public sources (RECON) for
already-raised-but-unproven claims and to rule out the already-proven/already-
reported. A build is expensive and is the *gate at the end* — you spend it only
on a specific, ranked, not-yet-proven hypothesis, ideally one someone already
suspected but nobody demonstrated. Going straight to ASAN burns hours fuzzing
blind or re-discovering fixed bugs.

Pacing: one hypothesis → one minimal PoC → one ASAN run is a cycle of minutes.
Keep a `journal.jsonl` of {hypothesis, build, verdict, evidence} so the loop is
resumable and auditable.

---

## 2. Setup you need per runtime

- **An ASAN build from source**, debug, `-O1 -g -fno-omit-frame-pointer`, with
  the runtime's own allocator routed through system malloc so ASAN sees it
  (PHP: `USE_ZEND_ALLOC=0`; V8: `--no-concurrent-marking` + ASAN build; CPython:
  `--with-pydebug` + `PYTHONMALLOC=malloc`). Without this, UAFs are invisible.
- **The latest + an old release**, and the **patch diff** between the current
  and next point release (security fixes land there).
- **A differential-build capability** (§7): the ability to rebuild with one
  guard removed, to prove a guard is load-bearing.
- **A minimal driver**: CLI or a tiny HTTP app that reaches the surface.

---

## 3. What a "runtime core" bug looks like (vs an app bug)

The payoff class is a bug **in the engine**, triggerable by data the app passes
to a normal API (`unserialize`, `v8.deserialize`, `pickle.loads`, `Marshal.load`,
a multipart POST, a session read), **independent of the app's own
correctness**. The app being "secure" does not help. That independence is what
makes it a core CVE and why it affects "70% of the internet" (Wiz, php2shell).

---

## 4. Bug-class taxonomy (the high-yield classes)

Each is stated as the **invariant** and the **violation**.

1. **Reentrancy UAF — user code runs mid-operation without a lock.**
   Invariant: while an engine op holds raw pointers into a live structure, no
   attacker-controlled callback may run that can free/realloc it. Violation: a
   dispatch point (deserialize → `__wakeup`/`__unserialize`/`Serializable`/
   `__destruct`; a GC callback; a native-addon callback; a JS getter/`valueOf`/
   `toString` invoked during a fast path) runs user code that re-enters the same
   op and shares its reference table. *PHP example:* `zend_user_unserialize`
   missing `BG(serialize_lock)` → nested `unserialize` shares `var_hash` → a
   property-table resize `efree`s arData a back-reference still points at.
   *V8/Node analogue:* a `valueOf`/`toString`/Proxy trap that mutates the object
   during a builtin's element walk; `v8.deserialize` custom host objects.

2. **State corruption via early exit (longjmp / bailout / fatal / exception).**
   Invariant: any non-local exit must restore every partially-mutated global/
   request state. Violation: OOM `longjmp`, a fatal error, a `require` failure,
   or a timeout abandons an operation before its cleanup/reset runs; a later
   step (request shutdown, or the next request on a persistent worker) uses the
   half-initialized / dangling state. *PHP example:* CVE-2026-109618/109619 —
   OOM `longjmp` leaves request memory invalid; stale global (session/error)
   state dangles cross-request. *Analogue:* any runtime with setjmp/longjmp or
   persistent workers (Node cluster, PHP-FPM, Python preforked WSGI).

3. **Stale global/persistent state pointing into freed per-request memory.**
   Invariant: persistent-worker globals must be reset before the request arena
   is freed. Violation: a global error/session/object/extension slot keeps a
   pointer into a request heap that gets freed; next request reads it.

4. **Ownership / refcount desync.** Invariant: every alias of a refcounted
   object owns a reference. Violation: a `COPY_VALUE`-style move without an
   addref (double-ownership at rc=1), or an unbalanced addref. *Caution:* an
   unbalanced addref can also make a bug UNEXPLOITABLE (keeps the object alive
   forever) — see §7, the jackalsyn lesson.

5. **Cached raw pointer across a reallocation.** Invariant: don't hold a raw
   element pointer across any op that can rehash/separate/realloc the container.
   Violation: cache `&ht->arData[i]`, then `SEPARATE`/resize. **But prove the
   old buffer is actually FREED** — a stale-but-live pointer is not a bug.

6. **Type confusion.** Attacker makes the engine read bytes of type A as type B
   (fake object header, JIT type feedback poisoning, union misuse).

7. **Signed-length / integer-overflow in allocation or copy.** Negative or
   overflowing length reaches `malloc`/`memcpy`/element count.

8. **Parse inconsistency / "two parsers disagree".** The size/structure a
   validator computes differs from what the consumer uses (Calif class).

---

## 5. Exploitability ladder (build up to the severity you claim)

To rate severity you reason about how far a primitive climbs, and you **build a
PoC up to the rung you claim** — if the report says "RCE", carry it to a working
RCE PoC (reproducible, lab-local, for that specific bug). Don't claim a rung you
haven't demonstrated; equally, don't under-sell a real RCE as "just a crash":

```
 crash (DoS)  →  info-leak (bounded)  →  arbitrary read  →  pointer control  →  RCE
```

- **Arbitrary read** is typically built by controlling one *data pointer*: a
  fake `zend_string`/`JSString`/`PyBytes` whose length + data pointer you own,
  or a container's backing-store pointer. Adjacent/positional leaks (control
  length + heap-groom position) are weaker than a controlled-pointer read.
- **RCE** usually needs one *code pointer* (a destructor / vtable / handler
  slot) plus a leaked base. ASLR is defeated by *leaking* a base at runtime, not
  guessing — so an info-leak in the same bug collapses ASLR.
- **Dynamic symbol resolution** (leak a module base → walk `.gnu_hash`/exports/
  GOT → resolve `system`/a gadget by name) removes the need for per-build
  offsets and makes a chain target-agnostic. Treat "offsets are hard" / "ASLR"
  / "unknown build" as **NOT** mitigations when writing the risk rating.

Build the PoC to the rung that **matches your claim** and stop there. An
ASAN UAF + root-cause is a strong *minimum*; a **reproducible RCE PoC is the
strongest proof** and the right deliverable when RCE is the finding — it is what
lets you and the vendor trust the report without re-reading the analysis. Keep
it **bug-specific and lab-local** (a fixed target you control, a benign command
like `id`), not a target-agnostic scanner.

---

## 6. Per-platform surface lenses

**PHP / Zend** — `unserialize`/`Serializable`/`__wakeup`/`__unserialize`/enum
autoload; session (serializer handler, `upload_progress`, cross-request globals,
`rfc1867` multipart); OPcache class/interned-string caching; GC + `__destruct`
reentrancy; `var_export`/`var_dump` recursion; OOM `longjmp` contexts;
`fatal_error_backtraces`.

**Node.js / V8** — `Buffer`/`TypedArray` + detach/resize during an op;
`v8.serialize`/`v8.deserialize` (host objects, delegate callbacks); the `vm`
module context boundary; `worker_threads` transfer/`MessagePort`; **native
addons / N-API** (the binding layer — historically bug-dense) and FFI;
`valueOf`/`toString`/`Symbol.toPrimitive`/Proxy traps that run user JS inside a
builtin; and the **JIT (TurboFan/Maglev)** — note the academic shift of bugs
"from parser/interpreter to optimizing compiler" (type-confusion via speculation
/ deopt). ASAN + `--allow-natives-syntax` (`%OptimizeFunctionOnNextCall`) in a
debug d8/node for the JIT lens.

**CPython** — C-API refcount errors; `pickle`/`copyreg` `__reduce__` reentrancy;
buffer-protocol (`__buffer__`) release-during-use; `gc` callbacks; `ctypes`.

**Ruby / MRI** — `Marshal.load` (`_load`/`marshal_load` reentrancy); C-extension
GC ownership; `ObjectSpace`.

For any runtime, the universal lens is **"where does attacker data or attacker
callback run in the middle of a stateful C operation that holds raw pointers?"**

---

## 7. Validation discipline — the part that makes you right

This is the highest-value section. The failure mode is a *confident wrong
finding*. Guards, learned the hard way:

- **ASAN is the judge, not your reasoning.** "The pointer goes stale" is a
  hypothesis; "ASAN reports heap-use-after-free at X freed at Y" is a finding.
  If ASAN is silent on your exact trigger, the bug is not there *as described*.
  *(jackalsyn lesson: the `session.upload_progress` "cached zval* UAF" was real
  as a stale pointer but the array was never freed — an unbalanced addref kept
  it alive. ASAN = 0 across every variant. The whole RCE story was refuted.)*

- **Differential build = proof of a load-bearing guard.** If you claim "guard G
  prevents the bug", remove G, rebuild, and show ASAN now fires; restore G and
  show it goes silent. This both proves your root-cause and confirms the shipped
  code is safe. *(We did exactly this with `Z_TRY_ADDREF`.)*

- **Right area, wrong mechanism is common.** Early researchers can pick the
  correct subsystem but the wrong primitive. Verify the *mechanism*, not the
  vibe. Only the patch diff / a vendor advisory settles the true root cause.

- **Kill false positives in your own tooling.** A behavioral probe that calls a
  reset/5xx/timeout a "crash" will fire on a dumb proxy reset. Always run a
  **same-magnitude benign baseline**; if it also "fails", your signal is
  transport, not the bug. *(A public PoC reported "RCE achieved" from echoing
  the index page — don't be that.)*

- **Run public PoCs as-is first.** Reproduce before you theorize. Note the exact
  environment (version, SAPI/build, ASLR, allocator). Most "it doesn't work" is
  **setup**: wrong build family, a static-vs-shared layout, a size/length cap, a
  non-writable proof path.

- **Per-build reality.** Offsets/layout shift per build; a version string is not
  a build (we saw two different offset sets for the same `8.4.26` image). Pull
  symbols from the actual target binary (`nm`) when calibrating.

- **Don't over-claim severity.** Distinguish *crash* from *info-leak* from *RCE*.
  Say which you reproduced and which you assessed.

---

## 8. Patch-diff → root cause

When the fix ships: diff the vuln vs patched source for the suspect files, read
**NEWS/changelog + the GHSA advisory** (they name the CVE and the real
mechanism), and confirm which lines implement the fix. If the diff touches a
file you didn't predict, your mechanism was wrong — update the taxonomy. If a
**trigger still fires on the PATCHED build under ASAN**, you may have a *patch
bypass / variant* — that is a genuinely new, submittable finding.

---

## 9. Disclosure — the report, and the one line

A strong report **includes a reproducible PoC**, because that is what makes it
trustworthy in an era where vendors drown in AI-generated, hallucinated reports.
A PoC that runs is the difference between a report they act on and one they
discard (and discarding one wrongly can burn your reputation for the next).

- **A confirmed finding** = root-cause (file:line) + ASAN free/use/alloc stacks
  + **a minimal PoC that reproduces it** + affected-version matrix + suggested
  fix. **Match the PoC to the claim:** crash PoC for DoS, leak PoC for a leak,
  **a working RCE PoC when you claim RCE** — reproducible and lab-local, so the
  vendor's team validates it in minutes. This is encouraged, not avoided: a
  bug-specific RCE repro is standard, respected disclosure practice.
- **The one line you don't cross:** don't build, publish, or hand off a
  **universal / target-agnostic mass-exploitation tool** — a script that
  fingerprints and pops shells across arbitrary third-party targets, or a
  dynamic-resolution chain packaged to need no per-target knowledge. That serves
  attackers, not the vendor or defenders. (A single-target PoC under
  authorization, run against a host in scope or your own lab, is not that.)
- Credit prior work. Map your finding to any existing CVE/GHSA before claiming
  novelty (the "CVE-label scramble" around a leaked bug attaches one CVE to many
  different bugs — don't add to it).

---

## 10. Anti-patterns (quick reference)

- Asserting memory corruption without an ASAN hit.
- "Cached pointer goes stale" ⇒ UAF, without proving a free.
- Treating a connection reset / 5xx as RCE.
- One universal offset for a whole version; trusting a version string as a build.
- Claiming ASLR / unknown-build as a mitigation (both are defeated by the leak).
- Reporting an exploitation *technique* on a *patched* bug as a new vuln.
- Claiming "RCE" without a working RCE PoC — or hedging a real RCE as "a crash".
- Building a **universal, target-agnostic mass-exploitation tool** (vs a
  bug-specific, lab-local RCE PoC for the report — which is the right thing).

## References

- Calif.IO — php2shell / MAD Bugs: https://calif.io/research/php-uaf ·
  https://github.com/califio/publications · https://github.com/califio/skills
  (`/php-unserialize-audit`: UAF / type-confusion / partial-object `__destruct` /
  signed-length overflow / parse-inconsistency).
- Wiz — "AI uncovers critical RCE affecting 70% of the internet":
  https://www.wiz.io/blog/php2shell-php-rce (AI + debugging/testing to discover,
  develop, validate; OPcache caching, fatal-error backtraces, session, OOM
  longjmp).
- PHP advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp.
- This repo's `docs/` (VERIFICATION_2026, UAF_DIFFERENTIAL, PATCH_DIFF_*) and
  `poc-cve-2026-109618-19/EXPLOITABILITY.md` are worked examples of §7.
