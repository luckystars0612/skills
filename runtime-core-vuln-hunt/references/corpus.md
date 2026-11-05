# Corpus — runtime-core memory-safety bugs (historical → current)

**This file = the cross-runtime TAXONOMY + index. Per-runtime deep-dives:**
- `v8-corpus.md` — V8 engine (TurboFan/Maglev type confusion, Wasm, heap sandbox)
- `nodejs-corpus.md` — Node core (vm/Buffer/worker, N-API), vm2/isolated-vm, Deno/Bun
- `cpython-corpus.md` — CPython (#157197 100-bug set, free-threading, reentrancy)
- `ruby-perl-lua-php-corpus.md` — Ruby Marshal/GC-compact, Perl, Lua bytecode, PHP extras
- `managed-runtimes.md` — JVM/HotSpot, .NET/CoreCLR, Wasm runtimes, BEAM, Go
- `tooling.md` — fuzzers (Fuzzilli/OverrideFuzz/Weaver), sanitizer builds, AI loop, triage

Reference corpus for the **CORPUS → TAXONOMY** phase of `runtime-core-vuln-hunt`.
Feed these patterns to the model, collapse to the taxonomy, then scan a target.
Entries are tagged with **PoC status** because an unproven hypothesis is a
*candidate*, not a finding (OverrideFuzz / CPython-fuzzing standard: an
ASAN-detected memory violation is what promotes a candidate to "present").

Legend: ✅ PoC/ASAN-confirmed · ⚠️ reported-with-claimed-PoC, unverified ·
🧪 hypothesis / research direction with no public PoC.

---

## 0. Foundational reading (methodology)

- **GitHub Security Lab — "Now you C me, now you don't"** (hidden C attack
  surface of interpreted languages). Thesis: *"the illusion of memory safety"* —
  the C layer under PHP/Python/Perl/Ruby holds exploitable bugs the high-level
  logic can't see; *"if you can't go wide, go deep."* Shows how an app-level bug
  that "can't reach code execution" is **pivoted to RCE** by an interpreter
  memory-corruption primitive. Examples: Perl `Perl_sv_vcatpvfn` format string
  (CVE-2005-3962); **PHP `debug_backtrace()` UAF (bug #76047)** used to escape
  config restrictions; Python `socket.recvfrom_into` missing size check
  (CVE-2014-1912). → https://github.blog/security/vulnerability-research/now-you-c-me-now-you-dont/
- **Wiz / Calif / OpenAI / Quarkslab — php2shell.** Frontier-AI + ASAN/debugger
  loop to *discover, develop, validate*; "the bug existed for years, the hard
  part is chaining it reliably across environments." OPcache class caching,
  fatal-error backtraces, session, OOM `longjmp`. → https://www.wiz.io/blog/php2shell-php-rce
- **Calif `/php-unserialize-audit`** bug classes: UAF, type confusion,
  partial-object `__destruct`, signed-length heap overflow, parse inconsistency.
- **Validation standard (academic):** OverrideFuzz — *"triggering a memory-safety
  violation the ASAN detects is sufficient to demonstrate presence; full exploit
  dev is out of scope."* Python-bytecode fuzzing — *"crash grouping is
  symptom-based and does not establish exploitability."* → crash ≠ RCE; prove the
  rung you claim.

---

## 1. Universal bug-class taxonomy (with cross-runtime instances)

### A. Reentrancy UAF — user code runs mid-operation without a lock
*Invariant:* while an op holds raw pointers into a live structure, no
attacker-controlled callback may free/realloc it.
- **PHP** ✅ `zend_user_unserialize` missing `BG(serialize_lock)` → nested
  `unserialize` shares `var_hash`; property-table 8→16 resize `efree`s arData a
  back-ref still indexes (Calif). Enum-autoload variant fixed in `b4a63ec`.
- **PHP** ✅ `var_destroy` `__destruct` re-entry UAF (dinosn) — frees `var_entries`
  chunk without resetting `last`, dispatches `__destruct` without the lock.
- **CPython** ⚠️ #93 decoder callback re-enters `seek()` → outer call reads freed
  input (`TextIOWrapper`). ✅(historical) buffer-protocol UAF with custom index
  (#29028).
- **Node/V8** 🧪 `valueOf`/`toString`/`Symbol.toPrimitive`/Proxy trap that mutates
  or detaches an object *during* a builtin's element walk (TypedArray/Array fast
  paths); `v8.deserialize` host-object delegate callbacks. Strong direction,
  needs a concrete reachable sink + PoC.

### B. State corruption via early exit (longjmp / bailout / fatal / exception)
*Invariant:* a non-local exit must restore every partially-mutated global/request
state.
- **PHP** ✅ CVE-2026-109618/109619 — OOM `longjmp` leaves request memory
  invalid; stale global (session/error) state dangles cross-request.
- **Any runtime with setjmp/longjmp or persistent workers** 🧪 — CPython
  (interrupt during GC), Ruby, Node cluster/preforked WSGI. Look for a fatal path
  that skips a reset that a later request/shutdown relies on.

### C. Stale global/persistent state → freed per-request memory
- **PHP** ✅ 109619 (session "send cookie" flag + stale `PS(id)`), used by 9bie's
  Set-Cookie heap leak.
- **Node** ⚠️ CVE-2025-23083 internal worker reachable via `diagnostics_channel`
  (permission bypass, not memory — but same "leaked internal handle" shape).

### D. Ownership / refcount desync
- **PHP** `COPY_VALUE` moves without addref (double-ownership rc=1). *Caution:* an
  unbalanced addref can make a bug UNEXPLOITABLE (jackalsyn's refuted
  upload_progress "UAF" — the array never freed). Always prove the free.
- **CPython** ⚠️ borrowed-reference promotion races (#15, #17, #37, #91): C code
  uses a borrowed ref another thread frees before it takes its own.
  ⚠️ #73 `PySys_GetObject()` returns a borrowed ref callers over-trust.

### E. Cached raw pointer across a reallocation
- **PHP** the upload_progress cached `zval*` (stale but **not freed** — ❌ not a
  bug; cautionary example).
- **CPython** ⚠️ bytearray/memoryview resize while native code holds old
  ptr+len (#74 `RawIOBase.read()` callback, #50 pickling a resizing bytearray,
  #45 memoryview release, #64 `PyArg_Parse` `et` reading released storage).

### F. Type confusion
- **V8** ✅ the dominant Chrome RCE class — TurboFan/Maglev assume an object map /
  type-feedback and fail to deopt when it changes: CVE-2020-16009 (map-deprecation
  deopt), CVE-2022-1364, CVE-2025-2135 (V8CTF), CVE-2025-10585 (Proxy →
  Ignition/TurboFan), CVE-2026-6307 (JS→Wasm deopt metadata), CVE-2026-85046
  (`Array.prototype.sort` inline, Maglev+TurboFan, ITW). Academic note: bug
  prevalence is **shifting parser/interpreter → optimizing compiler**.
- **Sandbox/embeddings** ✅ `isolated-vm` `ExternalCopy` type confusion → host
  memory corruption → host RCE (3rd-party, but exact runtime-core shape).
- **PHP** 🧪 fake object header / `zend_internal_function` confusion (used in
  exploitation, not as the root bug).

### G. Signed-length / integer overflow in alloc or copy
- **Python** ✅ CVE-2014-1912 `socket.recvfrom_into` missing size check.
- **General** 🧪 any `C:<len>:` / length-prefixed decoder that trusts a signed or
  unbounded length (Calif's "signed-length heap overflow" class).

### H. Parse inconsistency ("two parsers disagree")
- Validator's computed size/structure ≠ consumer's. Calif class; look in any
  format with a length/terminator the checker and the user read differently
  (multipart, serialize streams, headers).

### I. Concurrent mutation / non-atomic guards (free-threaded era)
- **CPython 3.14 free-threading** ⚠️ large new surface: #59 non-atomic Unpickler
  "running" guard (two callers mutate one Unpickler's native state); #51 concurrent
  pickle dispatch-table replacement reclaims a borrowed reducer; #7/#24/#81
  concurrent container mutation invalidating saved indices; #31 `gc.callbacks`
  promotion race; #14 double-free of a `_curses` encoding pointer. Source:
  python/cpython#157197 (100 reports, static-analysis, **claimed PoC but closed
  "not planned" / unverified** → a corpus of *candidates*, perfect hunting leads).

---

## 2. Per-runtime quick tables

### PHP / Zend
| Ref | Class | Status |
|---|---|---|
| CVE-2026-109618/109619 (php2shell) | B/C OOM+stale | ✅ |
| `serialize_lock` unserialize UAF (Calif) | A | ✅ |
| `var_destroy __destruct` re-entry (dinosn) | A | ✅ |
| bug #76047 `debug_backtrace()` UAF | A | ✅ (GitHub SecLab) |
| 2015-16 unserialize UAFs (Taoguang Chen: #68976, #70172, #70436, #70219) | A/E | ✅ historical |
| upload_progress "cached zval*" (jackalsyn) | E | ❌ refuted (keep as lesson) |

### Node.js / V8
| Ref | Class | Status |
|---|---|---|
| V8 TurboFan/Maglev type confusion (16009/1364/2135/10585/6307/85046) | F | ✅ |
| CVE-2025-55131 vm-timeout Buffer race (uninit mem) | B/E | ✅ |
| CVE-2025-23083 worker handle via diagnostics_channel | C (shape) | ✅ |
| `isolated-vm` ExternalCopy type confusion | F | ✅ (3rd-party) |
| `vm2` sandbox escapes (CVE-2026-47140 et al.) | F/logic | ✅ (3rd-party) |
| `v8.deserialize` host-object delegate | A/F | 🧪 under-explored |
| N-API / native-addon binding UAF/overflow | D/G | 🧪 historically dense, few public core CVEs |

### CPython
python/cpython#157197 clusters (⚠️ unverified): borrowed-ref races, concurrent
container mutation, buffer-protocol UAF, pickle concurrency, non-atomic guards,
reentrancy (#93), gc/refcount, C-API misuse. Historical ✅: #29028 buffer UAF,
CVE-2014-1912 recvfrom_into.

### Ruby / Perl
| Ref | Class | Status |
|---|---|---|
| `Marshal.load` gadget chains (CVE-2020-8165, ERB CVE-2026-41316) | logic (CWE-502) | ✅ (not memory) |
| Oj gem `array_class/hash_class` not GC-marked → UAF (CVE-2026-54901) | D (GC-marking) | ✅ (3rd-party) |
| **Core `Marshal.load` C-level memory bug** | A/D | 🧪 **gap — none found; worth auditing** |
| Perl `Perl_sv_vcatpvfn` format string (CVE-2005-3962) | format-string | ✅ historical |

---

## 3. Open hypotheses / under-explored directions (no public PoC)

These are *candidates* — exactly the leads to turn into ASAN PoCs:
1. 🧪 **V8 `valueOf`/Proxy reentrancy during a builtin element walk** → detach/
   resize a TypedArray mid-op (class A on V8). Dense historically but each needs
   a specific reachable sink.
2. 🧪 **`v8.deserialize` / Node `Buffer` host-object callbacks** re-entering
   deserialization (class A on Node core, not userland).
3. 🧪 **CPython free-threading (3.14+)**: the 100 reports in #157197 are claimed
   but unverified — pick a cluster (pickle concurrency, buffer-protocol UAF),
   build CPython `--with-pydebug PYTHONMALLOC=malloc` + ASAN/TSan, and promote
   candidates to findings. High yield, low competition.
4. 🧪 **Ruby core `Marshal`/`GC.compact` C-level UAF** — no public core memory
   CVE; `Marshal` custom `_load`/`marshal_load` reentrancy under GC compaction is
   unaudited territory.
5. 🧪 **Early-exit/bailout (class B) outside PHP** — any runtime with longjmp or
   preforked persistent workers; the php2shell pattern likely has analogues.
6. 🧪 **N-API / native-addon binding layer** — the "bilingual" boundary (scripting
   ↔ C) is historically bug-dense (academic: arxiv 2111.11169) but has few public
   *core* CVEs; auditing the N-API type/lifetime checks is open ground.

---

## 4. The validation bar (don't skip)

Promote 🧪/⚠️ → ✅ only with: an **ASAN free/use/alloc stack** on a minimal input,
a **root cause at file:line**, and (if claiming RCE) a **reproducible lab-local
RCE PoC**. Differential-build to prove any "this guard stops it" claim. Map to
existing CVEs before claiming novelty. See SKILL.md §7.

---

## Sources
- GitHub SecLab "Now you C me…" · Wiz php2shell · Calif php-uaf / califio/skills
- V8/Chrome: Security Boulevard (2135), ZeroPath/Tashita (6307), SentinelOne
  (1364), securityarsenal (85046)
- Node: nodejs.org security releases, endorlabs, osseva.io version tables,
  CVE-2025-55131/23083; isolated-vm (thehackernews), vm2 (securityonline)
- CPython: python/cpython#157197; arxiv OverrideFuzz (2605.12563), bytecode study
  (2608.12853), CONCURDEP (2609.28608)
- Ruby: Trail of Bits "Marshal madness"; Oj CVE-2026-54901; ERB CVE-2026-41316
