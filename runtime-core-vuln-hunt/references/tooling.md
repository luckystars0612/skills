# Tooling & methodology — how these bugs are actually found

Part of `runtime-core-vuln-hunt`. The concrete fuzzers, sanitizer builds, static
analysis, AI loops, and triage used to find/validate runtime-core memory bugs.

## 1. Fuzzers
- **Fuzzilli** (`googleprojectzero/fuzzilli`) — standard **JS-engine JIT** fuzzer.
  Mutates **FuzzIL** (custom IL), lifted to JS only at execution → stays valid,
  exercises JIT type speculation (plain API fuzzing can't reach JIT bugs). NDSS
  2023: 17 vulns/6mo. Weakness → V8 added hand-written **Program Templates** for
  specific JIT regions. Targets V8/d8, JSC, SpiderMonkey.
- **AFL++ / libFuzzer** — general coverage-guided; wrap a parse/eval/deserialize
  entry as a harness, or run the interpreter under AFL++ instrumentation/QEMU.
  Pair with structure-aware mutators (raw bytes rarely make valid bytecode).
- **Grammar fuzzers:** domato, **Grammarinator** (ANTLR grammar → AFL++ custom
  mutator, structure-preserving), gramatron/atnwalk; **Jackalope** (coverage-guided
  black-box, Win/macOS, no source).
- **OverrideFuzz** (arXiv **2605.12563**) — semantic-aware grammar fuzzer for
  **script runtimes** (CPython/Lua/QuickJS). Two-phase grammar (declaration vs
  execution) + mutators targeting override/dynamic-rebinding → reaches type
  confusion / prototype pollution. *Honest: no novel bugs in its eval; value =
  the methodology for generating override-hook reentrancy inputs.*
- **Weaver** (arXiv **2603.18789**) — greybox fuzzer at the **JS↔Wasm boundary**;
  type-aware generator keeps a dual-type representation per variable, UCB-1 bandit
  schedules mutators. 2 new bugs across 3 engines.
- **Wasm-specific:** RGFuzz (rule-guided, wasmtime), WADIFF (differential across
  runtimes), Fuzzm (arXiv 2110.15433, binary-only).

## 2. Sanitizer builds (custom allocators HIDE bugs — force malloc)
| Runtime | Recipe |
|---|---|
| **PHP/Zend** | `CFLAGS="-fsanitize=address"`; **`USE_ZEND_ALLOC=0`** + `USE_TRACKED_ALLOC=1` (ZendMM hides OOB). `--enable-memory-sanitizer` for MSAN (uninit reads). |
| **CPython** | `./configure --with-pydebug --with-address-sanitizer`; `--without-pymalloc` **or** `PYTHONMALLOC=malloc` at runtime. `PYTHONMALLOC=debug` = guard bytes w/o ASAN. |
| **V8/d8** | gn `is_asan=true is_debug=false v8_enable_verify_heap=true dcheck_always_on=true`; UBSAN/MSAN/TSAN via `is_*`. Harness flags `--allow-natives-syntax --expose-gc --sandbox-testing`. |
| **Node** | `./configure --debug` / `--enable-asan` (covers bundled V8 + N-API/libuv). |
| **BEAM** | `./configure --enable-address-sanitizer`; fuzz `binary_to_term`, port drivers, NIFs. |

**Which sanitizer finds what:** ASAN = OOB/UAF/double-free · MSAN = uninit reads
(needs instrumented deps) · UBSAN = signed overflow / bad cast / OOB-index (catches
the integer→OOB root *before* it corrupts) · TSAN = data races (Go/BEAM/free-threaded
CPython/JIT threads).

## 3. Static analysis & AI-assisted
- **CodeQL / Semgrep variant analysis** — model a known bug as a query, sweep for
  siblings (CodeQL multi-repo for scale). ToB guidance: ripgrep→Semgrep→CodeQL by
  complexity; start matching the known bug *exactly* then generalize; **>50% FP =
  too generic**; keep in CI for recurrence.
- **DNA** (CISPA, 2026) — synthesizes CodeQL queries from CVE + patch diff, repairs
  with compiler/LSP feedback + doc retrieval (LLMs invent API symbols otherwise).
- **The AI research loop:**
  - **Project Naptime → Big Sleep** (Project Zero + DeepMind): agent with Code
    Browser / sandboxed Python (fuzzing) / Debugger / Reporter tools; hypothesis-
    driven, reproducible; pivoted to **variant analysis**; found a real SQLite
    memory bug OSS-Fuzz missed — first public AI-agent case.
  - **Wiz/Calif/OpenAI/Quarkslab — php2shell** (CVE-2026-109618/109619): frontier-AI
    + ASAN/debugger loop to *discover, develop, validate*; "bug existed for years,
    hard part is chaining it." (Distinct from **wp2shell**, CVE-2026-63030/-60137,
    an OpenAI-assisted *WordPress-core* chain — don't conflate the two.)
  - **CVE-2026-75538 (Erlang inet heap overflow) was found by Claude** + Ada Logics
    — real data point for the agentic approach.
- **Differential patch analysis** — diff the fix to recover root cause (changed
  bounds check / added length validation / type guard), then write the variant
  query + an N-day repro. Closed-source: BinDiff/Ghidra.

## 4. Triage / debugging
- **gdb** (+ `rr` record/replay, pwndbg/gef) — catch crash, inspect corrupted
  object/metadata; ASAN's alloc/free stacks give the lineage immediately.
- **Differential builds** — ASAN vs release; `--with-pydebug` vs normal; JIT-on vs
  `--no-turbofan`/`-Xint`/interpreter-only — localize JIT vs GC vs interpreter and
  separate real corruption from allocator artifacts. (Same technique as the PHP
  `Z_TRY_ADDREF` differential in this repo's `docs/UAF_DIFFERENTIAL_2026.md`.)
- **Minimization** — afl-tmin / halfempty / C-Reduce / delta-debug on the FuzzIL or
  grammar output; re-confirm under ASAN each step.
- **Discipline:** reproduce under ASAN → classify (UAF / OOB-read / OOB-write / type
  confusion) → determine attacker control over the corrupted value/pointer →
  DoS-only vs R/W primitive → map to CWE + fixing commit. (SKILL.md §7.)

## Sources
arxiv 2605.12563 (OverrideFuzz) · 2603.18789 (Weaver) · 2110.15433 (Fuzzm) ·
github.com/googleprojectzero/fuzzilli · ndss-symposium.org 2023-290 · grammarinator
docs · hacking.kaist.ac.kr RGFuzz · projectzero.google Naptime (2024/06) + Big Sleep
(2024/10) · cispa.de DNA · github.blog multi-repo variant analysis · wiz.io
php2shell + wp2shell · fuzzing-project.org tips (USE_ZEND_ALLOC=0) · cpython
ASAN/pymalloc commit.
