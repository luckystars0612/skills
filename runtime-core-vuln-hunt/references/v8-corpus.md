# Corpus — V8 engine core (2018→2026)

Part of `runtime-core-vuln-hunt`. V8 itself (TurboFan/Maglev/Ignition, builtins,
GC/Oilpan, Wasm, the V8 heap sandbox) — not Blink/app logic.
✅ public PoC · ⚠️ advisory/ITW only, no public PoC · 🧪 hypothesis.

> **Recency caveat:** some 2026 root-cause narratives come from AI-generated/
> secondary blogs (ZeroPath labels its own analysis "AI-generated"). Treat 2026
> root causes as provisional until the Chromium issue tracker confirms.

## 1. JIT type confusion (CWE-843 — the dominant renderer-RCE class)
Meta-pattern: the optimizer makes a type/shape assumption (feedback, map
tracking, range analysis) the runtime later violates, and the deopt guard is
missing/wrong/bypassable → confused object → OOB R/W → `addrof`/`fakeobj`.

| CVE | Compiler | Root-cause sub-pattern | ITW | PoC |
|---|---|---|---|---|
| 2019-5782 | TurboFan | range/type inference (`Object.defineProperty`) | — | ✅ |
| 2020-6418 | TurboFan | speculation / type-feedback poisoning | ITW | ✅ |
| **2020-16009** | TurboFan | **map deprecation** (pointer-compression edge) → stale optimized code (TAG) | ITW | ✅ (edb 49745) |
| 2020-16040 | TurboFan | range analysis / bounds-check elimination → OOB write | — | ✅ |
| 2021-21224 | TurboFan | int data-type conversion (S32/float) → arbitrary R/W (KEV) | ITW | ✅ (crbug 1195777) |
| 2022-1096 / 1364 / 3723 / 4262 | TurboFan | type confusion (details withheld) | ITW | ⚠️ |
| 2023-2033 / 3079 / 4762 | TurboFan | type confusion, crafted page (KEV) | ITW | ⚠️ |
| 2023-4068 / 4069 | **Maglev** | WasmNull-vs-JSNull / Maglev type confusion | — | ✅ (writeups) |
| "incomplete object init" | **Maglev** | object fields uninit across deopt boundary (GH SecLab 2023) | — | ✅ |
| 2024-4947 | **Maglev** | ES module namespace export stores (also a Node advisory, Maglev default ≥Node22) | ITW | ⚠️ |
| 2024-2887 | TurboFan/Wasm | Wasm recursive-type count check insufficient (**Pwn2Own 2024**) | — | ✅ (ZDI) |
| 2025-2135 | V8 JIT | type confusion (**NOT ITW, no public PoC** — correct the record) | no | ⚠️ |
| 2025-5419 / 6554 / 10585 | V8 | type confusion / OOB, arbitrary R/W, crafted page (KEV) | ITW | ⚠️ |
| 2026-5865 | **Maglev** | **phi-node untagging** mis-handling (DB-only) | — | 🧪/⚠️ |
| 2026-6307 | TurboFan | JS→Wasm deopt-fallback type confusion (root cause AI-generated) | — | 🧪 |
| 2026-85046 | Maglev+TurboFan | **array element-type misinterpretation** (ITW; reporter Serotav) | ITW | ⚠️ |

Sub-patterns to index: map deprecation · speculation/feedback poisoning ·
range/int-conversion · deopt/incomplete-init · JS↔Wasm boundary.

## 2. Other core classes
- **OOB builtins** (Array/TypedArray/RegExp): 2025-5419 (ITW), 2018-16065
  (`BigInt64Array.of` — also reentrancy), StarLabs "incorrect bitwise AND" ✅.
- **UAF/GC**: 2024-3914/4949/5841, 2025-0445/0995; 2026-13965 (Oilpan UAF, DB-only
  🧪). Pattern: stale pointer survives GC (missed handle/write-barrier/stack-scan).
- **Integer overflow**: usually surfaces as the §1 range confusions, or
  count/length overflow in Wasm parsing (2024-2887).
- **WebAssembly**: 2023-4068 (null ref confusion) ✅, 2024-2887 (recursive-type) ✅,
  Black Hat Asia 2025 cluster (2024-5158/7550/3156/8638/5838 — WasmObject↔JSObject,
  WasmGC, JSPI) ⚠️/✅.
- **V8 sandbox (heap cage)**: all heap objects in a 4GB cage, 32-bit compressed
  ptrs; C++ objects/bytecode/JIT-metadata indirected via External/Trusted/Code
  Pointer Tables **outside** the cage. In-cage arbitrary R/W is now *contained* →
  modern RCE needs an **additional sandbox escape** (2024-2887 ZDI documents the
  cage held). TikTag (arXiv 2406.08719) has a speculative escape appendix. No
  clean public "sandbox bypass" CVE — under-published 🧪.

## 3. Reentrancy (user JS mid-builtin)
Pattern: `CHECK_not_detached` → `ToNumber/ToPrimitive/ToString/getter/Proxy trap`
(runs user JS that detaches/resizes) → builtin resumes on stale ptr/len.
- 2018-16065 (`EmitBigTypedArrayElementStore`, BigInt conversion detaches) ⚠️.
- CVE-2020-17053 is **Chakra/IE, not V8** — canonical study only, don't file under V8.
- Surface (Fuzzilli-found): TypedArray set/copyWithin/fill/sort comparators,
  `Array.sort` resizing a RAB/GSAB, RegExp `lastIndex`/`Symbol.replace`, Proxy traps.
- **Heuristic:** any builtin doing detach-check → user-coercion → cached-data_ptr
  access without re-validation after the callout.

## 4. Exploitation primitives (severity only)
Bug → `addrof`/`fakeobj` → relative-then-absolute R/W → (historically) the
"Wasm RWX page" trick, now mostly mitigated by the sandbox/W^X → needs a further
escape. (For rating impact; no step-by-step here.)

## 5. Tooling
- **Fuzzilli** (FuzzIL-based, coverage-guided; V8/JSC/SpiderMonkey; hundreds of bugs).
- **d8 `--allow-natives-syntax`**: `%PrepareFunctionForOptimization` → warmup →
  `%OptimizeFunctionOnNextCall` → call; `%DeoptimizeFunction` for deopt paths;
  `--maglev/--turbofan/--jit-fuzzing`.
- ASan (standard), MSan (uninit — incomplete-init bugs), TSan (GC/concurrency).
- `test/mjsunit/regress/` corpus, crbug tracker, Project Zero 0day RCAs, patch-diff.

## 6. Open hypotheses (🧪)
1. **RAB/GSAB resizable-buffer reentrancy** — resize a GSAB in a comparator/
   coercion during sort/set/copyWithin; under-covered variant of the detach bug.
2. **Maglev deopt state divergence** — newer, less-tested; incomplete-init +
   phi-untagging suggest a class; differential-fuzz Maglev vs TurboFan vs Ignition.
3. **JSPI / WasmGC boundary** — stack-switching suspend/resume lifetime bugs.
4. **V8-sandbox-internal corruption** — TPT/EPT/code-pointer-table index/tag
   confusion, freelist manipulation within the tables (barely published).
5. **`Symbol.toPrimitive`-triggered detach** — no V8 CVE keyed to this exact hook;
   audit every builtin that coerces user objects (most general coercion hook).

## Sources
Project Zero 0day RCA 2020-16009 · exploit-db 49745/48183 · crbug 1195777 ·
GH SecLab Maglev incomplete-init · ritsec.club CVE-2023-4068 · thezdi CVE-2024-2887 ·
Black Hat Asia 2025 (citation.thinkst.com/talk/96131) · starlabs.sg bitwise-AND ·
wiz CVE-2025-2135/2026-5865 · nvd CVE-2026-6307/85046 · zeropath (AI, caution) ·
chromium v8/sandbox/README · arxiv 2406.08719 (TikTag) · github.com/googleprojectzero/fuzzilli.
