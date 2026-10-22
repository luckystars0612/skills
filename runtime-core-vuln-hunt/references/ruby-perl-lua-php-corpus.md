# Corpus — Ruby / Perl / Lua / PHP-extras

Part of `runtime-core-vuln-hunt`. Core C of Ruby MRI, Perl, Lua/LuaJIT + PHP
surfaces beyond the main unserialize story. ✅ public RCE/leak PoC · ⚠️ crash/DoS
repro only · 🧪 hypothesis. **`[GADGET]`** = CWE-502 logic (not memory corruption).

## 1. Ruby MRI
- **`Marshal.load`:** all famous "RCE" is **`[GADGET]` logic** (ActiveSupport/
  Gem/ERB method dispatch) — CVE-2026-41316 (ERB guard bypass), 2024 UncaughtThrowError
  chain. **GAP (confirmed):** no public CVE for C-level memory corruption inside
  `marshal.c`. The danger is allocate-then-populate semantics, not a C bug.
- **GC compaction (`GC.compact`, 2.7+):** relocates objects; a C ext holding a raw
  `VALUE` it never marks/updates derefs a moved/stale slot → SEGV. All reproduced
  crashes are **extension-level** (psych/nokogiri/fiddle/pg); **no core CVE**.
  Tool: `GC.verify_compaction_references(expand_heap:true, toward: :empty)`.
- **CVE-2026-54901 (Oj gem) ⚠️** — UAF (CWE-416): `parser_mark` in `ext/oj/parser.c`
  doesn't GC-mark `d->array_class`/`d->hash_class` → GC frees them, next parse
  derefs freed. Fix ≥3.17.3. **The archetype: "C ext forgot to mark a VALUE."**
- **CVE-2018-8778 ✅** `String#unpack` `@` directive signed→OOB read (heap leak).
  CVE-2014-4975 `pack.c encodes()` off-by-one stack overflow ⚠️.
- **Fiddle/FFI** = intentional unsafe FFI (raw memcpy/dlsym) — any attacker-controlled
  call = arbitrary R/W/exec ✅. `ObjectSpace._id2ref` = address-of primitive 🧪.

## 2. Perl core
| CVE | Component | Class |
|---|---|---|
| CVE-2005-3962 | `Perl_sv_vcatpvfn` (sv.c) | int overflow → format-string buffer overflow |
| CVE-2020-10543 / -10878 / -12723 | `regcomp.c` | regex int-overflow → heap overflow / corrupted compiled bytecode / recursion overflow |
| CVE-2026-57432 | `pack.c` | int overflow → OOB heap read |
| CVE-2017-20230 | Storable `retrieve_hook` | signed class-name len → stack overflow |
| CVE-2026-57433 | Storable `SX_HOOK` | signed int overflow → **controlled abort**, NOT corruption 🧪 |
Perl story dominated by the **regex compiler** (2020 trio) + format-string wrap.

## 3. Lua / LuaJIT
**Core risk:** `load`/`loadstring` on untrusted **bytecode** is unsafe by design —
PUC-Lua `luaU_undump` has **no verifier** (removed in 5.1). Crafted `.luac` →
type confusion / OOB / arbitrary memory. Dominant in **game modding / embedded**.
- PUC-Lua ⚠️: CVE-2021-44964 (GC finalizer **UAF** → sandbox escape), -45985
  (finalizer-during-tailcall over-read), -44647 (`ldebug` type-confusion SEGV),
  -43519 (`lua_resume` stack overflow), CVE-2022-28805 (`lparser singlevar`
  over-read), -33099 (`luaG_runerror` heap overflow), CVE-2020-15889 (`lgc` over-read).
- LuaJIT ⚠️: CVE-2020-15890 (`__gc` frame-traversal OOB), CVE-2024-25176
  (`lj_strfmt_wfnum` stack overflow, NVD 9.8), -25178 (OOB read).
- 🧪 **Big gap:** no named CVE for "crafted `.luac` → RCE in `luaU_undump`/`lj_bcread`"
  — folklore with fuzzing evidence, no documented PoC. High-value disclosure target.

## 4. PHP beyond app-unserialize
- **Taoguang Chen `__wakeup` UAF cluster (2015-16) ✅:** #70169→CVE-2015-6831
  (`SplDoublyLinkedList::unserialize` + `__wakeup` UAF, edb-38120); #68976/#70172/
  #70219/#70436 (SPL/session/ArrayObject, same reassign-and-free family) ✅ (verify
  exact CVE mapping per-bug). HITCON 2015 "use-after-flee" writeup.
- **WDDX ⚠️:** CVE-2016-3141 (`wddx_stack_destroy` UAF), CVE-2016-7413 (recordset
  missing close tag UAF), bug #70661.
- **`debug_backtrace` UAF (#76047) ✅:** destructor accessing destructed backtrace
  args; dismissed as "just a crash", overridden; mm0r1 edb-48072 weaponizes a
  destructor→`getTrace()`/`debug_backtrace()` into a **disable_functions bypass →
  RCE** (PHP 7.0-7.4). (Not CVE-2019-11034 — that's the EXIF OOB-read.)
- **EXIF/GD/mbstring/phar ⚠️:** CVE-2019-11034 (`exif_process_IFD_TAG` OOB read,
  9.1), CVE-2015-0232 (EXIF uninit ptr free), CVE-2019-9023 (mbstring/oniguruma
  over-read), GD UAF (#73549), phar corruption (#73768), CVE-2019-9675 (phar tar
  overflow).
- **Core unserialize ✅:** CVE-2014-8142/2015-0231 (dup numeric keys UAF),
  CVE-2017-12932 (hash-API key-delete UAF).
- **OPcache 🧪:** CVE-2015-1351 (UAF, no public PoC), CVE-2015-8994 (SHM cross-EUID
  isolation). `opcache.file_cache` disk-deserialization is under-researched.

## 5. Two dominant root-cause families (all four runtimes)
**(A) Deserialization reentrancy / allocate-before-populate** — deserializer
partially builds an object then invokes a user callback (`__wakeup`/dtor PHP,
`_load`/`marshal_load` Ruby, `__gc`/finalizer Lua, `STORABLE_thaw` Perl) before
internal pointers are consistent → UAF.
**(B) C-ext/VM fails to mark or bound an attacker-influenced VALUE** — GC
reclaims/relocates an object the C side still holds (Oj CVE-2026-54901,
GC.compact family, LuaJIT `__gc`; signed-len-read-as-unsigned is the bounding variant).

**Highest-yield audit targets:** (1) every native `*_mark`/GC callback in a C ext
storing class/proc/custom VALUEs; (2) every deserializer callback that runs user
code mid-reconstruction.

## 6. Open hypotheses (🧪)
1. **Ruby core `marshal.c` memory corruption** — the headline gap. Fuzz `marshal.c`
   under ASAN with `TYPE_DATA`/`TYPE_USRMARSHAL` + user callbacks; `r_object0`
   recursion + id→object table reuse.
2. **Lua/LuaJIT crafted-bytecode → controlled corruption** — a documented `.luac`
   → type-confusion → arbitrary R/W PoC (esp. LuaJIT GC/proto confusion).
3. **Oj-style unmarked-VALUE UAF in other Ruby native parsers** (msgpack/protobuf/
   bootsnap/json-C) + compaction non-compliance.
4. **Perl Storable `SX_HOOK` beyond controlled-abort** (steer negative count past
   `av_extend`).
5. **PHP OPcache `file_cache` corruption** (deserialize compiled-script cache from
   disk — analogous to Lua bytecode).

## Caveats
Verify per-bug CVE mapping for the Chen cluster #68976/#70172/#70436/#70219 on
bugs.php.net; #70169→CVE-2015-6831 verified. Most Lua/PHP-ext entries are crash-grade.

## Sources
Oj CVE-2026-54901 (redhat/osv) · trailofbits "Marshal madness" · ruby-lang ERB
CVE-2026-41316 · bugs.ruby-lang.org GC.compact (#20022/#15809) · CVE-2018-8778
(ruby-lang) · nvd CVE-2005-3962 / 2020-10543 / 2026-57432/57433 · PUC-Lua/LuaJIT
(feedly/opencve) · bugs.php.net #70169/#76047 · edb-38120/48072 · HITCON2015
use-after-flee · nvd CVE-2019-11034 / 2017-12932.
