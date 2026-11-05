# Corpus — CPython core

Part of `runtime-core-vuln-hunt`. CPython C core (`Objects/`, `Modules/`,
`Python/`), not app logic. ✅ confirmed/fixed · ⚠️ claimed-PoC unverified · 🧪 hypothesis.

## 1. github.com/python/cpython#157197 — 100 reports ⚠️ (goldmine of leads)
Opened 2026-09-08, **closed "not planned"** (no maintainer triage). 100 numbered
3.14 memory-safety/concurrency reports, each links a Gist PoC — **all ⚠️
unverified**; treat as *leads*, reproduce under ASAN/TSan first. Dominant framing:
**borrowed-reference / unpinned-storage races** (C borrows a ref or caches an
internal pointer; another thread/callback frees it; C then derefs freed memory).

| Cluster | Items | Surface named |
|---|---|---|
| Borrowed-ref promotion races | 1,6,8,15-17,31,37,51,73,91,99-100 | `PySys_GetObject` (#73), decimal, struct, zstd, syslog |
| Concurrent container mutation | 2,3,7,24,81-83,94 | `dict.update`, `_sre.compile/template`, `_tkinter._flatten` |
| Buffer-protocol/bytearray resize UAF | 5,27,43-46,50,64,74,86 | `memoryview.cast/tobytes`, `PyArg_Parse` **et** (#64) |
| Pickle/unpickle concurrency | 50-60 (marshal 41-42) | `load_build`, `find_class`, `OSError.__reduce__` |
| Non-atomic guard | **59** | shared `Unpickler` `running`-guard race |
| Reentrancy | **93** | decoder callback re-enters `seek()` → outer uses freed input |
| GC/refcount | 31,63,85 | `gc.callbacks`, stale getter-specialization cache, ssl weakref |
| C-API misuse | 14,40,62,64,72,73 | `_curses` double-free, `PyArg_Parse et`, `PySys_GetObject` |

Highest-probability-real: buffer-resize-UAF + reentrancy clusters (match §4
fixed bugs).

## 2. Historical confirmed ✅
| CVE/bug | Module | Class |
|---|---|---|
| CVE-2014-1912 (bpo-20246) | `socket.recvfrom_into` | missing size check → OOB write |
| CVE-2021-3177 (bpo-42938) | `ctypes PyCArg_repr` | stack overflow (`sprintf`), **CVSS 9.8** |
| CVE-2018-20406 | `_pickle` | int overflow on `LONG_BINPUT` resize (multi-GB) |
| CVE-2010-1634 / 2008-3143 | `audioop`,`_struct` | int overflows → overflow/crash |
| CVE-2016-5636 | `zipimport get_data` | int overflow → heap overflow (verify fix commit) |
| bpo-29028 class | `bytearrayobject`/`memoryobject` | resize invalidates exported `Py_buffer` → UAF (mitigation: `BufferError` on resize while export live; **verify exact bpo number**) |

`marshal.loads`/`pickle` on untrusted data: unsafe by design (arbitrary object
construction) — **no standalone C-level memory CVE**; separate from corruption.

## 3. Free-threading (PEP 703 / no-GIL) — new surface
GIL made nearly every C builtin effectively atomic; removing it turns borrowed
refs / cached container-array pointers / length fields into **data races + UAF**.
✅ fixes: gh-117657 (TSan campaign — `dictobject.c`, `setobject.c` `used` atomic,
import lock, GC); **`PyDict_Next` no longer locks** (per-call locking didn't
prevent the hazard — design admission); gh-129069/142957 (`listobject.c` memmove
races). 🧪: no formal Python memory model (PEP 583 withdrawn; PEP 805 draft);
free-threading semantics under-specified = vuln-breeding. Academic **CONCURDEP:
144 dependency-invalidation bugs, 95 unpublished** → the #157197 cluster is real
and large.

## 4. Reentrancy via user hooks (GIL-independent, most reliably real)
C validates/caches → calls user-overridable method that frees/resizes → C
writes/reads stale pointer.
- **gh-142555 ✅ FIXED (the confirmed archetype):** `victim[1]=Evil()` where
  `Evil.__index__` calls `victim.clear()`; bounds check before `__index__`, write
  after → `b_setitem` (`arraymodule.c`) writes stale buffer ptr. **3.13+ SEGV
  under ASAN.** Dup gh-142882 (`array.extend`). Fix PR#142713, backported.
- `list.__index__` re-entry (2016) UAF; `bytearray/dict __eq__` freeing buffer
  mid-op; `__reduce__` during pickling (#50-60 ⚠️); buffer `__release__`; codec
  callbacks (#93); `__del__` resurrection/finalizer re-entry (#31,#85).
- Case study: github.com/yo-yo-yo-jbo/python_uaf.

## 5. Tooling
`./configure --with-pydebug --without-pymalloc CFLAGS="-fsanitize=address -g"` +
`PYTHONMALLOC=malloc` (pymalloc arenas hide OOB/UAF; GH-136790 lets ASAN+pymalloc
coexist but malloc is safest). **TSan** + `Tools/tsan/` for free-threading
(`--disable-gil -fsanitize=thread`). **OverrideFuzz** (arXiv 2605.12563 — grammar
fuzzer for override-hook reentrancy; honest: found no *novel* bugs, it's a
methodology). **CONCURDEP** (arXiv 2609.28608 — the likely engine behind #157197).

## 6. Open hypotheses (🧪)
1. Pickle `memo` race under free-threading (shared Unpickler + 2 threads, #59).
2. Buffer-protocol **et** format resize UAF (`PyArg_Parse`, #64) — `BufferError`
   guard may not cover the `et`/`et#` path.
3. Type-specialization cache staleness (#63) — 3.11+ specializing interpreter
   added cached C state predating no-GIL.
4. `_curses.window.encoding` double-free (#14).
5. Borrowed-return promotion races broadly — **any** C-API returning borrowed refs
   (`PyDict_GetItem`, `PyList_GetItem`, `PySys_GetObject`) under free-threading.
6. GC/weakref callback reentrancy during collection (#31,#85).
7. `_sre` compiled-pattern mutation while matcher holds cached pointers (#81-83).

## Caveats (from the researcher)
- #157197 unverified/closed "not planned" — leads, not findings. Clustering is
  credible (matches confirmed archetypes).
- **gh-142555 (`array.__index__`) is the confirmed, fixed template** — best to
  reproduce the unverified items.
- OverrideFuzz found **no novel** bugs — don't overstate. CONCURDEP corroborates
  the borrowed-ref surface is large.
- Verify before citing: bpo-29028 record, CVE-2016-5636 fix commit.

## Sources
github.com/python/cpython#157197 (+ #157196/#157198) · gh-142555/142713/142882 ·
python-security.readthedocs.io (CVE-2014-1912, CVE-2010-1634) · nvd CVE-2021-3177/
2018-20406 · discuss.python.org PEP 703/779/805 + "Safe Parallel Python" · LWN
free-threading (Nov 2025) · arxiv 2605.12563 (OverrideFuzz) / 2609.28608 (CONCURDEP) ·
github.com/yo-yo-yo-jbo/python_uaf.
