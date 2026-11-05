# Corpus — Node.js core & JS sandboxing runtimes (2015→2026)

Part of `runtime-core-vuln-hunt`. Node.js *core* + vm/vm2/isolated-vm + Deno/Bun
cores. Userland excluded except where it exercises a core primitive.
PoC status: ✅ public PoC/exploit · ⚠️ conceptual/crash-only/withheld · 🧪 hypothesis, no public PoC.

---

## 1. Node.js core memory / uninitialized-memory

### 1.1 `vm` timeout → uninitialized Buffer — CVE-2025-55131 ⚠️  (the key "core" case)
Node's buffer path toggles a **global zero-fill flag** off, allocates, toggles
back on. Under `vm.runInNewContext(code, ctx, {timeout})`, the V8 timeout
watchdog `longjmp`s out *during* the alloc window before the flag is restored →
flag stays **disabled** → later `Buffer.alloc()`/`new Uint8Array()` return raw
heap (prior secrets). TOCTOU/reentrancy on global state interrupted by the
timeout mechanism (CWE-497/908). Fixed 20.20.0/22.22.0/24.13.0/25.3.0 (advisory
2026-01-13). **This is the cleanest generalizable primitive → seeds §5.2.**

### 1.2 `Buffer.allocUnsafe` / pooled uninitialized reads ✅
`allocUnsafe` returns raw heap by design. **CVE-2018-7166**: arg-handling bug made
`Buffer.alloc(size,fill,enc)` skip the fill → raw memory (Node 10<10.9.0). The
whole `new Buffer(n)`→`allocUnsafe` API split exists because `new Buffer(number)`
returned uninitialized memory. Userland pivot: **CVE-2025-61917 (n8n)** exposed
`allocUnsafe` to untrusted code → memory read.

### 1.3 `worker_threads`/MessagePort duplicate transfer → segfault ✅ / 🧪(corruption)
`postMessage(value, transferList)` doesn't dedupe; same `MessagePort` twice →
**segfault**, same `ArrayBuffer` twice → fatal. Transfer detaches on first pass,
operates on detached/freed handle on second (double-detach → UAF-shaped).
nodejs/node#25786. `markAsUntransferable()` partially mitigates.

### 1.4 `v8.serialize`/`v8.deserialize` host-object hooks 🧪
`Deserializer._readHostObject()` is JS-overridable; wire format carries
attacker tags/lengths; `_setTreatArrayBufferViewsAsHostObjects`. Explicitly
**unsafe on untrusted input**. No CVE — strong under-explored surface (§5.1).

### 1.5 HTTP/2 (nghttp2) / HTTP/1 (llhttp)
- **CVE-2026-56848** nghttp2 heap **UAF** ⚠️ — `nghttp2_session_mem_send()` called
  re-entrantly during `..._mem_recv()`. 22/24/26.x.
- nghttp2 CONTINUATION-frame race (Apr 2024) ⚠️; **CVE-2023-35945** nghttp2 memory
  *leak* ✅ (CWE-400); **CVE-2024-27983** HTTP/2 crash + llhttp 9.2.1 bump ⚠️.
- No pure memory-corruption **llhttp** CVE in window — the risk is in nghttp2.

### 1.6 TLS/crypto — CVE-2025-59464 ✅
OpenSSL X.509 UTF-8 conversion in `getPeerCertificate(true)` fails to free →
remote leak via repeated connections (Node 24.x<24.12.0, CWE-401).

---

## 2. N-API / native-addon boundary (C↔JS)

**Foundational:** *Bilingual Problems* (arXiv 2111.11169, USENIX Sec 2023). Fuzzing
APIs of **33 npm native packages** → uninitialized reads, crashes, leaks; 6 web
apps a weak remote adversary could exploit; **7 advisories** filed. Classes
(Snyk): memory leak, **unchecked type** (JS value of unexpected type → native
treats as wrong C type → **type confusion**), reachable assertion. Structural
root: JS dynamic typing + native static-C assumption + unchecked
`napi_get_value_*` returns. **Lifetime/UAF:** addon caches a raw pointer into a
JS-owned Buffer/ArrayBuffer after GC/transfer-detach → UAF across the boundary
(`napi_ref`/finalizer mis-sequencing). Deno re-implements the N-API ABI →
inherits the hazards. ✅ (33 pkgs) / 🧪 (core UAF-via-detach).

---

## 3. JS sandbox escapes to host

**Class A** = memory-corruption escape (host R/W/CFI primitive). **Class B** =
prototype-pollution/gadget (pure-JS reachability of host `require`/constructors).

### 3.1 isolated-vm `ExternalCopy` TOCTOU type confusion ⚠️ — CLASS A (strongest in corpus)
`ExternalCopy` iterates `transferList` **twice**; second pass trusts first.
Elements can be **getters returning different values each call** → type confusion
→ deref attacker-controlled pointers. Guest reaches host-only `ExternalCopy` via a
shared `ivm.Reference`. Endor Labs: controlled-crash → **CFI hijack** → guest→host
escape. ≤7.0.0; fixed 6.2.0/7.0.1 (GHSA-864f-rcv7-6rh4, Aug 2026). >1M wk dl
(n8n, Activepieces, Mastra AI). *"We didn't break V8 — we broke the code that
carries data into it."*

### 3.2 vm2 — the CVE graveyard (deprecated) — mostly CLASS B ✅
CVE-2021-23449 (proto pollution), CVE-2022-25893 (WeakMap proto lookup),
CVE-2022-36067 "Sandbreak", CVE-2023-29017 (Promise handler), 2023-30547/32313/
32314 (exception/Proxy), 2023-29199/37466/37903 (exception transformer / host-obj
leak → maintainer **abandoned vm2**), CVE-2026-22709 (then/catch bypass; +patch-
bypass of 37903). **Every escape is a gadget reaching an un-wrapped host object —
not memory corruption.** Lesson: a pure-JS wrapper sandbox cannot durably contain V8.

### 3.3 `vm` core module — "not a security boundary" — CLASS B
Baseline: `this.constructor.constructor("return process")()` → host. Node docs:
*"not a security mechanism."* **CVE-2026-25533** ⚠️ — core defect: `vm` leaks host
references into the sandbox on infinite recursion (error objects during
stack-unwinding carry host prototypes) → escapable even with a hardened wrapper.

---

## 4. Deno / Bun cores

- **Deno CVE-2024-27934** ⚠️ — FFI `*const c_void`/`ExternalPointer` **UAF** (CWE-416),
  bypasses the permission sandbox regardless of grants. 1.36.2≤v<1.40.3, CVSS 8.4.
  Rust+V8 base makes core memory bugs rarer; FFI/`unsafe` + re-implemented N-API
  ABI are the hazards.
- **Bun** 🧪 — no confirmed core memory CVE; embeds **JavaScriptCore** (JSC bugs are
  upstream, e.g. the JSC UAF class) + large Zig/C surface (`bun:ffi`, bundler) is
  under-fuzzed publicly.

---

## 5. Open hypotheses (🧪 no public PoC)

1. **`v8.deserialize` host-object callback confusion** — crafted buffer drives
   `_readHostObject` to build a typed-array view with length/offset inconsistent
   with its ArrayBuffer → OOB host R/W. Any service deserializing cached/queued data.
2. **Generalize CVE-2025-55131** — other async interruptions of the alloc window
   (worker message mid-alloc, GC finalizer, nested `vm` timeout) wedge the same
   zero-fill flag → uninitialized reads **outside** the patched vm-timeout path.
3. **MessagePort double-detach → steerable UAF** — interleave duplicate transfer
   with GC pressure + realloc of the freed BackingStore → controlled UAF write.
4. **Bun `bun:ffi`/bundler native surface** — integer-width/length-trust in FFI
   marshalling or binary-asset parsing → host primitive.
5. **N-API detach-after-share UAF** — addon caches a pointer into a Buffer's
   BackingStore, Buffer later transfer-neutered → deref freed memory, no lifetime check.

## Sources
Node: nodejs.org/en/blog/vulnerability/december-2025-security-releases ·
endorlabs.com/learn/eight-for-one… · CVE-2025-55131 (sentinelone/indusface/opencve) ·
CVE-2018-7166 (nvd) · CVE-2025-61917 (wiz) · nodejs/node#25786 · CVE-2026-56848 ·
CVE-2023-35945 · CVE-2025-59464 (wiz/ubuntu) · april-2024-security-releases.
N-API: arxiv.org/abs/2111.11169 · snyk.io/blog/nodejs-add-on-extensions.
Sandbox: GHSA-864f-rcv7-6rh4 (endorlabs/securityweek/thehackernews) · vm2
(corgea/kodemsecurity/XmiliaH) · CVE-2026-25533 · Deno CVE-2024-27934 (nvd/GHSA-3j27-563v-28wf).
