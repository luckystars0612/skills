# Case studies: real browser bugs as recognition patterns

Each entry is a *recognition* aid, not an exploitation guide: the component, the root-cause class,
and the review question that would have surfaced it. All are public (vendor advisories, bug
trackers, conference talks, research blogs, 2018–2026). Use them to sharpen the lenses in
`review-lenses.md`; cross-referenced as `CS-xx`. Root causes are described at the level needed to
*find and report* the class, deliberately not at the level needed to weaponize it.

Severity/impact labels are as the vendors assigned them.

---

## JS engine / compiler invariant bugs (lens L3, L4)

**CS-01 — V8 Maglev deopt, mutable value treated as an immutable constant (Chromium, 2026).**
The mid-tier compiler's deoptimization path let a mutable heap number be reused as if it were an
immutable literal, so distinct objects could share one mutable value and break a bounds-check
assumption. *Review question (L3/L4):* where does the optimizer assume a value is immutable, and
can a mutable one reach that path? *Signal:* comments/invariants saying "only immutable X here."

**CS-02 — Firefox WebAssembly `call.bind` fast-path type confusion (CVE-2026-2796).**
A fast path unwrapped a `Function.prototype.call.bind(...)` import and stored the inner Wasm
function without re-checking its type signature; the main call path compensated, but a *second*
path (`ref.func`/`call_ref`) did not, giving a type confusion. *Review question (L4):* does every
path that can obtain this reference enforce the type check the main path does? *Signal:* an
optimization that is "correct for the calling path" with another way to get the same object.

**CS-03 — Turboshaft/Wasm bounds-check elimination after tier-up (CVE-2026-5873 class).**
An optimizer removed a bounds check that only held under a truncation assumption, so a large index
that the baseline tier trapped on was accepted after tier-up. *Review question (L4/L5):* which
checks does tier-up remove, and does the assumption that justified removal actually hold for all
inputs?

**CS-04 — WasmGC `struct.get`/`struct.set` as a typed field access (Firefox, 2026).**
Once a type confusion exists, WasmGC struct field access is a fixed-offset load/store — a reminder
that *any* confusion between a reference and a scalar in an engine is high impact. *Review
question:* can two modules share a deduplicated signature while one side's type differs?

---

## V8-sandbox / engine-sandbox consumers (lens L3)

**CS-05 — Blink/WebCodecs trusting a detached `ArrayBuffer` (animated-WebP TOCTOU, Chromium 2026).**
Blink treated a transferred image buffer as exclusively owned and cached its geometry, while an
in-sandbox attacker could still modify the bytes through a view it had unlinked, so cached
geometry no longer matched the current bytes. *Review question (L3):* which code outside the JS
engine relies on a transferred/detached buffer being immutable, when the engine's own threat model
does not promise that against an in-sandbox attacker? *Signal:* zero-copy wrapping of a JS-visible
backing store in a decoder/consumer.

**CS-06 — Reinterpreting a value across a trust boundary (type/tag confusion, multiple engines).**
A raw double crossing an IPC boundary masqueraded as a tagged object pointer (Firefox parent
process). *Review question (L1/L3):* does deserialization re-validate the type/tag, or trust the
sender's framing?

---

## Browser/parent-process UAF and lifetime (lens L2)

**CS-11 — Chrome CSS `CSSFontFeatureValuesMap` iterator invalidation (CVE-2026-2441, in the wild).**
Iterator invalidated by mutation during iteration → UAF reachable from a crafted page, code
execution in the sandboxed renderer. *Review question (L2):* can script mutate this collection
during iteration?

**CS-19 — Frame-bound Mojo object outliving its `RenderFrameHost`.** A browser-process object held
a `RenderFrameHost*` past the frame's lifetime because it was tied to a Mojo pipe instead of the
document. *Review question (L1/L2):* is this service `DocumentService`/`DocumentUserData`-based, or
does it store a raw frame pointer? *Signal:* `RenderFrameHost*` as a member of a Mojo impl.

**CS-21 — Chrome Payments component browser-process UAF (GHSL-2020-165 / issue 1125614).** UAF in a
browser-process component reachable from a compromised renderer. *Review question (L2):* across
this async component, what frees the object while a pointer is retained?

**CS-23 — Firefox `<object>` attribute setter UAF via nested event loops.** Setter re-entered actor
teardown and freed a callback still unwinding. *Review question (L2):* what nested event loop can
this setter spin, and what does it free?

**CS-24 — Firefox color-picker nested event loop UAF.** A synchronous input event spun a nested
loop that re-entered teardown. *Signal:* any UI that spins a nested loop (pickers, modals, print).

**CS-26 — Firefox XSLT `key()` reentrancy rehash (20-year-old).** Reentrant `key()` calls forced a
hash-table rehash that freed the backing store while a raw entry pointer was live. *Review
question (L2):* can a callback re-enter and resize this table mid-use? *Lesson:* old, rarely-fuzzed
features (XSLT) hide long-lived bugs.

**CS-28 — Firefox IndexedDB refcount race over IPC → parent UAF / sandbox-escape primitive.**
A compromised content process manipulated parent-side refcounts via a race. *Review question
(L6):* are these refcounts updated safely under concurrent IPC?

**CS-29 — Firefox WebTransport certificate-hash race.** Flooding a refcount-heavy copy loop
widened a race window. *Signal:* "flood to widen the window" is a recurring motif (L6).

**CS-30 — Firefox animation-timeline UAF class (in the wild, 2025–2026).** Animation/timeline
objects freed while referenced. *Review question (L2):* lifetime of animation objects across
document teardown.

---

## Renderer→browser / sandbox-boundary logic (lens L1)

**CS-14 / CS-15 — Chrome Windows handle-validation sandbox escapes (2025, high-reward / in-the-wild
class).** The browser process mis-validated handles or identity claims from a renderer, letting a
compromised renderer obtain a privileged handle. *Review question (L1):* does this broker validate
the caller's identity from trusted state, or believe what the renderer claims? *Signal:* handle
duplication/brokering paths.

**CS-16 — "Renderer claims to be the broker" ($250k-class Chrome sandbox escape).** An IPC message
let a renderer assert a privileged role the browser then trusted. *Review question (L1):* is the
sender's role derived from the connection/process, or taken from the message?

**CS-20 — Chrome `DragService.startDragging()` arbitrary file path (CVE-2024-11114 class).** A
renderer supplied a file path to a browser-side drag operation reaching outside the sandbox.
*Review question (L1):* is this path validated against what the renderer is allowed to access?

**CS-25 — Firefox parent-process image decode of content-supplied data.** A compromised content
process sent an arbitrary image to be decoded in the parent, pairing with a decoder bug for a
sandbox escape. *Review question (L1):* why is untrusted data decoded in the privileged process at
all (Rule-of-2)?

**CS-17 — Chrome GPU-process escape reachable from the renderer (CVE-2025-6558 class).** Improper
validation in GPU/ANGLE reachable from web content. *Review question:* what does the GPU process
trust from the renderer?

---

## WebUI / privileged UI and extensions (lens L7, L1)

**CS-31 — WebUI handler performing a privileged action with page-supplied arguments.** A
`chrome.send`/Mojo WebUI handler acted on arguments without validation. *Review question (L7):*
can web content reach this page, and are handler arguments validated?

**CS-32 — Component extension `onMessageExternal` without sender validation.** A broadly-scoped
`externally_connectable` plus an unchecked `sender.origin` let a matching (possibly XSS'd) site
reach privileged extension APIs. *Review question (L1/L7):* which origins can message this
extension, and what does it do with their messages?

**CS-33 — Adblocker/filter-list injection.** Filter rules (cosmetic/scriptlet/redirect) built from
a fetched list that is not integrity-checked can inject into every page. *Review question (L8):*
where do lists come from, are they authenticated, and can a rule inject script/CSS?

---

## Electron / CEF (lens L1, L9; engines.md §5)

**CS-35 — Electron `ipcMain` handler without `senderFrame` validation.** Any frame (including a
loaded web origin) could invoke a privileged main-process action. *Review question (L1):* does the
handler check `event.senderFrame` origin/URL?

**CS-36 — Electron protocol-handler argument injection (CVE-2018-1000006 class).** A registered
URL-scheme client passed attacker-controlled command-line arguments to the app. *Review question
(L9):* how are deep-link/protocol arguments parsed and quoted?

**CS-37 — Electron n-day via bundled-Chromium patch gap (Hacktron, 2026).** A desktop app shipped a
Chromium far behind upstream; a known, patched engine bug was still exploitable there, and the main
window ran without a sandbox. *Lesson:* track each Electron app's Chromium/Electron version against
upstream; the gap is the finding's context. *Note:* this is exactly the patch-gap class that most
programs exclude without a working exploit — treat as information (triage §3).

---

## Platform / updater / integrity (lens L9)

**CS-41 — Crashpad reading a "suspended" renderer that wasn't fully frozen (Chromium 2026).** The
unsandboxed crash handler assumed a target process could not change its memory while suspended; a
thread created to bypass the freeze changed page protections between a read and its retry. *Review
question (L3/L9):* what does a cross-process reader assume is stable about the target, and can the
target violate it?

**CS-42 — Secure Preferences legacy-MAC fallback (SUPERSTOMP technique, 2026).** A profile-integrity
scheme still accepted legacy HMACs after newer encrypted hashes were introduced, so a local actor
could forge the integrity state and install an extension. *Review question (L9):* does a newer
integrity check still fall back to a weaker legacy one?

**CS-43 — Updater/service loading from a user-writable path.** Classic SYSTEM-component DLL/binary
load or symlink-follow in a user-writable directory. *Review question (L9):* what does the
privileged updater read/execute, and can a standard user write it?

---

## Older full-chain references (for how boundaries stack, not for reuse)

**CS-51 — iOS WebKit→kernel chains (Coruna: 23 exploits / 5 chains; DarkSword: 6-vuln chain).**
Illustrate how a real mobile chain crosses WebContent → GPU/other process → dynamic linker →
kernel, each boundary a separate bug. *Use:* understand which boundary a WebKit finding sits on and
what would (not that you will) come next.

**CS-52 — Classic Chrome full chain (HackTricks reference: V8 RW → V8-sandbox escape via object
corruption → renderer→OS escape via an IPC logic bug).** A canonical three-stage shape:
engine memory bug, engine-sandbox escape, OS-sandbox escape. *Use:* to classify which stage a
finding belongs to during triage.

---

## Cross-cutting lessons (what the 2026 AI-assisted efforts concluded)

1. **Invariant-violation bugs are a sweet spot** — "something assumed immutable/exclusive/frozen
   can change" (CS-01, CS-05, CS-41). Ask the L3 question of every unit.
2. **Collisions are the top risk when many people point tools at the same popular code.** Spend
   effort on your own understanding of the target; dedupe early (harness §4).
3. **Good examples make agents far more effective** — feed them the surface map, extracted vendor
   code, and these case studies.
4. **Defense-in-depth that imposes hard barriers held** (frozen prototypes, removing a handle from a
   reachable table, MiraclePtr/`raw_ptr`); mitigations that only impose *friction* weaken against
   tireless automated search. When a fork disables a hard barrier (L10), that itself is a lead.
5. **Finding is cheaper than exploiting**, and a reported bug does not need an exploit. This skill
   stops at finding + root cause by design.
