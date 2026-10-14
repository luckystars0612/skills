# Review lenses: recognizing bug classes during code review

Each lens is a *detection* aid: what the class is, where it appears, the code smells and grep
patterns that surface candidates, the questions to ask, and how to tell a real issue from
intended behavior. The goal is to find and characterize a bug well enough to report it — not to
weaponize it (see SKILL.md §0 proof standard). Apply every lens whose "where" matches the unit.

Debug-only assertions are not security checks. Chromium `DCHECK`, Gecko `MOZ_ASSERT`, WebKit
`ASSERT` compile out of release builds; a property guarded only by one of those is unguarded in
production. When a safety property matters, grep for a release-mode check too (`CHECK`,
`MOZ_RELEASE_ASSERT`, `RELEASE_ASSERT`, `MESSAGE_CHECK`, `mojo::ReportBadMessage`).

Grep tips:
- Chromium C++: `rg -n --type cpp '<pat>' content/ chrome/ components/`; mojom: `rg -n 'interface' -g '*.mojom'`.
- Gecko: `rg -n '<pat>' dom/ ipc/ netwerk/ toolkit/actors browser/actors`.
- WebKit: `rg -n '<pat>' Source/WebKit Source/WebCore`.
- Closed-source vendor code: ask the same questions of the functions binary-diff flagged as
  vendor-only (recon §2.5).

---

## L1. Trusting identity supplied by the less-privileged side

**What.** A privileged handler uses an origin, URL, frame/tab ID, profile ID, path, size, type or
handle that the untrusted side *sent*, instead of deriving it from its own trusted state.

**Where.** Vendor Mojo/IPDL/WebKit IPC methods; Gecko JSActor parent handlers; Electron `ipcMain`
handlers; extension `onMessageExternal`; native messaging hosts; Android/iOS JS bridges.

**Smells / grep.** Handler parameters named `origin`/`url`/`frame_id`/`profile`/`path`/`handle`;
no call to `GetLastCommittedOrigin()` / `CanAccessDataForOrigin` / `CanCommitURL`; no
`ReportBadMessage`/`IPC_FAIL`/`MESSAGE_CHECK` on bad input; Electron `ipcMain.handle(` with no
`event.senderFrame` check; a preload exposing a generic `send(channel, …)`; `@JavascriptInterface`
methods reachable from any loaded origin.

**Questions.** Which parameters are identities or capabilities? Where does the handler obtain the
*trusted* version of each? If the sender lies, what goes wrong? Does bad input terminate the sender
or just get logged?

**Tell real from intended.** Real: the action affects data/origin the caller should not control.
Intended: the API is documented to act on caller-supplied values and the caller already had that
authority.

---

## L2. Object lifetime (use-after-free, dangling references)

**What.** Something is used after it is freed: raw pointers held across async boundaries, observers
not removed, frame-bound objects outliving their frame, iterators invalidated by mutation, objects
freed during re-entrant calls.

**Where.** Browser/parent-process objects tied to a frame/tab/profile; DOM code that can run script
mid-operation (event handlers, getters, mutation observers, modal dialogs, nested event loops);
collection iteration that calls out.

**Smells / grep.** Chromium `base::Unretained(this)` in stored/posted callbacks; member `T*`/`T&`
(not `raw_ptr<T>`) to externally-owned objects; `RenderFrameHost*` stored off a Mojo receiver;
observers added without `ScopedObservation`. Gecko `MOZ_CAN_RUN_SCRIPT` paths missing a
`RefPtr` guard. WebKit raw `this` in completion handlers instead of `Ref`/`WeakPtr`.

**Questions.** What can run in the middle of this function — script, event dispatch, a nested loop,
IPC, GC? Can that free, resize or reorder what is in use? Is every owner's lifetime longer on
*every* path, including teardown and navigation?

**Tell real from intended.** Real: a sanitizer (ASan/UAF) or debugger shows a read/write of freed
memory on a minimal, default-config testcase. Note whether the dangling pointer is a `raw_ptr`
(Chromium MiraclePtr may neutralize the browser-process case) — that changes severity and whether
it reproduces.

---

## L3. "Assumed stable" state that an actor can change

**What.** Code relies on something it believes nobody can change in a window — a value treated as
immutable, a buffer assumed exclusively owned after transfer/detach, a process assumed suspended, a
mapping assumed stable, a prototype assumed frozen — but some actor can change it.

**Where.** Engine optimizer/deopt invariants; consumers *outside* the JS engine of transferred or
detached buffers (WebCodecs, WebAudio, WebGPU, Streams, image/video/crypto); any check-then-use of
data in shared memory; cross-process readers (crash handlers, debuggers).

**Smells.** Comments like "immutable", "we own this", "cannot change", "suspended", "frozen";
zero-copy wrapping of a JS-visible backing store; reading another process's memory twice and
assuming consistency.

**Questions.** Enumerate every assumption of the form "X cannot change between A and B." For each,
who *can* change X — another thread, the renderer, an in-sandbox write the engine threat model
already grants the attacker, another process, the OS? Which consumers outside the engine forgot
that the engine does not promise semantic immutability to an in-sandbox attacker?

**Tell real from intended.** Real: you can show the "stable" thing differs between check and use
and the code then acts on stale metadata (OOB, type confusion). This is a recognition exercise;
reporting the root cause and a trigger is sufficient — do not build the escape.

---

## L4. Validation gaps on a second path

**What.** The main code path validates correctly, but a second path reaches the same operation
without the check: a fast path/optimization, a cache, a legacy fallback, a reference obtained a
different way, a different IPC entry point for the same action.

**Where.** Engine fast paths for common call shapes; dual APIs that reach one backend; IPC methods
that duplicate a guarded operation; migration/fallback code kept for compatibility.

**Smells.** A function with "fast"/"opt"/"cached"/"legacy"/"fallback" in its name near a security
check; two callers of a backend where only one validates; a check in `call_indirect`/the audited
entry but not in an alternative entry (`ref.func`/`call_ref`, a cached handle, a reused object).

**Questions.** How many ways can control reach this operation? Does each enforce the same checks?
Is there an "unchecked" sibling of a checked function?

**Tell real from intended.** Real: the unchecked path produces an observable violation (type
confusion, wrong-origin action, skipped integrity check). Confirm it is not a path the vendor
documents as privileged.

---

## L5. Integers, sizes, sentinels, truncation

**What.** Narrow fields, sentinel values, or truncations where the attacker controls counts/sizes:
32→16 bit fields, signed/unsigned wrap, a sentinel that a legitimate value can collide with, a
length taken from untrusted input without an upper bound tied to the real allocation.

**Where.** Vendor binary parsers (sync payloads, filter lists, notes, media, fonts, images);
layout code with bitfields; any `memcpy`/`memmove`/index with an untrusted length.

**Smells / grep.** `(uint16_t)`/`(int16_t)` casts of counters; `memset(…, -1, …)` used as a
sentinel; `memcpy(dst, src, len)` where `len` is untrusted and `dst` is fixed-size; size compared
to one bound but used against another; `+`/`*` on sizes without overflow checks.

**Questions.** What is the maximum attacker-controlled value of each count/size? Does it fit the
field and the destination? Can a legitimate value equal the sentinel? Is the bound that is checked
the bound that is used?

**Tell real from intended.** Real: a sanitizer OOB on a crafted input, with the arithmetic
explained. Many are low severity (a few bytes OOB); state impact conservatively.

---

## L6. Concurrency and races

**What.** State shared between threads/sequences/processes without correct synchronization, or a
check-to-use window an attacker can stretch by flooding an endpoint.

**Where.** Browser-process objects touched from multiple sequences; shared-memory parsing; refcount
updates reachable from IPC; anything with "this runs on the IO thread / UI thread" comments.

**Smells.** Missing `SEQUENCE_CHECKER`/sequence affinity; refcount inc/dec across processes;
TOCTOU on a value read from shared memory; comments asserting single-threaded access on a
reachable-from-IPC object.

**Questions.** Who else touches this state, on which thread/process? Is there a check-then-act on
shared memory? Can the attacker widen the window (many concurrent requests)?

**Tell real from intended.** Real: a reliable-enough reproduction (even if probabilistic) showing
the invariant broken, under a sanitizer or with instrumented logging.

---

## L7. Privileged UI rendering untrusted data

**What.** A WebUI / `about:` page, an extension page, or a native UI inserts web-controlled text
(tab titles, URLs, filenames, page text, notes, sync data) into DOM via `innerHTML`-style APIs, or
exposes a privileged action to a frame that web content can influence.

**Where.** `chrome://` / `about:` pages, component-extension pages, Electron renderer windows with
privileges, NTP/sidebar/AI panels.

**Smells / grep.** `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`/
`new Function` in privileged page JS; `postMessage` listeners without an `event.origin` check;
CSP/Trusted Types weakened versus upstream; `chrome.send`/WebUI handlers performing privileged
actions with page-supplied arguments.

**Questions.** Can web content navigate to, frame, or `window.open` this page? What web-controlled
strings reach the DOM, and through which sink? Is `event.origin` validated on message handlers?

**Tell real from intended.** Real: script executes in the privileged context, or a privileged
action fires for an origin that should not trigger it. Self-XSS and pages reachable only by pasting
code into DevTools are typically out of scope — check the program (triage-and-report §3).

---

## L8. Isolation and policy boundaries of vendor features

**What.** A vendor feature claims to isolate or restrict something — separate profiles/modes/
containers, parental controls, a password/autofill origin check, an account-SSO trust boundary,
E2EE sync — and the boundary can be crossed.

**Where.** Multi-profile/mode features, container/tab-group isolation, password manager/autofill,
account sign-in integration, sync, child/safe modes.

**Questions.** Does state (cookies, storage, cache, permissions, credentials, history, service
workers) created in container X become readable or usable in Y? Does autofill honor origin, frame,
and scheme (`about:blank`, `data:`, `blob:`, sandboxed iframes, PSL)? Which origins can trigger or
observe account SSO or obtain a token? Is the E2EE key ever derivable server-side; is sync metadata
and payload authenticated and safely parsed? Can restricted/safe mode content load anyway?

**Tell real from intended.** Real: your own test data crosses the boundary the feature advertises.
Check the vendor's own documentation for what the feature actually promises before calling a leak a
bug. Pure fingerprinting without a broken stated guarantee is usually out of scope.

---

## L9. Platform: installer, updater, services, protocol handlers

**What.** A privileged local component (SYSTEM/root updater or service, elevation COM server,
scheduled task) can be made to load/run data a standard user controls; or a protocol handler /
native messaging host / deep link passes attacker input to a dangerous operation.

**Where.** Install/update directories and their ACLs; services and their binary paths; COM
elevation interfaces; `shell\open\command`; native messaging host manifests; macOS privileged
helpers; Android exported components; Electron `setAsDefaultProtocolClient` argv handling.

**Smells.** User-writable directory read/executed by a SYSTEM component; symlink/junction follow in
temp/update paths; unsigned or rollback-allowed update payloads; PID-based (not audit-token) XPC
validation; protocol command strings with unquoted/injectable arguments.

**Questions.** What runs as SYSTEM/root, and from where does it read code/data/config? Can a
standard user write any of those paths or win a symlink race? Is every update payload
signature- and version-checked? Which arguments of a protocol/deep-link handler are
attacker-controlled, and where do they flow?

**Tell real from intended.** Real: a lower-privileged actor causes privileged execution or file
write across the user↔SYSTEM boundary. "Runs as SYSTEM" alone is usually intended and excluded;
the crossing is the bug. Attacks needing admin or physical access are typically out of scope.

---

## L10. Security-default regressions vs upstream

**What.** The fork ships with an upstream protection disabled or weakened by default.

**Where.** Launch switches in shortcuts; `chrome://flags`/`about:config` defaults; site-isolation
mode; sandbox status; CSP/Trusted Types on WebUI; certificate/HSTS handling; Safe Browsing /
download protection; Electron `webPreferences`/fuses.

**Questions.** Diff each security-relevant default against upstream at the same version. For each
weakened default, what concrete attack does it re-enable?

**Tell real from intended.** Real and reportable only with a concrete security consequence stated,
not "flag X differs." Some differences are deliberate product choices; frame the user-facing risk.
