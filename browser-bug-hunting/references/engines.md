# Engine architectures and trust boundaries

Use this file to (1) identify which engine a target is built on, (2) know which processes and IPC
systems exist, (3) know which boundary each component sits on, and (4) know how the vendor's
program expects boundary-crossing bugs to be demonstrated.

Always verify details against the exact version you are testing; architectures move fast.

---

## 1. Identifying the engine

| Signal | Chromium/Blink | Gecko | WebKit | Electron | CEF |
|---|---|---|---|---|---|
| Internal pages | `chrome://version` (forks often keep it, sometimes renamed: `edge://`, `brave://`, `vivaldi://`, `opera://`) | `about:support`, `about:buildconfig` | Safari: none public; WebKitGTK: `webkit://gpu` | DevTools → `process.versions` (if exposed), or strings in binary | `chrome://version` inside the app |
| Files | `resources.pak`, `chrome_100_percent.pak`, `v8_context_snapshot.bin`, `icudtl.dat` | `omni.ja`, `browser/omni.ja`, `libxul`/`xul.dll` | `WebKit.framework`, `JavaScriptCore.framework`, `libwebkit2gtk` | `resources/app.asar`, `electron.exe` or app-named binary, `resources.pak` | `libcef.dll`/`Chromium Embedded Framework.framework` |
| UA string | `Chrome/<ver>` | `Gecko/20100101 Firefox/<ver>` | `AppleWebKit/605.1.15 ... Version/<ver>` | `Chrome/<ver> Electron/<ver>` | `Chrome/<ver>` |

Record engine + exact upstream version in `work/version.md`. For Electron also record the Electron
version (it maps to a Chromium and Node version). For mobile apps, note whether the app ships its
own engine (Chromium-based Android browsers) or uses the system WebView/WKWebView.

---

## 2. Chromium (Chrome, Edge, Brave, Opera, Vivaldi, Arc-like browsers, Ulaa, Yandex, Samsung Internet, many others)

### 2.1 Process model
- **Browser process**: unsandboxed, owns profiles, files, network decisions, permissions, UI.
  The highest-value target.
- **Renderer processes**: run Blink + V8 for web content, sandboxed. With Site Isolation
  (site-per-process on desktop; partial on Android) each site gets its own process and the browser
  enforces a *process lock*: a renderer locked to site A must never get data for site B.
- **GPU process**: graphics, WebGL/WebGPU (ANGLE, Dawn, SwiftShader), video decode on some
  platforms. Sandboxed but less strictly than renderers on some platforms; renderer→GPU is an
  important escape path (e.g. CVE-2025-6558 class, see case studies).
- **Network service**: in its own process on most desktop platforms; parses HTTP, cookies, DNS.
- **Utility processes**: audio, storage, data decoder (JSON/XML/image decoding in a sandbox),
  printing, etc.
- **Crashpad handler**: separate, unsandboxed, reads crashing processes' memory (see XBOW stage 3
  in case studies).
- **Extension processes**: renderer processes hosting extension pages/service workers.

### 2.2 IPC: Mojo (ipcz underneath on current versions)
- Interfaces are defined in `.mojom` files. Generated bindings deserialize and type-check messages,
  but **semantic validation is the implementer's job**.
- Interfaces are bound through `BrowserInterfaceBroker` per frame/worker (see
  `content/browser/browser_interface_binders.cc`) or per process. **Frame-bound** implementations
  must not outlive their `RenderFrameHost`; historic bugs come from raw `RenderFrameHost*` kept in
  an object whose lifetime is tied to a Mojo pipe (use `DocumentService` /
  `DocumentUserData` to get this right).
- Trusted identity must come from browser-side state: `RenderFrameHost::GetLastCommittedOrigin()`,
  `ChildProcessSecurityPolicy::CanAccessDataForOrigin()`, `CanCommitURL()`, process lock checks.
  A handler that trusts an origin/URL/frame ID/profile/path sent by the renderer is a bug class.
- Invalid input should end in `mojo::ReportBadMessage()` / `bad_message::ReceivedBadMessage()`,
  which kills the renderer. A handler that logs and continues is suspicious.
- Windows-specific: handle passing across processes (DuplicateHandle, broker processes). Two
  2025 in-the-wild/high-reward sandbox escapes were handle-validation logic bugs (case studies).

### 2.3 V8 and its sandbox
- Tiers: Ignition (interpreter) → Sparkplug (baseline) → Maglev (mid-tier optimizer) → Turbofan
  (top tier, Turboshaft backend). Wasm: Liftoff (baseline) → Turboshaft/Turbofan.
- **V8 sandbox**: a large reserved region; the JS heap and most objects use compressed pointers
  inside a 4 GiB pointer-compression cage within it. Pointers to things outside (external objects,
  code, trusted objects) go through tables: External Pointer Table, Trusted Pointer Table (TPT),
  Code Pointer Table / Wasm Code Pointer Table (WCPT), JS dispatch table. Trusted objects live in
  "trusted space" outside the sandbox.
- Threat model: an attacker with arbitrary read/write **inside** the sandbox (assumed after any
  V8 bug) must not corrupt memory **outside** it. Any path from in-sandbox corruption to
  out-of-sandbox corruption is a "V8 sandbox bypass" and is its own bug class in Chrome VRP.
- Important consequence (see XBOW stage 2): V8 does *not* guarantee that in-sandbox objects keep
  their JS semantics against such an attacker (a detached `ArrayBuffer` can still be written by a
  view the attacker unlinked). Code outside V8 (Blink, codecs, WebCodecs) that relies on those
  semantics is vulnerable. This is a rich, under-explored area.
- Fuzzing/CTF infrastructure: `d8` shell with `--sandbox-testing` / sandbox fuzzing support,
  Chrome's v8CTF (exploit submissions against the latest V8 version).

### 2.4 Memory-safety hardening
- **PartitionAlloc** is the main allocator; **MiraclePtr/BackupRefPtr** (`raw_ptr<T>`) quarantines
  freed objects still referenced by `raw_ptr`, neutralizing many browser-process UAFs. Chrome VRP
  gives a separate bonus for bypassing MiraclePtr; when reviewing, note whether the dangling pointer
  is a `raw_ptr` (protected) or a raw `T*`/reference/`base::Unretained` in a callback (not).
- **Rule of 2** (`docs/security/rule-of-2.md`): never combine untrusted input + unsafe language +
  unsandboxed process. Vendor code that parses untrusted data in C++ in the browser process breaks
  this rule — a strong signal to review.
- CFG/CET on Windows, ASLR (note: on Windows, image bases are randomized per boot, so the same DLL
  is at the same address in every process — relevant to severity reasoning, not to proof).

### 2.5 Privileged UI
- **WebUI** (`chrome://...`): privileged pages with Mojo WebUI interfaces or legacy
  `chrome.send()` handlers (`WebUIMessageHandler::RegisterMessages`). Strict CSP and Trusted Types
  by default upstream; vendors sometimes relax them. Untrusted content must go in
  `chrome-untrusted://` frames.
- **Extensions**: component extensions and private APIs (`chrome.*Private`) can do things normal
  extensions cannot. Check `externally_connectable` in every vendor extension manifest.

### 2.6 How Chromium-family programs want boundary bugs shown
- Renderer-compromise sandbox escapes: Chromium accepts reproductions that simulate a compromised
  renderer with `--enable-blink-features=MojoJS` (MojoJS bindings) or a patched renderer, **as long
  as the report says the bug assumes a compromised renderer**. Never present such a PoC as
  web-reachable.
- V8 sandbox bypasses: demonstrated with the V8 sandbox testing API in `d8`
  (memory corruption API that simulates in-sandbox arbitrary write).
- Chrome VRP (April 2026 structure): full-chain browser-process exploits up to $250,000 plus up to
  $250,128 MiraclePtr-bypass bonus; base reward for memory safety reports starts at $500 with
  multipliers; Google states it prioritizes categories hard for automated AI tooling and offers
  special research builds to demonstrate memory access/info leaks. Each bug in a chain is reported
  separately with independent reproduction.
- Severity reference: `docs/security/severity-guidelines.md` in Chromium.
- Fork programs (Edge, Brave, Opera, etc.) usually reward only vendor-specific code and send
  upstream issues to Chromium. Check each profile.

---

## 3. Gecko (Firefox, Tor Browser, Mullvad Browser, LibreWolf, Waterfox, Floorp, Zen)

### 3.1 Process model
- **Parent process**: privileged; runs the browser UI written largely in privileged JavaScript
  ("chrome" JS with the system principal) plus C++.
- **Content processes**: web content, sandboxed. **Fission** gives site isolation on desktop.
- Other processes: GPU, **RDD** (remote data decoder for media), socket process, utility processes
  (some audio/codec work), extension process.

### 3.2 IPC
- **IPDL** protocols (C++ actors, e.g. `PContent`, `PBrowser`), and **JSActors**
  (`JSWindowActorParent/Child`, `JSProcessActor*`) written in JS. JSActors are a large logic-bug
  surface: parent-side handlers receive messages from potentially compromised content processes and
  must validate everything (principals, browsing context, URLs, sizes).
- Values crossing IPC are serialized (structured clone, IPDL params). Watch for type/tag
  confusion when deserializing (case study: NaN-boxed double read back as a tagged pointer).

### 3.3 Engine and hardening
- SpiderMonkey: Baseline Interpreter/JIT → Warp/Ion; Wasm baseline + optimizing tiers; WasmGC.
- **RLBox**: some third-party libraries run inside a Wasm-based in-process sandbox; data copied
  from the untrusted side must be verified (case study: RLBox verification gap).
- **Frozen prototypes** in privileged JS: Mozilla froze built-in prototypes by default after a
  series of prototype-pollution sandbox escapes; AI harness logs showed models repeatedly trying
  that path and failing. Treat frozen/hardened areas as low yield; look for code that runs before
  the freeze or in contexts not covered.
- PHC/hardened allocators, Address Sanitizer builds published by Mozilla (TaskCluster artifacts).

### 3.4 How Mozilla wants boundary bugs shown
- Sandbox escapes may assume a compromised content process; Mozilla's own AI pipeline permits
  patching Firefox source **only in code that runs in the sandboxed process** to simulate that,
  and its bug bounty has similar rules.
- Severity: sec-critical / sec-high (reachable by normal browsing; critical reserved for public or
  exploited), sec-moderate (needs unusual victim steps), sec-low.
- Mozilla classifies sec-high from sanitizer-detected UAF/OOB symptoms without requiring an exploit.

---

## 4. WebKit (Safari, all iOS browsers using WKWebView, WebKitGTK/WPE: Epiphany, embedded devices)

### 4.1 Process model
- **UI process** (Safari/app), **WebContent process** (sandboxed; JSC + WebCore), **Networking
  process**, **GPU process** (media, canvas, WebGL on recent OS versions), sometimes a Model process.
- IPC: message definitions in `*.messages.in`; receivers must validate with `MESSAGE_CHECK`-style
  macros. A missing/insufficient MESSAGE_CHECK on a privileged receiver is the classic WebKit
  sandbox-escape class.

### 4.2 JSC and hardening
- Tiers: LLInt → Baseline → DFG → FTL. Hardening: Gigacage (isolated heaps for some buffers),
  StructureID protections, PAC on arm64e (pointer authentication), JIT memory protections,
  Lockdown Mode (disables JIT and many features).
- Real-world iOS chains (Coruna, DarkSword) go WebKit RCE → PAC bypass / GPU or other process →
  dyld/kernel. These show how many boundaries an Apple chain crosses.

### 4.3 Programs
- Apple Security Bounty, Apple security notes credit AI tools in 2026 (OpenAI Codex Security,
  Anthropic/Claude) for WebKit memory-safety bugs. WebKitGTK/WPE issues go to WebKitGTK security
  advisories (WSA) and downstream distros.

---

## 5. Electron and CEF desktop apps (Slack, Discord, Teams, Notion, Cursor, VS Code, AI desktop clients, many vendor "browsers")

### 5.1 Architecture
- **Main process**: Node.js with full OS access. **Renderer**: Chromium renderer, optionally with
  Node. **Preload** scripts bridge the two via `contextBridge`.
- Key `webPreferences`: `nodeIntegration` (default false since Electron 5), `contextIsolation`
  (default true since 12), `sandbox` (default true since 20), `webSecurity`, `webviewTag`,
  `allowRunningInsecureContent`, `nodeIntegrationInSubFrames`.
- **Fuses** (build-time): `RunAsNode`, `EnableNodeOptionsEnvironmentVariable`,
  `EnableNodeCliInspectArguments`, `EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`,
  `GrantFileProtocolExtraPrivileges`. Check with `npx @electron/fuses read --app <path>`.

### 5.2 Where Electron bugs come from
- **Bundled Chromium lag**: apps ship their own Chromium and trail upstream by weeks to many
  months; in April 2026 Hacktron observed Notion on Chromium 144, Cursor 142, Claude Desktop 146,
  Discord 138, Slack 132. Some windows run without sandbox (Discord main window), so a single
  renderer bug can be enough.
- `ipcMain.handle/on` handlers that do not validate `event.senderFrame` (origin/URL) or arguments.
- Preload exposing over-powerful APIs through `contextBridge` (file access, `shell.openExternal`,
  arbitrary IPC send).
- `shell.openExternal(untrusted)` → launching arbitrary protocol handlers / files.
- Navigation and window controls: missing `will-navigate`/`setWindowOpenHandler` restrictions let
  attacker content load in a privileged window.
- Custom protocols (`protocol.handle`) with path traversal or privileged schemes.
- Deep links / protocol client registration passing attacker arguments to the app
  (CVE-2018-1000006: Windows protocol handler command-line argument injection in Electron apps).
- Auto-update integrity, asar integrity/fuses off, DLL search order in install directories.

### 5.3 CEF
- `CefMessageRouter` / JS bindings, custom scheme handlers, resource request handlers; same
  questions as Electron IPC: who can call, what is validated.

---

## 6. Mobile browsers and in-app browsers

### Android
- Chromium-based browsers ship their own engine; others use **Android System WebView**.
- Review: exported activities/services/receivers/providers, intent filters, `intent://` URL
  handling, deep links and App Links, `addJavascriptInterface` bridges (pre-API-17 reflection RCE
  was CVE-2012-6636; today the risk is over-powerful bridge methods exposed to any loaded origin),
  `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs`,
  `shouldOverrideUrlLoading`, Custom Tabs / TWA trust, `FileProvider` paths.

### iOS
- All browsers use WKWebView unless using an alternative engine permitted in specific regions.
  Review `WKScriptMessageHandler` names and which frames can post to them, custom URL schemes and
  universal links, `loadFileURL:allowingReadAccessToURL:` scope, app extensions, keychain sharing.

---

## 7. Boundary cheat-sheet (use in triage)

| Boundary | Typical demonstration |
|---|---|
| Origin ↔ origin (SOP, UXSS, cross-origin leak) | Page on origin A reads a secret planted on origin B |
| Web content ↔ privileged UI/API | Web page triggers a privileged WebUI/extension/bridge action |
| Renderer/content ↔ browser/parent process | Compromised-renderer simulation causes browser-process memory corruption or privileged action |
| JS engine sandbox ↔ rest of renderer | Engine sandbox-testing API write → corruption outside sandbox |
| Extension permission boundary | Extension without permission X achieves X |
| Profile/container/mode isolation | State created in profile X visible/usable in Y |
| Standard user ↔ SYSTEM/root (installer/updater) | Low-privileged user causes privileged component to load/run their data |
| Network attacker ↔ user | MITM alters update/component/sync data that is trusted |
| Vendor server ↔ E2EE data | Server-side party can read data claimed to be end-to-end encrypted |
