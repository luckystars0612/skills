# Recon playbook

Goal: produce `work/version.md` and `work/surface.md` (format at the end) so that every later
phase works on concrete, ranked units instead of "the browser".

Do recon on a dedicated VM snapshot with the target installed and a dedicated test profile.

---

## 1. Version and patch level (all engines)

1. Record target version, engine, upstream base version, channel, platform/OS build, CPU arch.
   - Chromium family: `chrome://version` (or the fork's scheme). Note the command line and
     profile path shown there.
   - Gecko family: `about:support` (application basics, build ID), `about:buildconfig`.
   - Electron: `process.versions` if reachable; otherwise strings in the main binary
     (`strings -n 8 <bin> | grep -E 'Chrome/[0-9]+\.|Electron/[0-9]+\.'`).
   - WebKit: Safari version ↔ OS release notes; WebKitGTK version from the package manager.
2. Get the matching **upstream** build for diffing and for "is this upstream?" checks:
   - Chromium: Chrome for Testing gives exact versioned builds (JSON endpoints at
     `googlechromelabs.github.io/chrome-for-testing`); Chromium snapshots and ASan builds are in
     the `chromium-browser-snapshots` / `chromium-browser-asan` storage buckets.
   - Firefox: `fuzzfetch` (MozillaSecurity) downloads release/nightly/ASan/fuzzing builds by
     version or revision.
   - Electron: the same Electron release from GitHub releases.
3. Patch gap (information only): compare the base version with the latest upstream security
   release notes (`chromereleases.googleblog.com`, Mozilla security advisories, Apple security
   notes). Record the lag in days and the list of security fixes the target lacks. Do not build
   exploits for them (see SKILL.md §0); flag them to the human.

---

## 2. Unpacking resources and diffing against upstream

The single most productive recon step for forks: **diff the target against upstream of the same
base version.** What is new is vendor code; vendor code is where the non-duplicate bugs are.

### 2.1 Chromium `.pak` files
```
python3 <chromium>/tools/grit/pak_util.py extract resources.pak -o extracted/resources
python3 <chromium>/tools/grit/pak_util.py extract chrome_100_percent.pak -o extracted/100p
# repeat for locales/*.pak if strings matter
```
- Some entries are compressed. GRIT brotli entries start with the bytes `1E 9B` followed by a
  6-byte little-endian decompressed size, then the brotli stream; others are gzip (`1F 8B`).
  Decompress before diffing.
- Extract the upstream build's paks the same way; then
  `diff -rq extracted/target extracted/upstream` and diff file contents for changed entries.
- Resource IDs differ between builds; match entries by content hash/filename hints, not by ID.
- What to look for in new/changed resources: WebUI HTML/JS bundles, `chrome.send('...')` message
  names, Mojo WebUI `PageHandler` method names, component extension `manifest.json`, URLs of
  vendor endpoints, feature names, pref names.

### 2.2 Gecko `omni.ja`
- `omni.ja` and `browser/omni.ja` are zip archives (optimized jar layout; use
  `python3 -m zipfile -e omni.ja out/` or `unzip` and ignore offset warnings).
- Diff against the same Firefox ESR/release. Vendor changes typically live in
  `browser/modules`, `actors/` (JSActors), `chrome/browser/content`, prefs files
  (`defaults/pref/*.js`, `greprefs.js`), and policies.

### 2.3 Electron `app.asar`
```
npx @electron/asar extract resources/app.asar extracted/app
npx @electron/fuses read --app <path-to-app-binary>
```
- Read `package.json` (main entry), then the main-process code: every `BrowserWindow`/
  `WebContentsView` creation with its `webPreferences`, every `ipcMain.handle/on`, every
  `shell.openExternal`, `protocol.handle/registerFileProtocol`, `setWindowOpenHandler`,
  `will-navigate` handler, auto-updater configuration, deep-link handling
  (`setAsDefaultProtocolClient`, `open-url`, `second-instance` argv parsing).
- Read preload scripts: everything exposed via `contextBridge.exposeInMainWorld`.

### 2.4 WebKit-based apps
- Safari: diffing is against Apple's open-source WebKit tags for the same release when possible.
- Apps embedding WKWebView: class-dump / Hopper / IDA for `WKScriptMessageHandler`
  implementations, `WKURLSchemeHandler`, navigation delegates.

### 2.5 Native binary diff (closed-source vendor native code)
- Diff the main browser binary (`chrome.dll`, `Chromium Framework`, `libchrome.so`, `xul.dll`,
  `libxul.so`) against upstream of the same version with BinDiff, Diaphora or ghidriff.
- Symbols: Google publishes Chrome symbols on its symbol server
  (`https://chromium-browser-symsrv.commondatastorage.googleapis.com`); Microsoft publishes Edge
  symbols on the Microsoft symbol server; Mozilla publishes Firefox symbols on its symbol server.
  Load upstream symbols, propagate names through matched functions, and isolate **unmatched**
  functions → vendor code queue.
- String anchors: vendor/product names, new mojom interface names (Chromium binder registration
  uses interface name strings), new pref names, new switches, new URLs/hosts, new IPDL/JSActor
  names.
- If an RE automation framework is available (IDA/x64dbg/WinDbg drivers), give it the list of
  unmatched functions and anchors as its work queue.

---

## 3. Internal pages and runtime state

### Chromium family
| Page | Why |
|---|---|
| `chrome://chrome-urls` | Full list of internal pages, including vendor ones |
| `chrome://version` | Command line (look for non-default switches) |
| `chrome://flags` | Diff defaults vs upstream; enabled experimental features increase surface |
| `chrome://policy` | Policies applied by default |
| `chrome://process-internals` | Site isolation mode, process locks |
| `chrome://sandbox` (Windows) | Sandbox status per process type |
| `chrome://extensions-internals` | All extensions including component/hidden ones, permissions |
| `chrome://components` | Component updater items (vendor components downloaded at runtime) |
| `chrome://gpu`, `chrome://media-internals` | GPU/media stack details |
| `chrome://net-export` | Capture vendor network channels |

Also inspect the profile directory: `Local State`, `Preferences`, `Secure Preferences`
(integrity MACs; see the SUPERSTOMP case study for legacy-MAC fallback), `Extensions/`,
component directories.

### Gecko family
`about:about`, `about:support`, `about:config` (diff prefs), `about:policies`,
`about:processes`, `about:addons` (system add-ons), `about:debugging#/runtime/this-firefox`.

---

## 4. Extensions shipped by the vendor (component, system, built-in)

For each one, record into `work/extracted/ext/<id>/`:
- `manifest_version`, `permissions`, `host_permissions`, `optional_permissions`,
  private APIs used (`chrome.*Private`, `browser.*` experiments in Firefox),
  `externally_connectable` (`matches`, `ids`), `web_accessible_resources` (and their `matches`),
  `content_scripts` (`matches`, `all_frames`, `match_about_blank`, `world: "MAIN"`),
  background service worker, `content_security_policy`.
- Beautified JS. Grep for: `onMessageExternal`, `onConnectExternal`, `onMessage`,
  `addEventListener('message'`, `postMessage(`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, `eval(`, `new Function(`, `setTimeout(` with strings, `chrome.scripting`,
  `chrome.tabs.executeScript`, `chrome.cookies`, `chrome.downloads`, `chrome.management`,
  `chrome.identity`, `fetch(` to vendor endpoints with credentials.

---

## 5. Platform layer

### Windows
- Services: `sc query`, `sc qc <name>` (binary path, account), `Get-CimInstance Win32_Service`.
- Scheduled tasks: `schtasks /query /fo LIST /v` (look for updater tasks running as SYSTEM).
- ACLs: `icacls "<install dir>" /T`, Sysinternals `accesschk -wsu "<dir>"` — any directory a
  standard user can write that a SYSTEM component reads/executes from is a lead.
- Procmon: filter on the updater/service process; look for `NAME NOT FOUND` DLL/EXE lookups in
  user-writable paths, operations in `%TEMP%`/`ProgramData` subfolders that follow
  junctions/symlinks, files written then executed.
- Protocol handlers: `reg query HKCR /f "URL Protocol" /s`; for each vendor scheme, read the
  `shell\open\command` string and how arguments are quoted.
- Native messaging hosts: `HKCU\Software\<Vendor>\...\NativeMessagingHosts`, `HKLM` equivalents;
  read each host manifest (`allowed_origins`) and the host binary.
- Elevation services (Chromium-based browsers often register an elevation service for
  app-bound encryption/updates): identify COM interfaces and who can call them.

### macOS
- `launchctl list`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`,
  `~/Library/LaunchAgents`, `/Library/PrivilegedHelperTools`.
- Entitlements: `codesign -d --entitlements :- <app or helper>`.
- XPC services inside the bundle; check the connection validation in the helper (audit token /
  code requirement checks vs PID-based checks).
- URL schemes: `Info.plist` → `CFBundleURLTypes`.

### Linux
- `dpkg -c` / `rpm -qlp`; maintainer scripts (`postinst`), setuid helpers, `.desktop` files and
  `MimeType=x-scheme-handler/...`, AppArmor profiles, update cron jobs/systemd timers.

---

## 6. Network channels (own accounts only)

- Proxy with mitmproxy/Burp. Chromium uses the OS trust store on Windows/macOS; on Linux add the
  CA to the NSS DB (`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n mitm -i ca.pem`). Firefox uses
  its own store unless `security.enterprise_roots.enabled` is set.
- Capture: account sign-in, sync, update checks, component/filter-list downloads, telemetry,
  vendor feature APIs (notes, wallets, AI, VPN), NTP content.
- For each channel record: certificate pinning, payload signing/integrity, version rollback
  protection, identifiers sent, whether responses are rendered in privileged contexts.

---

## 7. Mobile

### Android
```
apktool d app.apk -o extracted/apk
jadx -d extracted/jadx app.apk
```
- `AndroidManifest.xml`: `exported="true"` components, intent filters, deep links,
  `android:autoVerify` app links, `FileProvider` paths, permissions.
- Code grep: `addJavascriptInterface`, `@JavascriptInterface`, `setAllowFileAccess`,
  `setAllowUniversalAccessFromFileURLs`, `setAllowFileAccessFromFileURLs`,
  `shouldOverrideUrlLoading`, `Intent.parseUri`, `intent://`, `startActivity(` with
  attacker-derived intents, `loadUrl(` with attacker-derived URLs, `evaluateJavascript`.

### iOS
- Decrypted IPA → class-dump/IDA. `Info.plist` URL types, associated domains,
  `WKScriptMessageHandler` names and `userContentController:didReceiveScriptMessage:`
  implementations, `WKURLSchemeHandler`, navigation delegate policy decisions.

---

## 8. Output format

`work/surface.md` entries:
```
- id: S-012
  component: <name; file/resource/function/address>
  engine_layer: webui | builtin-ext | native-browser | native-renderer | ipc | service-integration |
                platform | mobile | defaults | upstream
  inputs: <what untrusted data enters, from where>
  reachable_by: web-page | specific-origin | any-extension | compromised-renderer | local-user |
                network-mitm | other-app
  privileged_capability: <what it can do that the caller cannot>
  vendor_specific: yes | no | modified-upstream
  notes: <observations; links to extracted files>
```
`work/units.tsv` columns: `unit_id  surface_id  description  reachable_by  score  status  agent  notes`
