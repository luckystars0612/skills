# Demonstrating impact: from trigger to paid bounty

A trigger that crashes is not a report. A report that says "this might be exploitable" gets
triaged low. This file bridges the gap between finding a bug and *proving* its impact at the
level vendors pay serious money for. Everything here uses sanctioned tooling and stays within
the proof standard: the goal is to *characterize* the primitive convincingly, not to weaponize
it.

---

## 1. Memory-safety bugs: crash → characterized primitive

### 1.1 The baseline: a reproducible crash with root cause

Every memory-safety finding starts here. Without this, nothing else matters.

- **Sanitizer build** (always preferred). Chromium publishes ASan builds per platform/channel;
  Firefox publishes ASan+UBSan nightly. Run the minimal testcase, capture the full sanitizer
  report (allocation stack, free stack, use stack for UAF; OOB offset and size for
  heap-buffer-overflow). This alone is enough for many programs to accept and pay.
- **Without a sanitizer build** (closed-source fork, mobile). Run under a debugger (lldb/gdb on
  Linux/macOS, WinDbg/x64dbg on Windows). Capture: faulting instruction, register dump, call
  stack, the heap state around the corrupted object. Correlate with source/disassembly to explain
  the root cause. Note the allocator: Chromium PartitionAlloc and Firefox mozjemalloc defeat
  OS page-heap tools — rely on the crash analysis plus root-cause reasoning.
- **Minimize** the testcase until every line is necessary. A 12-line HTML that crashes is worth
  more than a 500-line one. Document which lines trigger what (the allocation, the free, the
  reuse).

### 1.2 Upgrading severity: showing controlled corruption

A crash proves the bug exists. Showing *what an attacker controls* is what moves it from
"medium" to "high" or "critical." The question the vendor asks: "can the attacker control the
corrupted value, the offset, or the size?"

**How to demonstrate this without building an exploit:**

- **Vary the testcase inputs** and show the corruption changes predictably. If changing a
  length field in your HTML/JS moves the OOB offset, document that: "offset = input_length - 16,
  attacker-controlled." If changing the timing of a free changes which object fills the freed
  slot, show two runs where different objects land there.
- **Print the corrupted value** from JS if the bug gives you a read. A type confusion that lets
  you read a pointer as a float → print the float, show it changes per run (ASLR), and explain
  what it leaks. This is *observation*, not exploitation.
- **Use the engine's own testing/diagnostic API** where one exists:
  - **V8 sandbox testing API** (`--sandbox-testing` in `d8`): designed for exactly this purpose.
    It lets you demonstrate that a bug violates a sandbox invariant (e.g., corrupt a pointer
    table entry, read/write outside the cage) using V8's own sanctioned interface. Chrome VRP
    explicitly accepts findings demonstrated this way. The API provides:
    - `Sandbox.targetPage`: a page outside the sandbox to target
    - `Sandbox.base` / `Sandbox.byteLength`: cage boundaries
    - Signal functions that fire when a sandbox property is violated
    Use these to show: "my bug lets me write to `targetPage`" or "my bug lets me read outside
    `[base, base+byteLength)`." That is a demonstrated sandbox-escape *primitive*, which is
    what the VRP pays the high tier for — not a full chain.
  - **Firefox rr / Pernosco**: record the execution, replay to the corruption point, inspect
    the exact state. Submit the trace or annotated screenshots.
- **Annotate the sanitizer report.** Don't just attach it — walk through it: "Line 1 allocates
  a 64-byte CSSFontFeatureValuesMap. Line 2 is the free (triggered by the mutation on line 7 of
  the testcase). Line 3 is the reuse — a 64-byte allocation of attacker-controlled type X fills
  the slot. The stale iterator then reads field Y of type X as if it were field Z of the original
  type, giving attacker-controlled value W." This narrative is what separates a high-severity
  report from a "crash, might be exploitable" dismissal.

### 1.3 Chrome VRP reward tiers (2026 restructured program)

Understanding what pays what, so you aim for the right demonstration:

| Demonstration level | Base reward | What you show |
|---|---|---|
| Crash / denial of service only | Low | Sanitizer crash, root cause |
| Controlled read | Medium | You choose *what* is read and can observe the value |
| Controlled write | High | You choose *what* is written and *where* |
| Renderer compromise (code exec in sandbox) | High | Arbitrary JS/Wasm execution via the bug |
| Full chain (renderer + sandbox escape) | $250,000 | Code execution outside the sandbox |
| Full chain + MiraclePtr bypass | +$250,000 | Chain bypasses `raw_ptr` protection |

**Key insight:** "controlled write" — demonstrable with the sandbox-testing API or by showing
the corrupted value tracks attacker input — already reaches the high tier. You do not need a
full chain for a high payout on most bugs. The $250k tier is for the rare case where you *also*
escape the sandbox, and that is a human decision (SKILL.md §0).

Multipliers apply: renderer-process bugs get a base multiplier; browser-process bugs (no
sandbox) get a higher one; bugs reachable without user interaction get another. Document each
applicable multiplier in the severity justification.

### 1.4 Fork-specific severity amplification

When a fork makes a bug *worse* than it is upstream, say so explicitly:

- **Missing mitigation.** The fork ships without MiraclePtr, PartitionAlloc hardening, V8
  sandbox, or with `--no-sandbox` equivalent. An upstream "medium" UAF that MiraclePtr catches
  in Chrome becomes a "high" in the fork. Document: "upstream Chrome: MiraclePtr terminates on
  this UAF (tested on Chrome $VERSION). Target fork: no MiraclePtr, UAF is exploitable."
- **Older base version.** The fork is 10+ versions behind. An upstream-patched bug is still live.
  This is a patch-gap finding; many programs exclude it unless you show *reachability from
  fork-specific code* (not just "the old engine has the bug").
- **Relaxed defaults.** Site isolation disabled, JIT hardening off, WebUI CSP weakened. Show the
  concrete attack the default enables: "with site isolation disabled, Spectre-style
  cross-origin read is feasible from the testcase" — with the read demonstrated.
- **Extra attack surface.** The fork added a privileged extension/WebUI that creates a new path
  to a sensitive API. Even if the underlying API is upstream, the *reachability from web content
  via the fork's extension* is the fork's bug.

---

## 2. Logic / boundary bugs: showing the crossing

### 2.1 The oracle pattern

A logic bug's PoC is a test that says "this data was on side A, and I read it from side B where
I should not be able to." Build this into the testcase — don't describe it in words.

**Concrete oracle patterns by boundary type:**

- **Cross-origin read.** Plant a known secret (`BOUNTY_SECRET_7f3a`) in origin B (a second
  local server on a different port). From origin A, use the bug to read it. The PoC prints:
  `"LEAKED: BOUNTY_SECRET_7f3a"`. Automate with Playwright: two servers, one page, assert the
  secret appears.
- **Cross-profile / cross-container.** Create data (a bookmark, a cookie, a password entry) in
  profile/container X. Switch to profile/container Y. The PoC shows the data is accessible.
  Screenshot the before/after, or script it with the browser's automation.
- **Privilege escalation via WebUI/extension.** Plant a trigger on a web page. Show the
  privileged action fires (a file is read, a setting changes, an extension API responds). Log
  the privileged side: `console.log` in the extension background, `chrome.send` result in WebUI,
  `ipcMain` handler log in Electron.
- **Sandbox escape from IPC.** Use the vendor-sanctioned compromised-renderer simulation
  (MojoJS bindings, `--enable-blink-features=MojoJS` on a test build, or the vendor's own test
  harness) to call the IPC method directly with a crafted message. Show the browser process acts
  on it without validating the renderer's identity/origin. Label the finding "assumes compromised
  renderer."
- **Updater / platform privilege.** Create a symlink or write a file as a standard user. Show
  the SYSTEM/root service reads or executes it. Use Process Monitor / `inotifywait` / `dtrace`
  to capture the privileged access.

### 2.2 Making the PoC self-contained

A vendor triager runs your PoC on a clean machine. If it requires special setup, it gets
deprioritized or rejected.

Checklist:
- Single HTML file (or a small folder with a `README` and a `run.sh`/`run.py`).
- Works on a default-config, clean-profile install of the latest release.
- Contains its own oracle — prints the leaked data, logs the privileged action, shows the
  before/after state.
- Includes a 30-second video of the reproduction if the steps are complex.
- If automation is needed (Playwright/Puppeteer), include the script and a `package.json` with
  pinned versions.

### 2.3 Boundary-crossing severity scale

| Boundary | Typical severity | What to show |
|---|---|---|
| Web content → cross-origin data | High–Critical | Leaked secret from another origin |
| Web content → local file read | High–Critical | Known file contents printed |
| Web content → privileged browser API | High | API response or state change logged |
| Extension (low-perm) → high-perm API | Medium–High | API call succeeds from low-perm context |
| Profile/container A → B data | Medium–High | Data created in A visible in B |
| Local user → SYSTEM/root code exec | High–Critical | Controlled file executed as SYSTEM |
| Renderer → browser process action | High (assumes compromised renderer) | Action fires from Mojo/IPC |

---

## 3. Writing the severity justification

The severity justification is often the difference between a $500 and a $5,000 payout. Vendors
use their own scale (Chromium severity guidelines, Mozilla sec-rating, etc.) and the triager
applies it. Your job is to make their job easy by stating the case clearly.

**Template:**

```
Severity: [High / Critical] (per <vendor> severity guidelines, <section>)

Justification:
- Attacker model: [web page / extension / local user / network] with [no / one-click / ...] 
  user interaction.
- Boundary crossed: [which one, from the cheat-sheet].
- Attacker control: [what is controlled — offset, value, target, size — with evidence from 
  the testcase variations].
- Impact: [what the attacker achieves — read secret, write arbitrary, execute code in 
  <process>, escalate to <privilege>].
- Amplifying factors: [no user interaction / affects all platforms / default config / 
  no mitigation in this target].
- Mitigating factors: [requires specific precondition / probabilistic / only affects 
  <platform>]. State these honestly — underreporting them loses credibility.
```

**Common mistakes that get reports downgraded:**
- Claiming "critical" without showing controlled corruption or a crossed boundary.
- Saying "could lead to RCE" without evidence of attacker control.
- Ignoring mitigations (MiraclePtr, CFI, sandbox) that neutralize the primitive in practice.
- Overlong reports that bury the impact in pages of analysis. Lead with the boundary, the
  control, and the impact, then explain the root cause.

---

## 4. Engine-specific demonstration aids

### V8 (Chromium, Electron, Chromium-forks)

- `--sandbox-testing` in `d8`: the primary tool for sandbox-invariant violations. Run `d8`
  with this flag, access the `Sandbox` object from JS, and demonstrate the property violation.
  This is what Chrome VRP expects for V8-sandbox findings.
- `--allow-natives-syntax` + `%DebugPrint(obj)`: shows object layout, map, fields. Use to
  confirm a type confusion gives the wrong map/fields, but note that `--allow-natives-syntax` is
  a non-default flag — the *trigger* must work without it; use it only for *analysis*.
- `--trace-turbo` / `--trace-maglev`: trace compiler decisions to show where an optimization
  introduces the invariant violation. Attach the trace excerpt in the report.
- ASan build + `--single-process` (for heap bugs where multi-process hides the corruption):
  use only for analysis; the report's PoC must reproduce in multi-process default config.

### SpiderMonkey (Firefox)

- `--fuzzing-safe --disable-oom-functions` in the JS shell for clean reproduction.
- rr recording: `rr record ./firefox <testcase>`, then `rr replay` to walk through the
  corruption. Attach the trace or annotated session.
- `dumpObject()` / `dumpValue()` in debug builds to confirm type confusion or wrong value.

### JavaScriptCore (WebKit/Safari)

- `jsc` with `--useConcurrentJIT=false` to isolate JIT bugs from timing issues.
- `$vm.value(obj)` / `describe(obj)` in jsc to inspect object internals.
- Crash logs with the full register dump and disassembly of the faulting function.

### Electron apps

- Start the app with `--inspect` and use the DevTools protocol to observe the main process.
- `ELECTRON_RUN_AS_NODE=1` with a script to test `ipcMain` handlers directly (this IS the
  default — if the app does not disable it via fuses, it is reachable; document whether the
  fuse is set).
- Note that an Electron finding's severity depends heavily on whether `sandbox: true`,
  `contextIsolation: true`, and `nodeIntegration: false` are set. Check and document each.

---

## 5. The PoC is the report

Most triagers look at the PoC before reading the text. Invest in it accordingly:

1. **Minimize** — every line has a reason. Comment the key lines: `// trigger the UAF`,
   `// this value will be read as a pointer`.
2. **Name it well** — `poc-cross-origin-leak-via-webui-handler.html` not `test.html`.
3. **Make it deterministic** — if timing-dependent, add a retry loop with a counter; note the
   success rate ("triggers 3/10 runs on a clean profile").
4. **Include the oracle** — the PoC itself prints/logs the proof of impact. The triager should
   not need to set up external tooling to see the result.
5. **Include the analysis** — a separate `analysis.md` with the annotated sanitizer report,
   the root-cause walkthrough, and the severity justification. Don't put this in the HTML.

When a program offers higher rewards for deeper demonstration (Chrome VRP's full-chain tier,
ZDI's exploit tier), record what you have — the characterized primitive, the evidence of control
— and hand the decision to the human researcher. The skill's job ends at a clear, reproducible,
well-characterized finding with demonstrated impact. The human decides whether to invest in
chaining.
