# Security Advisory — <Vendor> <Model>: <Vuln title> (<CWE / impact>)

| | |
|---|---|
| **Vendor** | <Vendor> |
| **Product** | <Model> (<hw rev>) |
| **Affected firmware** | <version + build> (<date>, latest for the <variant>). Platform: <SoC>, <arch>, <OS>. |
| **Component** | <daemon / module / endpoint>. Runs as **<privilege>**. |
| **Vulnerability type** | CWE-<n>: <name> |
| **Impact** | <e.g. arbitrary OS command execution as root → full device compromise> |
| **Authentication** | <none / authenticated (role) / unauth in setup window / TOFU> |
| **CVSS v3.1 (base)** | **<score> (<sev>)** — `<vector>` (+ alternate vector for the unauth window if applicable) |
| **Status** | <novel / known-unpatched-in-latest>; reproduced <static+dynamic>. See §Disclosure. |

## 1. Summary
<2–4 sentences: the endpoint, the input, the sink, the guard that's missing, the impact.>

## 2. Affected products
- Confirmed: <model + firmware> (latest).
- Likely (not individually confirmed): <siblings sharing the code>. Vendor should treat
  the whole <module/daemon> as in scope.

## 3. Technical details
### 3.1 Vulnerable sink
```
<decompiled sink — the exact line where input meets the privileged operation>
```
<why it's unsafe: unquoted concat / unbounded copy / user-controlled format / unchecked path>

### 3.2 Executor / privilege
<how the sink runs (shell -c, the copy target, etc.) and why it's privileged (runs as root).>

### 3.3 Taint path (request → sink)
```
<source parser> → <dispatch> → <resolve/route> → <handler(args)> → <sink(input)>
```

## 4. Authentication and reachability
<the dispatch gate; who can reach it; missing-return / per-controller / TOFU / setup-window;
privilege obtained.>

## 5. Proof of Concept
```http
<step 1 — auth if needed>
```
```http
<step 2 — the exploit request>
```
Result (as root): <exact response + the on-device artifact, e.g. /tmp/pwn = uid=0(root)>.

## 6. Impact
<full-device consequences: traffic intercept, persistence, pivot; exposure model.>

## 7. Verification
- **Static (confidence):** <what was read from the decompilation>.
- **Dynamic:** <emulation harness; the request fired; the root marker / crash observed>.
  <harness caveats, honestly>.
- Reproduction: see REPRODUCE.md + <script>.

## 8. Remediation
1. Validate the input (allowlist) before use.
2. Eliminate the shell / bound the copy / fix the format arg / confine the path.
3. Audit the sibling handlers for the same pattern.
4. <auth fix: return on failure / global gate / remove TOFU> if applicable.

## 9. Disclosure triage (honest)
- Known/unrelated CVEs for this device: <list, and that they are NOT this>.
- This specific <component/primitive>: <novel / not found>; re-check NVD/vendor/GitHub
  immediately before publication.

## 10. Credits
Discovered through independent firmware security research; reported for coordinated
disclosure. Not published.
