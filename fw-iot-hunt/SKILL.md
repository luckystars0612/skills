---
name: fw-iot-hunt
description: Hunt high/critical vulnerabilities in IoT/OT firmware (routers, NAS, cameras, gateways, PLCs, embedded Linux/RTOS) by binary + source analysis and emulation. Distilled from real reproduced findings — D-Link unauth auth-bypass/file-write, TerraMaster TOS Go-daemon unauth root RCE, Cudy TR3000 app-RPC root command injection. Workflow: pick LATEST/LTS firmware (never EOL) of a common or less-fuzzed vendor → extract the rootfs (SquashFS/UBI/JFFS2/CramFS, vendor-obfuscated variants, monolith/RTOS, obfuscated Lua/Go) → map the privileged network daemons and their input→sink taint with IDA idalib → generate falsifiable bug hypotheses (cmd injection, missing-return auth bypass, stack overflow, format string, incomplete-blocklist SSRF, trust-on-first-use) → DISCLOSURE-CHECK before claiming novelty → confirm dynamically via FirmAE full-system or qemu-user+chroot emulation → professional advisory + REPRODUCE + PoC script. Use when auditing any firmware image, embedded web server, RPC/ubus/CWMP/UPnP surface, or when the user wants new bug ideas from a firmware blob. 中文触发词：固件漏洞、IoT漏洞、路由器漏洞、固件仿真、命令注入、栈溢出
tags: [firmware, iot, ot, embedded, router, nas, command-injection, buffer-overflow, auth-bypass, format-string, ida, idalib, binwalk, firmae, qemu, emulation, reverse-engineering, mips, arm, aarch64]
---

# fw-iot-hunt — IoT/OT firmware bug hunting

You are hunting **high/critical vulnerabilities in embedded firmware**. The unifying
target model, distilled from reproduced findings this methodology has produced
(D-Link DIR-X1860 unauth auth-bypass + file-write, TerraMaster TOS `TOSDaemon`
unauth root RCE, Cudy TR3000 app-RPC root command injection — see
`references/BUG_CLASSES.md`):

> **A network-facing daemon on the device runs as root and turns attacker-controlled
> input (HTTP/JSON-RPC/ubus/CWMP/UPnP/UDP-probe/NVRAM) into a privileged operation —
> a shell command, a fixed-size copy, a format string, a file write, an SSRF fetch —
> without validating the input or without correctly enforcing authentication.** Find
> the input source, trace it to the privileged sink, prove the guard is missing, then
> reach the sink over the wire on emulated or physical hardware.

Your job is NOT to write one exploit. It is to **map the privileged surface, generate
many falsifiable hypotheses, disclosure-check them, and confirm the survivors on a
running (emulated) device.** Reproduced or it didn't happen. VERIFIED vs INFERRED on
every claim. Latest/LTS firmware only — a bug in an EOL image is not a finding.

**Authorization gate (do this first, one line):** confirm the firmware/device is one
the user is authorized to analyze (publicly-downloadable vendor firmware for research,
own hardware, or an in-scope program). Emulation is local and safe; only test a
**physical or networked** device the user owns or is authorized to test. Never
auto-submit — the human files with the vendor PSIRT.

---

## Inputs this skill expects

- A **target**: a firmware file/URL, a vendor+model, an already-extracted rootfs, or
  "find a firmware worth auditing" (then apply Phase 0 target selection).
- Tooling available in this environment:
  - **Extraction:** `binwalk`, `sasquatch`/`unsquashfs`, `ubireader_extract_*`,
    `jefferson`, `cramfsck`, `dd`, `unluac`/`unluac2025.jar` (obfuscated Lua). See
    `references/EXTRACTION.md`.
  - **Static:** **IDA Pro via `idalib` MCP** — `mcp__plugin_ida-pro-mcp_idalib__*`
    (short names used below: `survey_binary`, `idb_open`, `decompile`, `imports_query`,
    `xrefs_to`, `xref_query`, `trace_data_flow`, `find_regex`, `search_text`,
    `list_funcs`, `func_query`, `list_globals`, `disasm`, `callgraph`, `strings`).
    Handles MIPS/ARM/aarch64/x86-64. Go daemons decompile too (gorm/gin patterns).
  - **Dynamic/emulation:** **FirmAE fork** (full-system qemu-system; modern-distro
    fixes) at `github.com/luckystars0612/FirmAE`; **qemu-user** (`qemu-mipsel`,
    `qemu-arm`, `qemu-aarch64`) + `binfmt` + `chroot` for single daemons or a whole web
    stack; native execution for x86-64 daemons. See `references/EMULATION.md` and
    `templates/stack_emulate.sh`.
  - Sibling skills: `cve-hunt` (disclosure-check + patch-bypass framing —
    **use its documentation reality-check gate before claiming novelty**),
    `ida-scripting`, `driver-analysis` (kernel/IOCTL), `triage-validation`,
    `report-writing`.

---

## The loop (each phase gates the next)

### Phase 0 — Target selection + intake
State the target and authorization in one line. If the user hasn't fixed a target, pick
one deliberately — the EV rule this methodology learned the hard way:

- **LATEST or LTS firmware only.** A known bug unpatched in the newest build is
  reportable (cross-model exposure); a bug in an EOL image is not. Download the current
  release from the vendor's support page.
- **Consumer-router flagship web stacks are saturated** (Tenda `/goform`, TP-Link
  `tdpServer`, Netgear SOAP — the obvious overflows are all CVE'd). Two better lanes:
  1. **Confirm known-unpatched-in-latest** via emulation for vendor coordination.
  2. **Less-fuzzed / newer surface** — second-tier IoT (NAS, cameras, travel routers,
     industrial gateways), or new feature code (EasyMesh, cloud/IPC daemons, VPN import,
     a Go/Rust rewrite of an old PHP app). This is where the novel bugs in this
     methodology's track record came from.

Identify the **architecture** (MIPS/ARM/aarch64/x86-64, endianness) and the **OS model**
(OpenWrt+LuCI, BusyBox+custom CGI, vendor RTOS monolith, full Linux NAS). This decides
the extraction and emulation path.

### Phase 1 — Extract the root filesystem
Follow `references/EXTRACTION.md`. In short: `binwalk` to fingerprint; carve and unpack
the filesystem (SquashFS via sasquatch, UBI via ubireader, JFFS2 via jefferson, CramFS).
Handle the traps this methodology has hit:
- **Vendor-obfuscated SquashFS** (e.g. Tenda: superblock magic `nice`, XZ magic rewritten
  to `Tenda`) — needs a de-obfuscator before unsquashfs.
- **Obfuscated Lua bytecode** (e.g. Cudy LuCI `apprpc/*.lua`, constant-tag tweaks) —
  decompile with `unluac`.
- **RTOS / monolith** (e.g. TP-Link TPOS: no Linux, no SquashFS, MINIFS asset fs, no
  shell) — load the monolithic image into IDA at the right base; there is no rootfs.
- **Update vs factory image** — an update/app package may lack the glibc base, bundled
  DB, and seeded schema (this blocked full TerraMaster boot). Prefer the factory image
  for emulation.

Confirm the version (`etc/openwrt_release`, `etc/VERSION`, a banner) so you know you're
on the latest.

### Phase 2 — Map the privileged network surface (idalib)
Enumerate the daemons that (a) run as **root** and (b) take **remote/local input**:
web server (`uhttpd`/`lighttpd`/`goahead`/`boa`/custom `anweb`), RPC (LuCI JSON-RPC,
`ubus`/`rpcd`), CWMP/TR-069, UPnP/`miniupnpd`, `/goform` handlers, UDP discovery
(`tdpServer`, OneMesh), MQTT, a Go/Node backend. For each, in IDA:

1. **Input sources** — `imports_query`/`xrefs_to` for the request parsers:
   `mg_get_var`/`websGetVar`/`httpd_*`, JSON parse (`cJSON_*`, `json_*`), `nvram_get`,
   `getenv`("QUERY_STRING"/"CONTENT_LENGTH"), `recvfrom`, ubus/blobmsg field getters,
   Go `c.PostForm`/`ShouldBindJSON`.
2. **Privileged sinks** — `imports_query`/`find_regex` for:
   - **command exec**: `system`, `popen`, `execve`/`execl*`, `do_system`,
     `___system`/`bstar`, `twsystem`, Lua `os.execute`/`luci.sys.fork_exec`/`.call`,
     Go `exec.Command("/bin/sh","-c", …)` / `bash -c`.
   - **memory copy**: `strcpy`, `strcat`, `sprintf`, `memcpy`, `sscanf` into
     fixed/stack buffers (overflow; check for a canary and RWX stack).
   - **format string**: user data reaching the `fmt` arg of `printf`/`syslog`/`sprintf`.
   - **file write / path**: `fopen`/`open`/`fwrite` with a caller-influenced path
     (traversal / arbitrary write); config/VPN import endpoints.
   - **SSRF**: `curl`/`wget`/`fetch` of a user URL with an incomplete blocklist.
3. **Taint** — `trace_data_flow` (or manual `decompile` reading) from each source to each
   sink. The bug is present when input reaches the sink **unquoted/unbounded/unvalidated**.
4. **Auth reachability** — for every candidate sink, decide who can reach it:
   - Is the route behind a session/auth check? Read the dispatcher.
   - **Missing-`return` auth bypass** (the D-Link pattern): the handler *calls*
     `check_auth` but does not `return` on failure, so the privileged code runs anyway.
     Grep each handler for an auth check that isn't followed by a return/branch-out.
   - **Per-controller vs global auth** (the TerraMaster pattern): auth applied per route;
     one controller (e.g. the setup/`Initialise` wizard) has no login middleware.
   - **Trust-on-first-use / default creds** (the Cudy pattern): first login with any
     password accepted on a factory-default device; empty/default admin password.
   - **Setup-window gating**: unauth only while un-provisioned (still a real finding —
     factory-new and post-reset devices).

Spawn subagents to map separate daemons/subsystems in parallel on a large image; **you**
form the final ranked hypothesis list. Prefer `find_regex`/`imports_query`/`xrefs_to`
over `search_text` on huge monolithic images (search_text can time out).

### Phase 3 — Generate MULTIPLE falsifiable hypotheses
Don't stop at one. For a non-trivial image emit **5–8+ hypotheses**, one per candidate,
in the `references/HYPOTHESIS_TEMPLATE.md` format. Build each from:

```
INPUT SOURCE            ×  SINK / BUG CLASS          ×  AUTH REACHABILITY
- HTTP query/POST param    - cmd exec (shell concat)    - unauth (no gate)
- JSON-RPC / ubus param    - stack overflow (strcpy)    - missing-return auth bypass
- CWMP SetParameterValues  - format string (%n/%s)      - per-controller gap (setup wizard)
- UDP discovery packet     - arbitrary file write       - trust-on-first-use / default cred
- NVRAM / config value     - path traversal             - low-priv authed → root (privesc)
- config/VPN import blob    - SSRF (incomplete blocklist) - setup-window only
- MQTT / cloud message     - integer/heap overflow      - authed admin (still useful)
```

Each hypothesis MUST state: **Claim** (one falsifiable sentence) · **Evidence** (the
decompiled line / import / data-flow — cite the idalib finding; say if inferred) ·
**Kill condition** (the single observation that disproves it — e.g. "input is
length-checked to 15", "handler returns on auth fail", "path is fixed") · **Cheapest
next test** · **Rank** (likelihood × impact × novelty).

### Phase 4 — DISCLOSURE-CHECK before celebrating (mandatory gate)
Before investing in reproduction, **check whether the bug is already public.** This
methodology has twice reproduced already-disclosed bugs and wasted the effort — never
skip this. Invoke the `cve-hunt` skill's documentation reality-check discipline:
- Search NVD/CVE, vendor advisories, GitHub, exploit-db, and packet-storm for the
  **vendor + model + component + primitive** (not just the vendor).
- Distinguish: (a) genuinely novel; (b) known CVE but **unpatched in the latest**
  firmware (reportable as cross-model / regression coordination); (c) duplicate of a
  disclosed & fixed bug (drop it). Note that a device can have *other* known CVEs while
  *your specific* sink is novel (Cudy had ipsec/MQTT CVEs but `net.set_wan` was new).
- Record the verdict per hypothesis. A killed/duplicate hypothesis is a result — report
  it so you don't re-tread.

### Phase 5 — Confirm dynamically (emulation)
Kill cheap hypotheses statically first (one `decompile`/`trace_data_flow` each). For the
survivors, stand up a running device and reach the sink over the wire. Pick the lightest
faithful harness (full detail + gotchas in `references/EMULATION.md`):

- **Whole-device (FirmAE fork)** — best fidelity for router web stacks. `importFS.sh`
  when the built-in extractor fails; fix NIC/VLAN wiring to the model's real bridge
  (e.g. LAN on `br0` over `eth2.1`); modern-distro fixes (`ip tuntap`, not `tunctl`).
- **qemu-user + binfmt + chroot** — run the device's *own* daemons on the host. Bring up
  the dependency stack, not just the target: e.g. the Cudy proof booted real
  `ubusd`+`rpcd`+`uhttpd` together and seeded the provisioned state (session allow-list,
  a known password) so an authenticated request reaches the sink. `templates/stack_emulate.sh`
  generalizes this.
- **Native** — x86-64 Go/C daemons run directly (stand in the DB/redis they expect).

Then prove the primitive over HTTP/UDP/etc: for command injection, an injected marker
file owned by root (`id > /tmp/pwn` → `uid=0(root)`); for overflow, a controlled crash
(SIGSEGV / `$pc`); for file write, the attacker file on disk. Understand harness
artifacts vs real behavior — a blocking `ifup`/`ubus` call that stalls a payload is a
timing artifact, **not** sanitization; confirm the sink is genuinely reached.

### Phase 6 — Report
Write the advisory with `report-writing` and `templates/ADVISORY.md`: metadata table
(vendor/model/firmware/component/CWE/CVSS/auth), summary, technical root cause with the
decompiled sink and the taint path, auth-reachability, a tested PoC (exact request →
exact response → root marker), impact, honest verification status (static vs dynamic),
remediation, and disclosure triage. Ship a `REPRODUCE.md` and a re-test/PoC script
(`templates/` has a generalizable emulate→exploit→verify script). Compute CVSS honestly
(authenticated vs unauth-in-setup-window can be two vectors). **Never auto-submit** — the
human coordinates with the vendor PSIRT.

---

## Rules of engagement
- **Latest/LTS only.** A finding in an EOL image is not a finding. Confirm the version.
- **Disclosure-check BEFORE reproducing.** Reproducing a known CVE is wasted effort;
  celebrating one as novel is a credibility hit. Phase 4 is mandatory.
- **Reproduced or it didn't happen.** Prove the primitive on a running device — a root
  marker, a controlled crash, an on-disk artifact. Static-only is a lead, labeled as such.
- **VERIFIED vs INFERRED** on every claim. idalib/emulation evidence is verified;
  "probably reachable" is inferred — say which.
- **Cheapest disproof first.** Most hypotheses die in one decompile — do that before any
  emulation.
- **Auth reachability is half the bug.** An unreachable sink is not a vulnerability.
  Missing-return, per-controller gaps, and trust-on-first-use are the recurring ways a
  "post-auth" sink becomes unauth — check them explicitly.
- **Harness artifact ≠ sanitization.** When a payload doesn't fire under emulation,
  determine whether it's the harness (blocking call, missing service, wrong cwd/namespace)
  or a real guard, before concluding either way.
- **Record dead/duplicate hypotheses** in the report — they show coverage.
- **Never auto-submit.** Prepare the package; the human files it.

## Pointers
- `references/EXTRACTION.md` — firmware fingerprinting + unpacking recipes, vendor
  obfuscation, obfuscated-Lua, RTOS/monolith, update-vs-factory traps.
- `references/BUG_CLASSES.md` — the recurring embedded bug classes with idalib detection
  queries and the three worked case studies (D-Link / TerraMaster / Cudy).
- `references/EMULATION.md` — FirmAE full-system + qemu-user chroot recipes, the stack
  bring-up + state-seeding pattern, NIC/VLAN wiring, and the gotchas hit in practice.
- `references/HYPOTHESIS_TEMPLATE.md` — the hypothesis format + a worked example.
- `templates/stack_emulate.sh` — generalized qemu-user+chroot daemon-stack bring-up.
- `templates/ADVISORY.md` — the professional advisory skeleton.
