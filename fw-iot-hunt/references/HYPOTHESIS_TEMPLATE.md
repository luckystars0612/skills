# Hypothesis template + worked example

Emit 5–8+ of these for a non-trivial image. One candidate per hypothesis. Cheapest
disproof first; a killed or duplicate hypothesis is a result — keep it.

## Format

```
### H<n> — <one-line title>
- Daemon / component:  <binary + function/offset or Lua module.method>
- Input source:        <HTTP param / JSON-RPC param / CWMP / UDP probe / NVRAM / config>
- Sink / bug class:    <cmd-exec | overflow | format-string | file-write | traversal | SSRF | auth-bypass | TOFU>
- Claim (falsifiable): "Because <X> does <Y> without <guard>, a <who> can <impact>."
- Evidence:            <decompiled line / import / data-flow — cite the idalib finding; mark VERIFIED or INFERRED>
- Auth reachability:   <unauth | missing-return | per-controller gap | TOFU/default | authed-low-priv→root | setup-window>
- Kill condition:      <the single observation that disproves it>
- Cheapest next test:  <one decompile / one trace_data_flow / one emulated request>
- Disclosure check:    <novel | known-CVE-unpatched-in-latest | DUPLICATE(id) — Phase 4>
- Rank:                <likelihood × impact × novelty, 1-5 each>
```

## Worked example (Cudy TR3000 — the real finding)

```
### H1 — net.set_wan concatenates params[0] into a root shell
- Daemon / component:  LuCI apprpc, luci.apprpc.net.set_wan  (usr/lib/lua/luci/apprpc/net.lua)
- Input source:        JSON-RPC params[0] of POST /cgi-bin/luci/rpc/app method net.set_wan
- Sink / bug class:    cmd-exec — sys.fork_exec("ifup "..params[0]..";…") -> nixio.exec("/bin/sh","-c") as root
- Claim:               "Because set_wan concatenates params[0] unquoted into a fork_exec shell string,
                        an authenticated user can inject `; <cmd> #` and run <cmd> as root."
- Evidence:            VERIFIED — decompiled sink line at net.lua fork_exec; sys.lua fork_exec -> nixio.exec /bin/sh -c;
                        jsonrpc.handle calls copcall(fn, unpack(params)) so params[0] == first arg.
- Auth reachability:   authed-low-priv→root (any web-UI role); TOFU unauth on factory-default (defpasswd=1).
- Kill condition:      params[0] is validated to ^[A-Za-z0-9._-]+$, OR passed as a separate argv, OR set_wan returns early.
- Cheapest next test:  decompile set_wan fully (confirm no early return / no filter) — done; then one emulated HTTP request.
- Disclosure check:    novel for this component (device has unrelated ipsec/MQTT CVEs; net.set_wan not disclosed) — re-check before filing.
- Rank:                likelihood 5 × impact 5 × novelty 4
```

Outcome: killed nothing (no filter, no early return), disclosure-checked novel,
reproduced end-to-end over HTTP → `/tmp/pwn` = `uid=0(root)`. Reported.
