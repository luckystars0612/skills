# Embedded bug classes — detection + three worked case studies

Each class: what it is, how to find it with idalib, and the kill condition. The three
case studies at the end are real, reproduced findings this methodology produced.

---

## 1. OS command injection (CWE-78) — the highest-yield class

**Shape:** attacker input concatenated (unquoted) into a string run by a shell.

**idalib hunt:**
```
imports_query / find_regex for sinks:
  C:   system, ___system, popen, do_system, twsystem, bstar, execl/execlp, exec.Command
  Lua: os.execute, luci.sys.call, luci.sys.fork_exec (-> nixio.exec "/bin/sh" "-c")
  Go:  exec.Command("/bin/sh","-c", …) / ("bash","-c", …)
For each: xrefs_to -> decompile the caller -> is a request field concatenated in?
Then trace_data_flow from the request parser (mg_get_var/cJSON/PostForm/nvram_get) to it.
```
**Kill conditions:** the field is passed as a *separate argv element* (no shell);
strict allowlist/validation before use; value is a fixed constant. `${IFS}` defeats a
naive space filter — a space-only check is not a kill.

## 2. Missing-`return` / broken auth (CWE-306/862)

**Shape:** the handler calls an auth check but doesn't act on the result — no `return`,
no branch away — so the privileged code runs even when auth fails.

**idalib hunt:** in each request handler, find the `check_auth`/`session_verify`/
`is_logged_in` call and read what follows. If the failure path only prints a message and
falls through to the file write / command / state change, it's an unauth bypass. Also
map **per-route vs global** auth: which controller/route group lacks the login middleware
(setup/init/wizard controllers are the usual offenders).

**Kill condition:** the check is followed by `return`/`goto error`/an early-out that
actually skips the sink; or a global filter gates the route before dispatch.

## 3. Stack/heap buffer overflow (CWE-121/122)

**Shape:** unbounded/oversized copy of input into a fixed buffer.

**idalib hunt:** `imports_query` for `strcpy`, `strcat`, `sprintf`, `sscanf`, `memcpy`,
`gets`; `xrefs_to` each; `decompile` and check the destination size vs the source length.
Note whether the binary has a **stack canary** and whether the stack/segment is **RWX**
(no NX) — determines exploitability past a crash. Watch the classic router entry points:
`/goform/*` handlers, `tdpServer`/OneMesh UDP parsers, SOAP/UPnP, CWMP SetParameterValues.

**Kill condition:** a bounded copy (`strncpy`/`snprintf`/`strlcpy` with a correct size),
a prior length check, or a destination provably >= max input. An `atoi`/`sscanf` bound is
often bypassable (`"22?AAAA"`) — read it carefully.

## 4. Format string (CWE-134)

**Shape:** attacker data reaches the *format* argument of `printf`/`sprintf`/`syslog`/
`fprintf` (not the varargs). Enables read/write and often RCE on embedded.

**idalib hunt:** `xrefs_to` the printf family; for each call, check whether the format
arg is a caller-supplied string rather than a literal. `trace_data_flow` from the request
field to that arg.

**Kill condition:** the format arg is a constant literal and user data is a value arg.

## 5. Path traversal / arbitrary file write (CWE-22/73)

**Shape:** a caller-influenced path reaches `fopen`/`open`/`fwrite`/`unlink`/`rename`, or
an import/upload endpoint writes attacker content to a chosen path.

**idalib hunt:** `imports_query` file ops; `decompile` handlers whose path comes from a
request field; check for `../` filtering and base-dir confinement. Config/VPN/cert import
endpoints are prime (they write to `/tmp` or `/etc` and may feed a later parser).

**Kill condition:** canonicalization + base-dir check; a fixed filename.

## 6. SSRF via incomplete blocklist (CWE-918/1327)

**Shape:** a server-side fetch of a user URL with a blocklist that misses
metadata/loopback/RFC1918 or a scheme/encoding.

**idalib hunt:** find the URL fetcher (`curl_easy_*`/`wget`/`http.Get`); read the
validator. Missing `169.254.169.254`, `[::1]`, `0.0.0.0`, decimal/hex IP, DNS-rebinding,
or non-http schemes = bypass.

**Kill condition:** an allowlist (not blocklist), or resolve-then-check-then-pin.

## 7. Trust-on-first-use / default credentials (CWE-1392/798)

**Shape:** factory-default device accepts the first login with any/blank password, or
ships a fixed admin password; empty `nvram` password treated as "no auth required".

**idalib/config hunt:** read the login handler and default config
(`defpasswd`/`sysauth`/`g_Pass` empty checks). This is what turns a "post-auth" sink into
**unauthenticated** on factory-new and post-reset devices.

---

## Case study A — D-Link DIR-X1860 (missing-return auth bypass → unauth file write + crash)

`/usr/sbin/anweb` (MIPS). Three config-import handlers
(`amneziawg_import`/`openvpn_import`/`client_routing_rule_import`) call `check_auth()`
but **do not `return`** on failure, then `fopen64` a `/tmp` file and `upload_file()` the
request body — **unauthenticated file write**. The imported `method` var is also used as
a printf format and passed to the backend, giving a format-string + a SIGSEGV in the root
`civetweb`/`anweb` worker. Verified under FirmAE full-system emulation (unauth HTTP 200 +
root-owned `/tmp` files + `do_page_fault … SIGSEGV`). Class 2 + 4 + 5.

## Case study B — TerraMaster TOS `TOSDaemon` (unauth root RCE, Go)

TOS-5 replaced the fuzzed PHP app with a Go daemon (`gin`, root, no priv-drop). Route
`POST /v2/Initialise/Initialise` is on a controller with **no login middleware** (only a
double-submit CSRF, which is not auth). `user_name` (checked only for spaces) flows to
`modifySshUser`: `fmt.Sprintf("sed -i 's/^AllowUsers .*$/AllowUsers %s/' %s", user_name,
cfg)` → `ShellExec` → `os/exec.Command("/bin/bash","-c",…)` as root. Single-quote
breakout; `${IFS}` beats the space filter. Gated to the un-provisioned setup window.
Class 1 + 2. (Static HIGH + partial dynamic — full boot needs the factory image.)

## Case study C — Cudy TR3000 (app-RPC root command injection, LuCI)

`POST /cgi-bin/luci/rpc/app` method `net.set_wan` → `luci.apprpc.net.set_wan(params)`:
```lua
sys.fork_exec("ifup " .. params[0] .. ";ifup " .. params[0] .. "2;wandetect")
```
`params[0]` concatenated unquoted; `fork_exec` → `nixio.exec("/bin/sh","-c",…)` as root.
Reachability: `rpc/app` requires a session (bad session → 403), but any web-UI role
reaching it gets root (privesc), and `defpasswd=1` gives trust-on-first-use unauth on a
factory-default device. Reproduced end-to-end over HTTP under qemu-aarch64+chroot
(booted real `ubusd`+`rpcd`+`uhttpd`, seeded `config.main.sysauth` + a root password):
`{"method":"net.set_wan","params":["; id > /tmp/pwn #",{"proto":"dhcp"}]}` → `/tmp/pwn`
= `uid=0(root)`. Class 1 + 7. Note the honesty point: the device had *other* known CVEs
(ipsec/MQTT) but this specific sink was novel — Phase-4 disclosure-check per-primitive.
