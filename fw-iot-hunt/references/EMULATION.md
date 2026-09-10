# Emulation — reach the sink on a running device

Pick the lightest harness that faithfully reaches your sink. Three tiers, plus the
gotchas this methodology hit in practice.

---

## Tier 1 — Whole-device full-system (FirmAE fork) — best for router web stacks

Fork with modern-distro fixes: `https://github.com/luckystars0612/FirmAE` (branch `main`;
uses `ip tuntap`, not the removed `tunctl`; adds `scripts/importFS.sh` for images the
built-in extractor can't unpack).

```bash
git clone --recursive https://github.com/luckystars0612/FirmAE && cd FirmAE
sudo ./download.sh && sudo ./install.sh && ./init.sh
# if extractor.py fails on the image, register the rootfs you already extracted:
sudo ./scripts/importFS.sh <brand> "$FW" /path/to/rootfs    # -> images/<IID>.tar.gz
sudo ./run.sh -r <brand> "$FW"                              # boot qemu-system-<arch>
```

**NIC/VLAN wiring (model-specific, critical).** FirmAE attaches the host TAP to `eth0` by
default, but many devices put the LAN on a **bridge over a VLAN sub-interface** (e.g.
DIR-X1860: `br0` over `eth2.1`, the 3rd NIC). Symptoms: boots but no ping / `web=000`.
Fix — point the TAP at the right NIC and add a host VLAN sub-interface:
```bash
IID=1
# edit scratch/$IID/run.sh: move tap to net2/eth2, make net0 a socket
sudo bash scratch/$IID/run.sh &
sudo ip link add link tap${IID}_0 name tap${IID}_0.1 type vlan id 1
sudo ip addr add 192.168.0.3/24 dev tap${IID}_0.1
sudo ip link set tap${IID}_0.1 up
curl -s -o /dev/null -w 'web=%{http_code}\n' http://192.168.0.1/     # up when non-000
```
Reach the guest root console on the **secondary** serial: `socat - UNIX-CONNECT:/tmp/qemu.<IID>.S1`.

## Tier 2 — qemu-user + binfmt + chroot — run the device's OWN daemons

Best when full-system won't boot but you can run the individual binaries. Register the
interpreter (once), then bring up the **dependency stack**, not just the target daemon.

```bash
sudo apt install -y qemu-user-static binfmt-support    # registers qemu-<arch> binfmt
ls /proc/sys/fs/binfmt_misc/qemu-aarch64               # confirm; 'F' flag => works in chroot
```

**The whole-web-stack pattern (the Cudy proof).** A single daemon usually isn't enough —
LuCI needs `ubusd` + `rpcd` alongside `uhttpd`. Boot them together in the chroot and
**seed the provisioned state** so an authenticated request path exists (this is normal
first-boot state, not a weakening of the bug):

```bash
R=/path/to/rootfs
sudo mkdir -p $R/{proc,dev,sys,tmp,var/run,var/lock,var/state}
sudo mount -t proc proc $R/proc; sudo mount -o bind /dev $R/dev; sudo mount -o bind /sys $R/sys
sudo setsid chroot $R /sbin/ubusd  >/tmp/ubusd.log  2>&1 </dev/null & sleep 2
sudo setsid chroot $R /sbin/rpcd   >/tmp/rpcd.log   2>&1 </dev/null & sleep 2
sudo setsid chroot $R /usr/sbin/uhttpd -f -h /www -x /cgi-bin -p 0.0.0.0:8080 >/tmp/uhttpd.log 2>&1 </dev/null & sleep 3
# seed: session allow-list + a known password (example for LuCI)
grep -q "list sysauth 'root'" $R/etc/config/luci || sudo sed -i "/^config core main/a \\\tlist sysauth 'root'" $R/etc/config/luci
HASH=$(openssl passwd -1 -salt abcd1234 test123); sudo sed -i "s|^root:[^:]*:|root:${HASH}:|" $R/etc/shadow
```
See `templates/stack_emulate.sh` for a parameterized, cleanup-aware version.

**Single-daemon** targets (a CGI/`/goform` binary) can run under a thin chroot with the
request fed via `QUERY_STRING`/stdin env, or invoked directly with `qemu-<arch> ./binary`.

## Tier 3 — Native — x86-64 Go/C daemons

Run directly on the host; stand in the services they expect (the daemon often reveals its
own DSN in an error, e.g. TerraMaster's `host=127.0.0.1 port=5032 user=terramaster
database=tos`). Beware update-package limits: no bundled DB/seeded schema → startup runs
but full listen fails (gorm "relation … does not exist"). Use the factory image for a
complete boot.

---

## Proving the primitive (what counts as reproduced)

- **Command injection:** injected marker owned by root — `{"…":"; id > /tmp/pwn #"}` then
  `/tmp/pwn` contains `uid=0(root)`. Point the payload at an attacker host for a callback
  proof without console access.
- **Overflow:** a controlled crash — `SIGSEGV`, `do_page_fault … BadVA`, or `$pc` under a
  controlled value in the serial log / gdbserver.
- **Auth bypass / file write:** the unauthenticated request returns success and the
  attacker file appears on the device (root-owned).

## Gotchas (learned the hard way)

- **`pkill`/`kill` in a compound command** can kill your own shell/process group
  (exit 144). Kill by exact pid, separately.
- **binfmt 'F' flag** lets `qemu-<arch>` run inside the chroot without copying the
  interpreter in; if absent, copy `/usr/bin/qemu-<arch>` into `$R/usr/bin/`.
- **Stale session across a restart** — a daemon restart invalidates prior cookies;
  re-login before firing.
- **Harness timing ≠ sanitization** — e.g. a payload leading with `ifup <iface>` stalls
  on a blocking netifd/ubus call, delaying the injected command. Lead with the injection
  (`; cmd #`) and confirm the sink is reached; don't misread a stall as a filter.
- **Wrong `rpc/*` node / method map** — verify the method→module binding (e.g. LuCI
  `app.lua`: `net = require "luci.apprpc.net"`) and that the dispatcher recognizes the
  method (unknown method → "Method not found" vs a clean `null` result = it ran).
- **Update vs factory image** — see Tier 3; factory image needed for a full boot.
- **Don't disturb co-tenant services** — if another session holds a port/container
  (redis, postgres), use a different port rather than fighting it.
