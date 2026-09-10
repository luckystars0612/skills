#!/bin/bash
# =============================================================================
# stack_emulate.sh  —  generalized qemu-user + binfmt + chroot bring-up for an
# embedded daemon stack, plus teardown. Distilled from the Cudy TR3000 proof
# (real ubusd + rpcd + uhttpd booted together to reach a LuCI RPC sink).
#
# Adapt the DAEMONS array + seed_state() to your target, then:
#   sudo ./stack_emulate.sh up   --rootfs /path/to/rootfs
#   sudo ./stack_emulate.sh down --rootfs /path/to/rootfs
#
# Requirements: qemu-user-static + binfmt-support for the target arch
#   (verify /proc/sys/fs/binfmt_misc/qemu-<arch> exists; 'F' flag => runs in chroot).
# =============================================================================
set -u
ROOTFS=""; PORT=8080
CMD="${1:-up}"; shift || true
while [ $# -gt 0 ]; do case "$1" in
  --rootfs) ROOTFS="$2"; shift 2;;
  --port)   PORT="$2";   shift 2;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done
[ -n "$ROOTFS" ] || { echo "usage: $0 up|down --rootfs DIR [--port N]"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (mount/chroot)"; exit 1; }
ROOTFS="$(cd "$ROOTFS" && pwd)"

# ---- EDIT ME: the daemons to boot, in order, with their args ----------------
# Format: "<path-in-rootfs>|<args>"   (empty args allowed)
DAEMONS=(
  "/sbin/ubusd|"
  "/sbin/rpcd|"
  "/usr/sbin/uhttpd|-f -h /www -x /cgi-bin -p 0.0.0.0:${PORT} -t 60 -T 30 -n 3"
)

# ---- EDIT ME: seed provisioned state so an authed request path exists --------
seed_state() {
  local R="$1"
  # Example (LuCI): session allow-list + a known root password.
  if [ -f "$R/etc/config/luci" ]; then
    grep -q "list sysauth 'root'" "$R/etc/config/luci" || \
      sed -i "/^config core main/a \\\tlist sysauth 'root'" "$R/etc/config/luci"
  fi
  if [ -f "$R/etc/shadow" ] && command -v openssl >/dev/null; then
    local H; H="$(openssl passwd -1 -salt abcd1234 test123)"
    sed -i "s|^root:[^:]*:|root:${H}:|" "$R/etc/shadow"
  fi
}

pids_of() { pgrep -f "qemu-.* .*${1}" 2>/dev/null; }

up() {
  mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,var/run,var/lock,var/state}
  mountpoint -q "$ROOTFS/proc" || mount -t proc proc "$ROOTFS/proc"
  mountpoint -q "$ROOTFS/dev"  || mount -o bind /dev "$ROOTFS/dev"
  mountpoint -q "$ROOTFS/sys"  || mount -o bind /sys "$ROOTFS/sys"
  seed_state "$ROOTFS"
  for d in "${DAEMONS[@]}"; do
    local bin="${d%%|*}" args="${d#*|}"
    [ -x "$ROOTFS$bin" ] || { echo "missing $ROOTFS$bin"; continue; }
    echo "[*] starting $bin $args"
    # shellcheck disable=SC2086
    setsid chroot "$ROOTFS" "$bin" $args >"/tmp/$(basename "$bin").log" 2>&1 </dev/null &
    sleep 2
  done
  sleep 1
  local code; code="$(curl -s -m5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/" 2>/dev/null)"
  echo "[+] web on :$PORT -> HTTP ${code:-none} (a 403/401 auth gate is expected)"
}

down() {
  for d in "${DAEMONS[@]}"; do
    local bin; bin="$(basename "${d%%|*}")"
    for p in $(pids_of "/$bin"); do kill -9 "$p" 2>/dev/null; done
  done
  for m in proc dev sys; do mountpoint -q "$ROOTFS/$m" && umount -l "$ROOTFS/$m"; done
  echo "[+] stopped + unmounted"
}

case "$CMD" in
  up)   up;;
  down) down;;
  *) echo "usage: $0 up|down --rootfs DIR"; exit 1;;
esac
