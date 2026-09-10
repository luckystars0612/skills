# Firmware extraction — fingerprint, unpack, and the traps

Goal: get a readable root filesystem (or the loadable monolith) so IDA and emulation can
work. Confirm the **version** afterward — you must be on the latest/LTS.

## 0. Host tools

```bash
sudo apt install -y binwalk squashfs-tools sasquatch qemu-user-static binfmt-support \
                    p7zip-full unzip curl
pipx install ubi_reader        # ubireader_extract_files / _images  (UBI/UBIFS)
pip3 install --user jefferson  # JFFS2
# unluac.jar for obfuscated Lua (from the unluac project)
```

## 1. Fingerprint

```bash
file "$FW"
binwalk "$FW"                  # note filesystem type + offset
binwalk -E "$FW"               # entropy: flat high entropy => encrypted/packed vendor blob
```

Common signatures and what they mean:
- **uImage / FIT** → header + (LZMA/XZ) kernel + a filesystem further in.
- **Squashfs** → the usual rootfs. Note the offset.
- **UBI erase count header** → NAND UBI volume; rootfs is a SquashFS/UBIFS inside a volume.
- **JFFS2 / CramFS** → older NOR-flash filesystems.
- **No filesystem, flat/high entropy** → encrypted image (vendor key needed) OR an RTOS
  monolith (no filesystem — load into IDA directly, see §6).

## 2. SquashFS (the common case)

```bash
OFF=$(binwalk "$FW" | awk '/[Ss]quashfs/{print $1; exit}')
dd if="$FW" of=root.sqfs bs=1 skip="$OFF"
sasquatch -d rootfs root.sqfs      # sasquatch handles vendor LZMA quirks
# or: unsquashfs -d rootfs root.sqfs
cat rootfs/etc/openwrt_release 2>/dev/null || cat rootfs/etc/VERSION 2>/dev/null
```

## 3. UBI / UBIFS (NAND — e.g. Cudy TR3000)

```bash
OFF=$(binwalk "$FW" | awk '/UBI erase count header/{print $1; exit}')
dd if="$FW" of=ubi.img bs=1 skip="$OFF"
ubireader_extract_files -o ubi_files ubi.img     # extracts each volume's files
# if a volume is itself a squashfs blob, carve+unsquashfs it (as §2)
ROOTFS=$(dirname "$(find ubi_files -path '*/usr/sbin/uhttpd' -o -path '*/bin/busybox' | head -1)")/..
```

## 4. JFFS2 / CramFS

```bash
# JFFS2
jefferson -d rootfs firmware_jffs2.img
# CramFS
mkdir rootfs && cramfsck -x rootfs firmware_cramfs.img
```

## 5. Vendor obfuscation (know the traps)

- **Tenda obfuscated SquashFS** — superblock magic is `nice` instead of `hsqs`, and the
  XZ stream magic is rewritten to `Tenda`. Patch the magics back before unsquashfs, or
  use a small de-obfuscator (`extract_squashfs.py` pattern: restore `hsqs` + XZ `\xfd7zXZ`).
- **Obfuscated Lua bytecode (Cudy LuCI `apprpc/*.lua`, `controller/*.lua`)** — Lua 5.1
  `.luac` with tweaked constant tags (e.g. int tag 9 for int32). Decompile with
  `unluac`:
  ```bash
  java -jar unluac.jar rootfs/usr/lib/lua/luci/apprpc/net.lua > net.lua
  ```
  Decompile the whole controller set: the RPC dispatcher (`controller/rpc.lua`), the
  method→module map (`app.lua`), the JSON-RPC caller (`jsonrpc.lua`), the executor
  (`sys.lua` → `fork_exec` → `nixio.exec("/bin/sh","-c",…)`), and each `apprpc/*.lua`
  handler. Read variable roles from the register names (`A0_2` = first arg, etc).
- **Encrypted images** — flat high entropy with no signatures. Look for a bootloader/
  updater that decrypts (key/IV in a binary), a plaintext older release to diff, or a
  known vendor key. If none, this target is blocked without hardware (UART/flash dump).

## 6. RTOS / monolith (no filesystem — e.g. TP-Link TPOS on Archer A8)

Some devices run a single flat firmware with no Linux/SquashFS (an asset "MINIFS" holds
web assets, but there is no rootfs and often **no shell** — `system`/`popen`/`sh` absent,
so classic command injection is impossible). Approach:
- Carve the code image; identify the load base (reset vector / string cross-refs).
- `idb_open` the monolith at the correct base (IDA: `base = load_addr`;
  `VA = base + file_offset`). Analyze the CWMP/UPnP/discovery parsers as functions in one
  address space.
- Bug classes shift to memory-safety (bounded copies?) and protocol logic, not shell.

## 7. Go / Node / compiled-app backends (e.g. TerraMaster TOSDaemon)

- A **Go** daemon decompiles in IDA with symbols often retained (package.method names);
  look for `gin`/`gorm`/`net/http` route registration, `os/exec.Command`, and
  `fmt.Sprintf` templates feeding a shell. Auth is often middleware attached per route —
  find the route group that lacks the login middleware.
- **Update vs factory image**: an update/app package frequently lacks the glibc base,
  bundled Postgres/Redis, and the seeded DB schema — enough to *analyze* statically and
  even reach startup dynamically, but **not** to fully boot (gorm migrations fail on a
  missing schema). For a full live PoC, obtain the **factory image**.

## 8. Confirm you're on the latest

`cat etc/openwrt_release` / `etc/VERSION` / `etc/os-release` / a web-UI version string.
Cross-check against the vendor's current download-page build. A finding only counts if
it's present in the newest release.
