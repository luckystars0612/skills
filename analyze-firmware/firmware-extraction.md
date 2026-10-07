# Firmware Extraction

Techniques for unpacking firmware images, extracting filesystems, and handling bootloader formats. All procedures assume binwalk v3.x (snap install).

---

## Entropy Analysis

Entropy analysis reveals the structure of firmware images before extraction.

```bash
# Generate entropy plot
binwalk -E <firmware_path>
```

**Interpreting entropy:**

| Entropy Pattern | Interpretation | Action |
|----------------|----------------|--------|
| Uniformly high (~0.99) | Encrypted or heavily compressed | Try decryption (crypto-analysis.md), check for known encryption headers |
| High regions + low gaps | Compressed sections within structured firmware | Normal firmware, proceed with extraction |
| Uniformly low (~0.3-0.6) | Uncompressed code/data | Raw binary, bare-metal, or uncompressed filesystem |
| Rising entropy | Data section follows code | Common in bare-metal firmware |
| Periodic patterns | Repeated structures | Possible block-level encryption or repeated data |

**Identifying encrypted regions:**
```bash
# Check for encryption headers
binwalk <firmware_path> | grep -iE '(aes|des|encrypt|cipher|crypto)'

# Look for known encryption signatures
hexdump -C <firmware_path> | head -16  # Check first bytes for format headers

# Calculate entropy of specific region
dd if=<firmware_path> bs=1 skip=<offset> count=<size> 2>/dev/null | \
  python3 -c "import sys,math; d=sys.stdin.buffer.read(); e=-sum(c/len(d)*math.log2(c/len(d)) for c in [d.count(bytes([b])) for b in range(256)] if c); print(f'Entropy: {e:.4f}')"
```

---

## binwalk v3.x Extraction

### Basic Operations

```bash
# Signature scan (list contents without extracting)
binwalk <firmware_path>

# Architecture detection via opcode signatures
binwalk -A <firmware_path>

# Recursive extraction (primary method)
binwalk -Me <firmware_path>

# Extract to specific directory
binwalk -Me -C /tmp/fw_extract <firmware_path>
```

### binwalk v3.x vs v2.x Differences

| Feature | v2.x | v3.x |
|---------|------|------|
| Install | `pip install binwalk` | `snap install binwalk` or build from source |
| Extraction | `-e` or `-Me` | `-Me` (same syntax) |
| Entropy | `-E` | `-E` (same syntax) |
| Config | `~/.config/binwalk/` | Snap-confined paths |
| Plugins | Python plugins | Limited plugin support |
| Dependencies | `sasquatch`, `jefferson` auto-installed | Must install separately |

### Post-Extraction Analysis

```bash
# Survey extracted contents
find _<firmware_name>.extracted/ -type f | wc -l   # Total file count
find _<firmware_name>.extracted/ -type f -executable | head -20  # Executables
find _<firmware_name>.extracted/ -name '*.so' -o -name '*.a' | head -20  # Libraries
find _<firmware_name>.extracted/ -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.json' -o -name '*.xml' -o -name '*.yaml' | head -20  # Configs

# Find the root filesystem (look for etc/passwd)
find _<firmware_name>.extracted/ -name 'passwd' -path '*/etc/*' 2>/dev/null

# Identify architecture of extracted binaries
file _<firmware_name>.extracted/$(find _<firmware_name>.extracted/ -type f -executable -print -quit 2>/dev/null)
```

---

## Filesystem Extraction

### SquashFS

Most common Linux firmware filesystem.

```bash
# Check SquashFS details
unsquashfs -s <squashfs_image>

# Extract SquashFS
unsquashfs -d /tmp/squashfs_root <squashfs_image>

# If standard unsquashfs fails (vendor-modified SquashFS):
# Install sasquatch for non-standard SquashFS
# git clone https://github.com/devttys0/sasquatch && cd sasquatch && ./build.sh
sasquatch <squashfs_image> -d /tmp/squashfs_root 2>/dev/null
```

**Common SquashFS offsets:** binwalk will find these, but manual extraction:
```bash
# Find SquashFS magic in firmware
grep -boa 'hsqs\|sqsh' <firmware_path> | head -5

# Extract at offset
dd if=<firmware_path> bs=1 skip=<offset> of=/tmp/squashfs.img
unsquashfs -d /tmp/root /tmp/squashfs.img
```

### JFFS2

Common in NOR flash-based devices.

```bash
# Create JFFS2 mount point (requires root)
modprobe mtdram total_size=65536 erase_size=256
modprobe mtdblock
dd if=<jffs2_image> of=/dev/mtdblock0
mkdir -p /tmp/jffs2_mount
mount -t jffs2 /dev/mtdblock0 /tmp/jffs2_mount

# Alternative: jefferson (pure Python JFFS2 extractor)
# pip install jefferson
jefferson <jffs2_image> -d /tmp/jffs2_root
```

**Note:** jefferson may not be installed. Install with: `pip install jefferson`

### UBIFS

Common in NAND flash-based devices.

```bash
# Extract UBI image
# pip install ubi_reader
ubireader_extract_images <ubi_image>
ubireader_extract_files <ubi_image> -o /tmp/ubi_root

# Manual UBI extraction
modprobe nandsim first_id_byte=0x2c second_id_byte=0xda third_id_byte=0x90 fourth_id_byte=0x95
flash_erase /dev/mtd0 0 0
ubiformat /dev/mtd0 -f <ubi_image>
ubiattach -p /dev/mtd0
mount -t ubifs ubi0:rootfs /tmp/ubi_mount
```

**Note:** `ubi_reader` may not be installed. Install with: `pip install ubi_reader`

### CPIO

Common in initramfs/initrd and embedded firmware.

```bash
# List contents
cpio -t < <cpio_archive>

# Extract
mkdir -p /tmp/cpio_root && cd /tmp/cpio_root
cpio -idm < <cpio_archive>

# Handle gzipped cpio (common for initramfs)
zcat <cpio_archive.gz> | cpio -idm

# Handle xz-compressed cpio
xzcat <cpio_archive.xz> | cpio -idm
```

### cramfs

Compressed ROM filesystem, common in older embedded devices.

```bash
# Extract cramfs
mkdir -p /tmp/cramfs_root
cramfsck -x /tmp/cramfs_root <cramfs_image>

# Or mount (requires root)
mount -t cramfs -o loop <cramfs_image> /tmp/cramfs_mount
```

### ext4 / ext2 / ext3

```bash
# Mount (requires root)
mkdir -p /tmp/ext_mount
mount -o loop,ro <ext_image> /tmp/ext_mount

# Extract without root using debugfs
debugfs <ext_image> -R 'ls -l /' 2>/dev/null
debugfs <ext_image> -R 'rdump / /tmp/ext_root' 2>/dev/null
```

### FAT / VFAT

```bash
# Mount
mkdir -p /tmp/fat_mount
mount -o loop,ro <fat_image> /tmp/fat_mount

# Extract without root
mtools -i <fat_image> mdir ::
mcopy -s -i <fat_image> :: /tmp/fat_root
```

### YAFFS2

Common in NAND flash (Android, embedded Linux).

```bash
# pip install yaffshiv
yaffshiv -d /tmp/yaffs_root <yaffs_image>

# Alternative: unyaffs
unyaffs <yaffs_image> /tmp/yaffs_root
```

### romfs

Simple read-only filesystem.

```bash
# Mount
mount -t romfs -o loop,ro <romfs_image> /tmp/romfs_mount

# Extract with genromfs tools
# Or use binwalk extraction
```

---

## Bare-Metal Firmware Formats

### Intel HEX (.hex, .ihx)

```bash
# Convert Intel HEX to raw binary
objcopy -I ihex -O binary <firmware.hex> <firmware.bin>

# Or with Python
python3 -c "
from intelhex import IntelHex
ih = IntelHex('<firmware.hex>')
ih.tobinfile('<firmware.bin>')
print(f'Start address: 0x{ih.minaddr():08x}')
print(f'End address: 0x{ih.maxaddr():08x}')
print(f'Entry point: 0x{ih.start_addr.get(\"EIP\", ih.start_addr.get(\"IP\", 0)):08x}')
"

# Quick analysis of HEX file
head -5 <firmware.hex>  # Check format
grep -c ':' <firmware.hex>  # Line count
```

### S-Record (.srec, .s19, .s28, .s37)

```bash
# Convert S-Record to raw binary
objcopy -I srec -O binary <firmware.srec> <firmware.bin>

# Quick analysis
head -5 <firmware.srec>
# S0 = header, S1/S2/S3 = data (16/24/32-bit addr), S7/S8/S9 = end
```

### Raw Binary with Load Address

For raw binary dumps (e.g., from SPI flash), you need to determine the load address:

```bash
# Common load addresses by architecture
# ARM Cortex-M: 0x08000000 (STM32), 0x00000000 (NXP), 0x00400000 (Atmel SAM)
# ARM Linux: 0x80008000, 0x40008000
# MIPS: 0x80000000, 0xBFC00000 (reset vector)

# Analyze with r2 at specific load address
r2 -a arm -b 32 -m 0x08000000 <firmware.bin>

# Extract vector table (ARM Cortex-M, first 16 words)
hexdump -C <firmware.bin> | head -4
# Word 0: Initial Stack Pointer
# Word 1: Reset Handler (entry point)
```

---

## Bootloader Extraction

### U-Boot

```bash
# Identify U-Boot header
hexdump -C <firmware_path> | grep -i "27 05 19 56"

# Parse U-Boot header
binwalk <firmware_path> | grep -i 'u-boot'

# Extract U-Boot image components
# pip install uboot-mimage-tool or use binwalk
dumpimage -l <uboot_image>  # List image contents
dumpimage -T flat_dt -p 0 -o /tmp/kernel <uboot_image>  # Extract kernel
dumpimage -T flat_dt -p 1 -o /tmp/dtb <uboot_image>     # Extract DTB
dumpimage -T flat_dt -p 2 -o /tmp/rootfs <uboot_image>  # Extract rootfs

# Extract U-Boot environment
strings <firmware_path> | grep -A 50 'bootcmd='
strings <firmware_path> | grep -A 50 'bootargs='

# Security-relevant U-Boot env vars
strings <firmware_path> | grep -iE '(bootcmd|bootargs|ethaddr|ipaddr|serverip|gatewayip|loadaddr|console|baudrate|verify)='
```

### ARM Trusted Firmware (ATF)

Multi-stage boot chain separation:

```bash
# ATF Boot Loader stages
# BL1: ROM bootloader (usually not in firmware image)
# BL2: Trusted Boot Firmware
# BL31: Runtime firmware (EL3)
# BL32: Secure-EL1 payload (OP-TEE)
# BL33: Non-secure world bootloader (U-Boot/UEFI)

# Find FIP (Firmware Image Package) header
hexdump -C <firmware_path> | grep -i "aa 55 5a 3c"  # TOC header
binwalk <firmware_path> | grep -i 'arm\|trusted\|fip'

# Extract FIP contents
# pip install fiptool (or build from ATF source)
fiptool unpack <fip_image>
```

---

## Nested and Layered Firmware

### OTA Update Packages

```bash
# Android OTA
# payload.bin uses Chrome OS update format
python3 -c "
# Extract Android OTA payload
import zipfile
with zipfile.ZipFile('<ota.zip>') as z:
    z.extractall('/tmp/ota_extract')
    print([f.filename for f in z.filelist])
"

# Generic OTA (often tar/zip with manifest)
file <ota_package>
binwalk <ota_package>
```

### Encrypted Firmware Blobs

```bash
# Check for known encryption wrappers
hexdump -C <firmware_path> | head -4

# Common patterns:
# - XOR encryption: look for repeating patterns in hexdump
# - AES-CBC: look for 16-byte aligned blocks, IV may precede ciphertext
# - Custom: analyze update utility for decryption logic

# See crypto-analysis.md for detailed decryption approaches
```

### Partition Tables

```bash
# Check for GPT/MBR partition table
fdisk -l <firmware_path> 2>/dev/null

# Extract individual partitions
# Use offsets from fdisk output
dd if=<firmware_path> bs=512 skip=<start_sector> count=<sector_count> of=/tmp/partition.img

# Check for Android sparse images
file <firmware_path> | grep -i sparse
simg2img <sparse_image> <raw_image>  # Convert sparse to raw
```

---

## UEFI Firmware

```bash
# UEFI firmware analysis
# pip install uefi_firmware
python3 -c "
import uefi_firmware
parser = uefi_firmware.AutoParser('<firmware_path>')
if parser.type() is not None:
    firmware = parser.parse()
    firmware.dump('/tmp/uefi_extract')
    firmware.showinfo()
"

# Extract UEFI volumes manually
binwalk <firmware_path> | grep -i 'uefi\|efi\|firmware volume'

# UEFITool (if installed)
# UEFIExtract <firmware_path> all
```

**UEFI structure:**
- **Firmware Volume (FV):** Container for firmware files
- **Firmware File System (FFS):** Files within volumes
- **DXE drivers:** Driver Execution Environment — security-relevant
- **PEI modules:** Pre-EFI Initialization
- **NVRAM:** Non-volatile variables (may contain secrets)

---

## Device Tree Blob (DTB)

```bash
# Find DTB magic (0xd00dfeed) in firmware
grep -boa $'\xd0\x0d\xfe\xed' <firmware_path> | head -5
# Or in little-endian
hexdump -C <firmware_path> | grep 'd0 0d fe ed'

# Extract DTB from firmware
binwalk <firmware_path> | grep -i 'device tree\|flat.*device.*tree\|dtb'

# Decompile DTB to DTS (readable text)
dtc -I dtb -O dts -o /tmp/device_tree.dts <dtb_file>

# Extract useful info from DTS
cat /tmp/device_tree.dts | grep -E '(compatible|model|reg |status)' | head -30

# SoC identification from DTB
grep 'compatible' /tmp/device_tree.dts | head -5
# e.g., "ti,am335x-bone" → TI AM335x SoC (BeagleBone)
# e.g., "nvidia,jetson-nano" → NVIDIA Jetson Nano

# Peripheral identification (security-relevant)
grep -A 2 'uart\|spi\|i2c\|gpio\|ethernet\|usb\|can\|watchdog' /tmp/device_tree.dts | head -40
```

**Security-relevant DTB information:**
- **UART/debug ports:** May expose serial console
- **SPI flash:** Firmware storage, possible physical extraction
- **I2C devices:** Sensors, EEPROMs (may store keys)
- **Watchdog:** Safety timer configuration
- **CAN bus:** Industrial communication
- **Memory regions:** Trusted/secure memory partitions

---

## Troubleshooting Extraction

### Common Issues

| Problem | Solution |
|---------|----------|
| binwalk extracts nothing | Try `binwalk -Me --run-as=root`, check if firmware is encrypted |
| SquashFS extraction fails | Use sasquatch for vendor-modified SquashFS, check endianness |
| JFFS2 won't mount | Check erase block size, try jefferson instead |
| Unknown filesystem | Check `hexdump` for magic bytes, consult firmware documentation |
| Encrypted sections | See crypto-analysis.md, analyze update utility for keys |
| Nested extraction incomplete | Run binwalk again on inner extracted files |

### Verifying Complete Extraction

```bash
# Check extraction completeness
# 1. Compare entropy of original vs extracted
binwalk -E <firmware_path>  # Should show extracted regions

# 2. Verify filesystem has expected structure
ls _<firmware_name>.extracted/*/etc/ 2>/dev/null  # Linux rootfs check
ls _<firmware_name>.extracted/*/usr/ 2>/dev/null

# 3. Count executable files
find _<firmware_name>.extracted/ -type f -executable | wc -l

# 4. Check for remaining compressed/encrypted blocks
binwalk _<firmware_name>.extracted/**/* 2>/dev/null | grep -i 'compress\|encrypt' | head -10
```
