# Firmware Identification

Techniques for determining architecture, OS/RTOS, bootloader, compiler, and hardware platform from firmware images and binaries.

---

## Architecture Detection

### From ELF Headers

The most reliable method when ELF binaries are available:

```bash
# Quick architecture check
file <binary>

# Detailed ELF header
readelf -h <binary> 2>/dev/null
```

**ELF Machine field mapping:**

| Machine | Architecture | Common Robot Use |
|---------|-------------|-----------------|
| `EM_ARM` (40) | ARM 32-bit | Most robot controllers, cobots |
| `EM_AARCH64` (183) | ARM 64-bit (AArch64) | Modern platforms, Jetson, RPi4+ |
| `EM_MIPS` (8) | MIPS | Network devices, some PLCs |
| `EM_386` (3) | x86 (32-bit) | Industrial PCs |
| `EM_X86_64` (62) | x86_64 | Vision systems, industrial PCs |
| `EM_PPC` (20) | PowerPC | Legacy industrial, some PLCs |
| `EM_RISCV` (243) | RISC-V | Emerging embedded platforms |

```bash
# Check endianness from ELF
readelf -h <binary> 2>/dev/null | grep 'Data'
# "2's complement, little endian" → LE
# "2's complement, big endian" → BE

# Check for ARM Thumb mode
readelf -h <binary> 2>/dev/null | grep 'Entry point'
# Odd entry point address → Thumb mode (bit 0 set)

# ARM-specific flags
readelf -A <binary> 2>/dev/null | head -20
# Shows: architecture version, FPU, ABI
```

### Opcode Frequency Analysis (for Stripped/Raw Binaries)

When no ELF header is present (raw firmware dumps):

```bash
# ARM detection — look for common ARM instruction patterns
# ARM prologues: PUSH {r4-r11, lr} = 0xe92d____
hexdump -C <firmware.bin> | grep -c 'e9 2d' | head -1  # ARM LE
hexdump -C <firmware.bin> | grep -c '2d e9' | head -1  # ARM BE

# ARM Thumb prologues: PUSH {r4-r7, lr} = 0xb5__
hexdump -C <firmware.bin> | grep -c 'b5 [0-9a-f][0-9a-f]' | head -1

# MIPS detection — look for common MIPS instructions
# addiu sp, sp, -N = 0x27bd____
hexdump -C <firmware.bin> | grep -c '27 bd' | head -1  # MIPS BE
hexdump -C <firmware.bin> | grep -c 'bd 27' | head -1  # MIPS LE

# x86 detection — look for function prologues
# push ebp; mov ebp, esp = 0x55 0x89 0xe5
hexdump -C <firmware.bin> | grep -c '55 89 e5' | head -1

# RISC-V detection — look for common patterns
# addi sp, sp, -N
hexdump -C <firmware.bin> | grep -c '13 01' | head -1  # RV32

# PowerPC detection
# stwu r1, -N(r1) = 0x9421____
hexdump -C <firmware.bin> | grep -c '94 21' | head -1
```

**Architecture-specific instruction patterns:**

```bash
# Use binwalk opcode scan
binwalk -A <firmware.bin>
# This scans for architecture-specific patterns and reports best matches

# Use r2 to attempt analysis at different architectures
for arch in arm arm.gnu mips x86 ppc riscv; do
  echo "=== Testing $arch ==="
  r2 -a $arch -b 32 -c 'aa; afl | wc -l' -q <firmware.bin> 2>/dev/null
done
# Highest function count likely = correct architecture
```

### ARM Cortex-M Vector Table Detection

ARM Cortex-M processors have a distinctive vector table at offset 0:

```bash
# Check first 8 words (32 bytes) — vector table
hexdump -C <firmware.bin> | head -2

# Word 0: Initial SP (should be RAM address: 0x20000000-0x20040000 for STM32)
# Word 1: Reset handler (should be in flash: 0x08000000+ for STM32)
# Word 2: NMI handler
# Word 3: HardFault handler

python3 -c "
import struct
with open('<firmware.bin>', 'rb') as f:
    data = f.read(64)
    vectors = struct.unpack('<16I', data)
    names = ['Initial SP', 'Reset', 'NMI', 'HardFault', 'MemManage', 'BusFault',
             'UsageFault', 'Reserved', 'Reserved', 'Reserved', 'Reserved',
             'SVCall', 'Debug', 'Reserved', 'PendSV', 'SysTick']
    for i, (name, addr) in enumerate(zip(names, vectors)):
        print(f'  [{i:2d}] {name:12s}: 0x{addr:08x}')

    # Heuristic: valid Cortex-M if SP is in RAM range and Reset is in Flash
    sp = vectors[0]
    reset = vectors[1]
    if 0x20000000 <= sp <= 0x20100000 and 0x08000000 <= reset <= 0x08200000:
        print('  -> Likely STM32 Cortex-M')
    elif 0x20000000 <= sp <= 0x20100000 and reset < 0x00100000:
        print('  -> Likely NXP/Atmel Cortex-M')
"
```

---

## OS/RTOS Identification

### String-Based Detection

```bash
# Comprehensive OS/RTOS string search
strings -n 6 <firmware_or_binary> | grep -iE \
  '(linux version|linux kernel|busybox|buildroot|openwrt|yocto|poky|ubuntu|debian|raspbian|
    vxworks|wind river|tornado|
    freertos|free rtos|
    qnx neutrino|qnx|
    threadx|azure rtos|
    zephyr|
    nuttx|
    rtems|
    chibiOS|chibios|
    mbed|arm mbed|
    riot.os|riot-os|
    contiki|
    nucleus|
    ecos|
    ros[^a-z]|ros2|robot.operating.system|roslaunch|roscore|rclcpp|rclpy|ament|colcon)' | sort -u | head -30
```

**OS-specific identification strings:**

| OS/RTOS | Identifying Strings | Notes |
|---------|-------------------|-------|
| **Linux** | `Linux version`, `Linux kernel`, `/proc/`, `/sys/` | Check kernel version for CVEs |
| **VxWorks** | `VxWorks`, `Wind River`, `WIND`, `wdbAgent` | Symbol table often present |
| **FreeRTOS** | `FreeRTOS`, `xTaskCreate`, `vTaskDelay`, `pvPortMalloc` | API function names in strings |
| **QNX** | `QNX`, `Neutrino`, `procnto`, `/dev/shmem` | Microkernel, IPC-heavy |
| **ThreadX** | `ThreadX`, `Azure RTOS`, `tx_thread_create` | API prefixed with `tx_` |
| **Zephyr** | `zephyr`, `CONFIG_`, `k_thread_create`, `k_sem_give` | API prefixed with `k_` |
| **NuttX** | `NuttX`, `nsh>`, `CONFIG_` | POSIX-like RTOS |
| **ROS** | `roscore`, `roslaunch`, `rospy`, `roscpp` | Robot Operating System 1 |
| **ROS2** | `rclcpp`, `rclpy`, `rmw_`, `ament_`, `ros2`, `colcon` | Robot Operating System 2 |

### Filesystem-Based Detection

When firmware is extracted to a filesystem:

```bash
# Linux detection
[ -f etc/os-release ] && cat etc/os-release
[ -f etc/issue ] && cat etc/issue
[ -f proc/version ] && cat proc/version
ls lib/modules/*/build 2>/dev/null  # Kernel modules → Linux

# BusyBox version
strings usr/bin/busybox 2>/dev/null | grep 'BusyBox v' | head -1
./usr/bin/busybox 2>/dev/null | head -1  # If same arch

# ROS/ROS2 detection
ls opt/ros/ 2>/dev/null             # ROS installation directory
find . -name 'setup.bash' -path '*/ros/*' 2>/dev/null
find . -name 'package.xml' 2>/dev/null | head -10

# VxWorks detection
strings <firmware> | grep -c 'vx[A-Z]'  # VxWorks API naming convention
```

### Binary API Detection

For stripped binaries, imported function names reveal the RTOS:

```bash
# Check dynamic symbols for RTOS API
readelf -s <binary> 2>/dev/null | grep -iE \
  '(xTaskCreate|vTaskDelay|xQueueSend|xSemaphore|  # FreeRTOS
    tx_thread|tx_queue|tx_semaphore|tx_mutex|        # ThreadX
    k_thread|k_sem|k_msgq|k_timer|                   # Zephyr
    taskSpawn|semTake|msgQSend|wdStart|               # VxWorks
    pthread_create|sem_wait|mq_send|                  # POSIX (Linux/QNX/NuttX)
    ros::init|ros::NodeHandle|                        # ROS
    rclcpp::init|rclcpp::Node)' | head -20
```

---

## Bootloader Identification

```bash
# U-Boot detection
strings <firmware_path> | grep -iE '(u-boot|u_boot|uboot|das u-boot)' | head -5
# U-Boot version string
strings <firmware_path> | grep 'U-Boot [0-9]' | head -3
# U-Boot environment
strings <firmware_path> | grep -E '^boot(cmd|args|delay)=' | head -10

# Barebox detection
strings <firmware_path> | grep -i 'barebox' | head -5

# RedBoot detection
strings <firmware_path> | grep -i 'redboot' | head -5

# GRUB detection
strings <firmware_path> | grep -i 'grub' | head -5

# Custom bootloader — look for boot messages
strings <firmware_path> | grep -iE '(boot|starting|init|load|firmware|version)' | head -20
```

**U-Boot version → vulnerability mapping:**

| U-Boot Version | Known Issues |
|---------------|-------------|
| < 2018.01 | No verified boot by default |
| < 2019.07 | CVE-2019-13103 to CVE-2019-13106 (ext4, misc overflow) |
| < 2022.04 | Various overflow in image parsing |

---

## Compiler and Toolchain Detection

```bash
# GCC version from strings
strings <binary> | grep -E 'GCC:.*[0-9]+\.[0-9]+\.[0-9]+' | head -5

# GCC comment sections
readelf -p .comment <binary> 2>/dev/null

# IAR detection
strings <binary> | grep -i 'iar' | head -5

# Keil / ARMCC detection
strings <binary> | grep -iE '(keil|armcc|arm compiler)' | head -5

# LLVM/Clang detection
strings <binary> | grep -iE '(clang|llvm)' | head -5

# Linker identification
readelf -d <binary> 2>/dev/null | grep -i 'needed\|soname'
readelf -l <binary> 2>/dev/null | grep 'interpreter' | head -1
# /lib/ld-linux-armhf.so.3 → ARM hard-float Linux
# /lib/ld-musl-armhf.so.1 → musl libc (Alpine, Buildroot)

# Build system artifacts
strings <binary> | grep -iE '(buildroot|yocto|poky|openwrt|cmake|meson|make)' | head -10
```

**Compiler version → security implications:**

| Compiler | Version | Security Notes |
|----------|---------|---------------|
| GCC < 4.9 | No `-fstack-protector-strong` | Weaker stack protection |
| GCC < 8.0 | No `-fcf-protection` | No control flow integrity |
| GCC < 12.0 | No `-ftrivial-auto-var-init` | Uninitialized variable risk |
| IAR | Any | Often no ASLR/NX in output |
| Keil/ARMCC | Any | Bare-metal, no OS protections |

---

## Hardware Platform Identification

### SoC Detection from DTB

```bash
# Extract and analyze Device Tree
dtc -I dtb -O dts <dtb_file> 2>/dev/null | grep 'compatible' | head -10

# Common robot SoC identifiers:
# "nvidia,tegra210" → NVIDIA Jetson TX1/Nano
# "nvidia,tegra186" → NVIDIA Jetson TX2
# "nvidia,tegra194" → NVIDIA Jetson Xavier
# "ti,am335x" → TI AM335x (BeagleBone)
# "ti,am5728" → TI AM5728 (robot controllers)
# "nxp,imx6" → NXP i.MX6 (many robots)
# "nxp,imx8m" → NXP i.MX8M (modern robots)
# "st,stm32" → STMicroelectronics STM32
# "brcm,bcm2835" → Broadcom BCM2835 (Raspberry Pi)
# "xlnx,zynq" → Xilinx Zynq (FPGA+ARM, industrial)
# "qcom,sdm845" → Qualcomm SDM845 (mobile robots)
```

### Peripheral Register Ranges

For bare-metal firmware, peripheral base addresses identify the SoC:

```bash
python3 -c "
# Common peripheral base addresses
soc_signatures = {
    0x40000000: 'STM32 (APB1 peripherals)',
    0x40010000: 'STM32 (APB2 peripherals)',
    0x48000000: 'STM32 (AHB1/GPIO)',
    0x50000000: 'STM32 (AHB2/AHB3)',
    0x44E00000: 'TI AM335x (PRCM)',
    0x44E09000: 'TI AM335x (UART0)',
    0x01C20000: 'Allwinner (CCU)',
    0x01C28000: 'Allwinner (UART0)',
    0x3F200000: 'BCM2835/RPi (GPIO)',
    0x3F201000: 'BCM2835/RPi (UART0)',
    0x020C4000: 'NXP i.MX6 (CCM)',
    0x70006000: 'NVIDIA Tegra (UARTA)',
}

import struct
with open('<firmware.bin>', 'rb') as f:
    data = f.read()

for offset in range(0, min(len(data), 0x10000), 4):
    val = struct.unpack('<I', data[offset:offset+4])[0]
    if val in soc_signatures:
        print(f'  Offset 0x{offset:08x}: 0x{val:08x} → {soc_signatures[val]}')
" 2>/dev/null
```

### Robot Vendor Signatures

```bash
# Robot manufacturer identification
strings <firmware_or_binary> | grep -iE \
  '(universal.robot|ur[35]e?[0-9]*|urscript|
    kuka|krl|sunrise|iiwa|
    abb|rapid|robotstudio|irc5|
    fanuc|karel|tp_|
    yaskawa|motoman|motoplus|
    denso|cobotta|
    dobot|
    franka|panda|libfranka|
    clearpath|jackal|husky|
    boston.dynamics|spot|
    dji|phantom|mavic|matrice|
    irobot|roomba|create|
    softbank|pepper|nao|
    fetch|freight|
    turtlebot|
    mir[0-9]|mobile.industrial.robot|
    omron|ld[- ][0-9]|
    locus|
    6river|
    vecna|
    otto|
    waymo|
    nuro)' | sort -u | head -20
```

---

## Identification Summary Template

After completing identification, record findings in this format:

```
## Firmware Identification Results

- **File:** [filename]
- **SHA256:** [hash]
- **Size:** [size]
- **Architecture:** [ARM 32-bit LE / ARM64 LE / MIPS BE / x86_64 / RISC-V / PowerPC]
- **Instruction Set:** [ARMv7 / ARMv8 / MIPS32 / etc.] [Thumb / Thumb2 if ARM]
- **OS/RTOS:** [Linux 5.4 / VxWorks 7 / FreeRTOS 10.4 / QNX 7.1 / bare-metal]
- **Bootloader:** [U-Boot 2020.04 / Barebox / custom / N/A]
- **Compiler:** [GCC 9.3.0 / IAR 8.50 / Keil MDK 5.37]
- **Libc:** [glibc 2.31 / musl 1.2.2 / newlib 4.1 / uClibc-ng 1.0.39]
- **SoC/Platform:** [STM32F407 / NXP i.MX8M / Jetson Nano / BCM2711]
- **Robot Platform:** [UR5e / KUKA iiwa / custom AGV / N/A]
- **Security Posture:** [NX: yes/no, ASLR: yes/no, Stack Canary: yes/no, PIE: yes/no, RELRO: full/partial/no]
```

This information feeds directly into all subsequent analysis phases — architecture determines disassembly settings, OS determines vulnerability patterns, and platform determines robot-specific checks.
