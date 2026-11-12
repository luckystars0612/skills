# GreatXML — BitLocker Bypass via WinRE unattend.xml Injection

## Target
- **Component:** Windows Recovery Environment (WinRE)
- **Prerequisite:** Defender Offline Scan was previously initiated on the target machine
- **Access required:** Physical access to the machine

## Vulnerability class
WinRE configuration injection — if Defender Offline Scan has been used, the recovery
partition accepts unattend.xml, which can spawn an unrestricted shell with access to
the unlocked BitLocker volume.

## Technique

### Precondition
Windows Defender Offline Scan (triggered from Windows Security → Virus & Threat
Protection → Scan Options → Microsoft Defender Offline Scan) modifies WinRE's boot
configuration. After this scan has been run at least once, the recovery environment
processes `unattend.xml` from the recovery partition root.

### Attack steps
1. Copy `unattend.xml` + `Recovery\` directory to the recovery partition root
2. Reboot into WinRE (Shift+Restart → Troubleshoot → Advanced → Recovery)
3. During `windowsPE` configuration pass, the unattend.xml executes:
   ```xml
   <RunSynchronous>
       <RunSynchronousCommand>
           <Path>start X:\Windows\System32\conhost.exe</Path>
       </RunSynchronousCommand>
   </RunSynchronous>
   ```
4. `conhost.exe` provides an unrestricted command shell
5. BitLocker volume is unlocked and mounted — full read/write access

### unattend.xml capabilities
The PoC's unattend.xml (generated from schneegans.de) includes:
- `windowsPE` pass: synchronous command execution → shell
- `specialize` pass: PowerShell script execution
- `oobeSystem` pass: account creation (Admin/User), auto-logon
- `FirstLogon` commands: additional post-logon automation

### What the shell can access
- The unlocked `C:\` volume (BitLocker keys are loaded by WinRE)
- `X:\` (WinRE ramdisk — full Windows PE tools)
- All local accounts' files, SAM database, SYSTEM hive
- Can plant persistence (DLLs, scheduled tasks, services)

## Hunt generalization
1. **Recovery partition attack surface:** What configuration files does WinRE
   process? Are there other injection points beyond unattend.xml?
2. **Pre-boot persistence:** After any AV initiates an offline scan, does it
   leave the recovery environment in a more permissive state?
3. **Other AV offline scans:** Kaspersky, ESET, Bitdefender all have offline/
   rescue disk features — do they similarly weaken WinRE configuration?
4. **Secure Boot interaction:** Does Secure Boot prevent unattend.xml injection
   on the recovery partition? (Typically no — the partition is FAT32 and writable)
