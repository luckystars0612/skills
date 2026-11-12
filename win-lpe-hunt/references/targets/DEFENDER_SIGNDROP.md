# SignDrop — CLFS Authentication Mitigation → Arbitrary File Create as SYSTEM

## Target
- **Binary:** clfs.sys (kernel) + MsMpEng.exe (confused deputy)
- **Privilege:** NT AUTHORITY\SYSTEM
- **Estimated impact:** ~80% of Windows installations

## Vulnerability class
Logic flaw in CLFS authentication mitigation (introduced Oct 2025 to protect log files).
The security mitigation itself becomes the attack vector.

## Technique chain

### Background: CLFS authentication
Since Oct 2025, clfs.sys creates `.cnpf` authentication files alongside `.blf` log files.
These files contain cryptographic signatures to prevent memory corruption via crafted logs.

### Privileged operation — CLFS container association + `.cnpf` creation
1. User creates a log via `\CLFS\??\<path>` (NtCreateFile with CLFS prefix)
2. User associates a container via `AddLogContainer` / `DeviceIoControl(0x8007A808)`
   specifying a path like `\BaseNamedObjects\Restricted\<GUID>`
3. CLFS creates the container and its `.cnpf` file under the calling user's context (OK)
4. **The bug:** if another process later opens the same `.blf`, CLFS re-opens associated
   containers. If an associated container file is empty and its `.cnpf` is missing, CLFS
   creates a NEW `.cnpf` **in the opener's context** — not the original creator's context.

### Redirect — object-manager symlinks
```cpp
// Symlink container path → user-controlled temp dir
NtCreateSymbolicLinkObject(\BaseNamedObjects\Restricted\<GUID>, workdir\<GUID2>)
// Symlink .cnpf path → target write location
NtCreateSymbolicLinkObject(\BaseNamedObjects\Restricted\<GUID>.cnpf, target_path)
```
After the log + container are set up, attacker swaps the `.cnpf` symlink to point at the
desired write target (e.g., `C:\Program Files\Common Files\microsoft shared\ink\hid.dll`).

### Confused deputy — coerce Defender to open the CLFS log
```cpp
// RPC call to Defender's signature update
Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL,
    "\\\\.\\GlobalRoot\\BaseNamedObjects\\Restricted\\<GUID3>", &errstat)
```
The symlink `<GUID3>` points to the workdir containing `MpEngine.dll` (bait) and the CLFS
`.blf` (with associated container path `\BaseNamedObjects\Restricted\mpasbase.vdm`).

MsMpEng opens the `.blf` → CLFS re-opens the associated container → `.cnpf` is missing →
CLFS creates `.cnpf` **as SYSTEM** at the symlinked target path.

### Race-win — oplock on bait file
Oplock on `MpEngine.dll` in the workdir fires when Defender accesses it. In the callback,
attacker swaps the CLFS `.cnpf` symlink from the temp path to the real target. Then closes
the oplock to let Defender (and CLFS) proceed.

### Key property: DACL inheritance
CLFS creates the `.cnpf` with the **original container file's DACL** — which is the
attacker's file with full permissions. So the SYSTEM-created file at the target path is
writable by the attacker.

### SYSTEM conversion — DLL plant
The created file lands in `C:\Program Files\Common Files\microsoft shared\ink\hid.dll`.
Attacker writes payload DLL content, then triggers `osk.exe` (On-Screen Keyboard) which
loads `hid.dll` from that directory → code execution. Final shell via `runas conhost.exe`.
Uses `CreateTransaction`/`DeleteFileTransacted` for atomic cleanup.

## Unique properties
1. **Bypasses ALL AV/EDR self-protection:** the file creation comes from the AV's own
   process, so kernel drivers (WdFilter, klif.sys, etc.) allow it
2. **Works against any AV:** just change the coercion target from Defender to another engine
3. The CLFS mitigation itself (learning mode / enforcement mode) must be enabled for the
   bug to exist — disabling it exposes older memory corruption bugs

## Vulnerability check
```
HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication\Mode
  0 or 1 → vulnerable (learning or enforcement)
  2 or 3 → not vulnerable
```

## Hunt generalization
- Any kernel driver that creates files on behalf of an opener (not the original creator)
- Look for `ZwCreateFile`/`IoCreateFile` paths where the caller identity changes between
  initial setup and later re-open
- CLFS container association is a reusable primitive for coercing any privileged log-opener
