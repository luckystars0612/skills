# LegacyHive — User Profile Service Arbitrary Hive Load LPE

## Target
- **Service:** User Profile Service (profsvc.dll / svchost.exe)
- **Privilege:** Load another user's registry hive into attacker's session
- **Prerequisites:** Credentials for another standard user + a third username

## Vulnerability class
Symlink + oplock race against the User Profile Service's hive-loading logic. UPS
follows a poisoned registry value to load an arbitrary hive path, giving the attacker
read/write access to another user's HKCU.

## Technique chain

### Stage 1 — Offline hive poisoning (offreg.lib)
```cpp
OROpenHiveByHandle(hNtuserDat, &hHive)  // open target user B's ntuser.dat
OROpenKey(hHive, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", &hKey)
ORSetValue(hKey, L"Local AppData", REG_EXPAND_SZ,
    L"\\\\?\\globalroot\\BaseNamedObjects\\Restricted", ...)
ORSaveHive(hHive, outputPath, OsMajorVersion, OsMinorVersion)
```
This sets user B's `Local AppData` shell folder to an object-manager path that the
attacker controls.

### Stage 2 — Object namespace setup
```cpp
NtCreateDirectoryObjectEx(&hDir, ..., L"\\BaseNamedObjects\\Restricted",
    ..., shadowDirHandle)
NtCreateSymbolicLinkObject(&hSymlink, ..., L"\\BaseNamedObjects\\Restricted\\target",
    &targetUserHivePath)
```
Build a directory structure in the object namespace that will redirect UPS's path
resolution to the target user's hive.

### Stage 3 — Oplock race on UsrClass.dat
```cpp
FSCTL_REQUEST_BATCH_OPLOCK on copied UsrClass.dat
```
When UPS opens UsrClass.dat for user B's profile load, the oplock fires, giving the
attacker a window to swap symlinks.

### Stage 4 — Trigger via CreateProcessWithLogonW
```cpp
CreateProcessWithLogonW(userB, domain, passwordB, LOGON_WITH_PROFILE, ...)
```
This triggers UPS to load user B's profile. UPS reads the poisoned `Local AppData`
shell folder → follows the object-manager path → loads the hive from the symlinked
location (which is the target user's actual hive, not user B's).

### Result
The target user's registry hive is mounted under the attacker's `HKCU\Software\Classes`
(via UsrClass.dat association), giving full read/write access to another user's registry.

## Key techniques from source

### offreg.lib — offline registry editing
Same library used in PrettyPrague and ShieldCrash. Allows editing a hive file without
mounting it — no privilege required, just file access.

### NtCreateDirectoryObjectEx with shadow
The shadow directory parameter creates an object directory that inherits entries from
another directory but allows the attacker to add/override specific entries. Critical for
building redirects that pass path-validation checks.

### Batch oplock for race synchronization
`FSCTL_REQUEST_BATCH_OPLOCK` (legacy oplock) — fires when any process opens the file
with a non-compatible sharing mode. Simpler than `FSCTL_REQUEST_OPLOCK` but limited to
one oplock per file.

## Hunt generalization
1. **Profile service interactions:** Any service that loads user profiles based on
   registry values is potentially vulnerable to hive-value poisoning
2. **Shell folder redirection:** `User Shell Folders` values are trusted paths —
   poisoning them redirects any component that resolves shell folders
3. **Cross-user hive access:** If you can edit another user's ntuser.dat (standard user
   can if the other user's profile directory has weak ACLs), you can poison it
4. **CreateProcessWithLogonW as trigger:** This API forces profile load for any user
   whose credentials you have — universal trigger for UPS bugs
