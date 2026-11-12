# BigDiskBuster — Windows Defender Update DoS

## Target
- **Binary:** MsMpEng.exe update subsystem
- **Type:** Denial of Service (signature/platform update prevention)
- **Privilege required:** Standard user

## Vulnerability class
Resource exhaustion attack on Defender's update mechanism.

## Technique

### Mechanism
1. Monitor `ProgramData\Microsoft\Windows Defender\Platform\` and `Definition Updates\`
   using `ReadDirectoryChangesW` for `FILE_ACTION_ADDED` / `FILE_ACTION_MODIFIED`
2. When Defender creates new update directories (GUID-named or version-named):
   - Query free disk space via `NtQueryVolumeInformationFile(FileFsFullSizeInformation)`
   - Allocate the entire free space in hidden temp files:
     `NtCreateFile(AllocationSize=FreeSpace, FILE_ATTRIBUTE_HIDDEN|FILE_DELETE_ON_CLOSE)`
3. Defender cannot write update files → update fails → Defender rolls back the directory
4. PoC detects the rollback (directory deletion), releases the disk space, waits for retry

### Additional technique
- Lock `MRT.exe` (Malicious Software Removal Tool) with `FILE_SHARE_READ` only →
  prevents engine binary replacement

### Result
Machine permanently runs stale signatures. The PoC loops forever, blocking every update
attempt while appearing idle between attempts.

## Hunt generalization
Any security product that writes updates to the system drive without pre-reserving space
or using a dedicated partition is vulnerable to this pattern. Check:
- Where does the product store signature/engine updates?
- Does it verify available space atomically?
- Can a standard user exhaust the target volume?
