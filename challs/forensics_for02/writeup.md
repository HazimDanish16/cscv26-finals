# FOR02 (forensics, 500)

**Status:** solved
**Flag:** `CSCV2026{E:\Archive\legal_14\proj_F3\vault_CA\ops_7B\playlist_balladsong.txt}` (confirmed correct by user on the scoreboard)

## Summary
The attacker wiped the data and overwrote free space, and also reused the MFT records of the target file and its parent folders for junk folders (`Recovered/*`), so `fls` cannot show the path. The NTFS change journal (`$UsnJrnl:$J`) still logs the file's create/delete events with parent MFT references, which lets the folder chain be rebuilt. The drive letter (`E:`) comes from the Recycle Bin `$I` records.

## Files / target
- Files given: `raw.E01` (6.8 GB), sha256 `c98969cbd394ae92f9bf449c1657e7b230a9050daa953dc04950657ee5bd7e24` (verified)
- Image is a bare NTFS volume "Data" with no partition table: use TSK with `-i ewf`, no `-o` offset.
- Kept outside the repo (too large): downloaded to `C:\Users\LocalAdmin\Downloads\raw.E01`.

## Recon / what we observed
- `fsstat -i ewf` shows NTFS, MFT only 512 records. `fls -r -d` lists many deleted files with intact MFT records (`Works/*`, `Documents/*`, `Projects/*`, `Downloads/*`, two `Archive/.../vault_snapshot.bak`). These are decoys: their paths are still known, and the task says the file's trace is gone.
- Text-like deleted files still in the MFT (`Rollout plan 5.txt`, `Contract appendix 13.txt`, `Meeting minutes 35.md`) have records, so they are not "unrecoverable". Ruled out.
- ~250 empty `Recovered/<word>_<hex>` folders are wipe noise created at 04:54:23 and overwrite MFT records 126-130 and 141-256.

## Vulnerability
Overwriting free space and recycling MFT records does not clear `$UsnJrnl:$J`, which records (MFT ref, parent ref, name, reason, time) for every file operation.

## Exploitation steps
1. Verify hash; `img_stat -i ewf`, `fsstat -i ewf raw.E01` (NTFS, no partition table).
2. Extract metadata: `icat -i ewf raw.E01 0 > MFT`, `icat -i ewf raw.E01 39-128-3 > UsnJrnl_J`.
3. Parse the journal (`usndump.py`) and list names whose MFT record number now holds a different name (`mftdump.py` for the MFT). Records 126-130 stand out: at 04:18:47 they were `legal_14`, `proj_F3`, `vault_CA`, `ops_7B`, `playlist_balladsong.txt`, and at 04:54:23 they were deleted and reused as `Recovered`, `audit_26`, `secure_DD`, `ops_6B`, `hr_57`.
4. Rebuild the chain from the journal's parent refs at creation: 130 (par 129) -> 129 `ops_7B` (par 128) -> 128 `vault_CA` (par 127) -> 127 `proj_F3` (par 126) -> 126 `legal_14` (par 125) -> 125 `Archive` (par 5 = root). No RENAME events on any of them.
5. Drive letter: Recycle Bin `$I` records (`$ITRUADM.xlsx` -> `E:\Works\Reports\...`, `$IH19IZ5.exe` -> `E:\winrar-x64-723.exe`) show the volume was `E:`.
6. Flag format wanted the drive letter and backslashes. First attempt without the drive letter (`Archive/legal_14/...`) was rejected.

## Solve script
See `solve.sh` (+ `usndump.py`, `mftdump.py`) in this folder.

## Flag verification
- [x] Submitted and confirmed correct by the user
- Timestamp / round: CSCV26 final, 2026-10-16

## Lessons / patterns for next time
- "Wiped / free space overwritten" does not mean metadata is gone: check `$UsnJrnl:$J`, `$LogFile`, `$I30` slack and Recycle Bin `$I` files.
- When an MFT record number appears in the journal with two different names, the earlier one is what was overwritten. Rebuild paths using parent refs at creation time.
- The flag may want the original Windows path: get the drive letter from `$I` files, LNKs, or the registry. Try `X:\` with backslashes first.
- TSK needs `-i ewf` for E01 here, and `mmls` printing nothing means a bare filesystem (try `fsstat`).
