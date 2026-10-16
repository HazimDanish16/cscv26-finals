# FOR02 (forensics, 500pts)

id: `for02`

instancer: False

## Description

[raw.E01](https://files.59.153.245.189.sslip.io/FOR02-6f73dfc9b4a77bb624bd8d1b/raw.E01) (6.8 GB) · mirror: [Google Drive](https://drive.google.com/file/d/1tPDo0HWdMhxlioDRC6uMypeqNHLluvXU/view?usp=drive_link)  
SHA-256: `c98969cbd394ae92f9bf449c1657e7b230a9050daa953dc04950657ee5bd7e24`

A workstation holding internal data was compromised. The attacker wiped the data and overwrote all free disk space to make recovery impossible. It is known that a very important text file once existed on the data partition but no longer does. Recover the full directory path of that file.

Flag format: `CSCV2026{<full_filepath>}`

## Status: candidate found (NOT submitted)
Image: C:\Users\LocalAdmin\Downloads\raw.E01 (sha256 verified). Bare NTFS volume "Data", no partition table (use `-i ewf`, no offset).
Method: MFT records of the target were overwritten by attacker's junk dirs (Recovered/*), so fls shows nothing. Reconstructed from $UsnJrnl:$J (usndump.py) + $MFT (mftdump.py).
- USN: mft=130 `playlist_balladsong.txt` par=129, created 2026-09-07 04:18:47, edited, DELETED 04:54:23.
- par chain at creation: 129 ops_7B <- 128 vault_CA <- 127 proj_F3 <- 126 legal_14 <- 125 Archive <- 5 (root). No renames on any of them.
- Records 126-130 later reused as Recovered / Recovered/hr_57 etc (wipe noise) -> path unrecoverable from MFT alone.
- Decoys: Archive/hr_FD/.../vault_snapshot.bak, Archive/dept_91/.../vault_snapshot.bak, Works/*, Rollout plan 5.txt etc. still have deleted MFT records.
Candidate: `Archive/legal_14/proj_F3/vault_CA/ops_7B/playlist_balladsong.txt`
