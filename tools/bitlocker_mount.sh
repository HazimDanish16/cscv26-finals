#!/usr/bin/env bash
# Usage (WSL): tools/bitlocker_mount.sh <volume-image> <recovery-key|password> [password]
#   recovery key form: 48 digits, as 6-digit groups separated by dashes (as Windows shows it)
#     e.g. tools/bitlocker_mount.sh disk.img 123456-123456-123456-123456-123456-123456-123456-123456
#   user password form: pass "password" as the second arg literally, then the password as the third
#     e.g. tools/bitlocker_mount.sh disk.img password MyP@ssw0rd
# Mounts the decrypted volume (via dislocker-fuse + FUSE) at ./<volume-image>.mnt/, which exposes
# a raw decrypted image file (dislocker-file) you can point tools/disk_sweep.py at directly.
#
# NOTE: CLI usage verified against dislocker --help and a smoke test (bad-volume error handling
# confirmed working), but NOT live-tested against a real BitLocker volume - those can only be
# created with Windows' manage-bde, not from Linux. First real use, double check it behaves as
# expected and report back if the flags need adjusting.
set -e
img="$1"; shift
[ -z "$img" ] && { echo "usage: $0 <volume-image> <recovery-key|password> [password]"; exit 1; }
command -v dislocker >/dev/null 2>&1 || { echo "!! dislocker not installed - run tools/setup_wsl.sh's apt command"; exit 1; }

mnt="${img}.mnt"
mkdir -p "$mnt"

if [ "$1" == "password" ]; then
  echo "[dislocker] decrypting with user password"
  dislocker -V "$img" -u"$2" -- "$mnt"
else
  echo "[dislocker] decrypting with recovery key"
  dislocker -V "$img" -p"$1" -- "$mnt"
fi

echo "mounted - raw decrypted volume at: $mnt/dislocker-file"
echo "run: ~/ctfenv/bin/python tools/disk_sweep.py \"$mnt/dislocker-file\""
echo "unmount when done: fusermount -u \"$mnt\""
