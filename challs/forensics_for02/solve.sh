#!/usr/bin/env bash
# FOR02 - recover path of a deleted file whose MFT records were overwritten, via $UsnJrnl.
# Usage (WSL): ./solve.sh /path/to/raw.E01   (needs sleuthkit; mftdump.py/usndump.py alongside)
set -e
E="${1:?image}"; D="$(cd "$(dirname "$0")" && pwd)"; W=$(mktemp -d)
PY=~/ctfenv/bin/python
icat -i ewf "$E" 39-128-3 > "$W/J"            # $Extend/$UsnJrnl:$J (bare NTFS, no -o offset)
$PY "$D/usndump.py" "$W/J" > "$W/usn.txt"
# find the destroyed file: a .txt whose DELETE came right before its folder chain was deleted
grep -E "playlist_balladsong.txt" "$W/usn.txt"
# walk parents at creation time (mft=130 par=129 -> 128 -> 127 -> 126 -> 125 Archive -> 5 root)
grep -E "mft=(125|126|127|128|129) .* CREATE +[^ ]+$" "$W/usn.txt" | head -5
echo 'CSCV2026{E:\Archive\legal_14\proj_F3\vault_CA\ops_7B\playlist_balladsong.txt}'   # E: from Recycle Bin $I files
