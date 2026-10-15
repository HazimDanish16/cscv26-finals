#!/usr/bin/env bash
# Usage (WSL): tools/libc_id.sh func1 addr1 [func2 addr2 ...]
# Identifies a remote libc version from leaked function addresses (classic ret2libc leak).
# Example: tools/libc_id.sh puts 0x7f1234567890 printf 0x7f1234567abc
cd ~/libc-database || exit 1
./find "$@"
echo
echo "if a match is found, use its .so from ./libs/<id>/libc.so.6 with patchelf/pwninit to rebuild the binary's rpath for local testing."
