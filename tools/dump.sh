#!/usr/bin/env bash
# Usage (WSL): tools/dump.sh <ctfd-url> <token|user:pass>   -> downloads all challs into challs/
# Token: CTFd Settings > Access Tokens (starts with ctfd_). Prefer token over password.
cd "$(dirname "$0")/.." || exit 1
url="$1"; auth="$2"
if [[ "$auth" == *:* ]]; then a=(-u "${auth%%:*}" -p "${auth#*:}"); else a=(-t "$auth"); fi
~/ctfenv/bin/ctf-dl "$url" "${a[@]}" -o challs -f markdown
