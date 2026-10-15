#!/usr/bin/env bash
# Usage (in WSL): tools/triage.sh <file-or-dir>   -- quick first-look on challenge files
t="$1"; [ -z "$t" ] && { echo "usage: $0 <path>"; exit 1; }
for f in $(find "$t" -type f | head -50); do
  echo "=== $f"; file "$f"
  echo "--- flag-ish strings:"; strings -n 6 "$f" | grep -iE 'cscv|flag\{|ctf\{' | head
  case "$(file -b "$f")" in
    *image*|*audio*|*PDF*) exiftool "$f" | head -30; binwalk "$f" | head -20;;
    *ELF*) (command -v checksec >/dev/null && checksec --file="$f") ;;
    *pcap*) tshark -r "$f" -q -z io,phs 2>/dev/null | head -30;;
  esac
done
