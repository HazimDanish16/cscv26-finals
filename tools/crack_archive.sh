#!/usr/bin/env bash
# Usage (WSL): tools/crack_archive.sh <file> [wordlist]
# Password-protected zip/pdf/office(docx,xlsx,pptx) cracking - format-specific direct crackers,
# no john-jumbo build needed. Default wordlist: rockyou.txt (cheap - see brute-force policy in
# CLAUDE.md; only reaches for this on a clear password-cracking challenge).
set -e
f="$1"
wl="${2:-/usr/share/wordlists/rockyou.txt}"
[ -z "$f" ] && { echo "usage: $0 <file> [wordlist]"; exit 1; }
ext="${f##*.}"
need() { command -v "$1" >/dev/null 2>&1 || { echo "!! $1 not installed - run tools/setup_wsl.sh's apt command"; exit 1; }; }
case "$(echo "$ext" | tr A-Z a-z)" in
  zip)
    need fcrackzip
    echo "[fcrackzip] dictionary attack against $wl"
    fcrackzip -D -u -p "$wl" "$f" && exit 0
    echo "[fcrackzip] not found via dictionary - trying short numeric/charset brute (len 1-6, a-zA-Z0-9)"
    fcrackzip -b -c a1 -l 1-6 -u "$f"
    ;;
  pdf)
    export PATH="$HOME/.local/bin:$PATH"
    need pdfcrack
    echo "[pdfcrack] dictionary attack against $wl (RC4/AES-128 - R2-R4 only, not AES-256/R6)"
    if ! pdfcrack -f "$f" -w "$wl"; then
      echo "[pikepdf fallback] pdfcrack can't handle AES-256 (R6) PDFs - trying direct password check instead"
      ~/ctfenv/bin/python - "$f" "$wl" <<'PY'
import sys, pikepdf
f, wl = sys.argv[1], sys.argv[2]
with open(wl, encoding='latin1', errors='ignore') as fh:
    for line in fh:
        pw = line.rstrip('\n')
        try:
            pikepdf.open(f, password=pw).close()
            print(f'PASSWORD FOUND: {pw!r}')
            sys.exit(0)
        except pikepdf.PasswordError:
            continue
print('not found in wordlist')
PY
    fi
    ;;
  docx|xlsx|pptx|doc|xls|ppt)
    echo "[msoffcrypto-tool] trying $wl against Office encryption"
    ~/ctfenv/bin/python - "$f" "$wl" <<'PY'
import sys, msoffcrypto
f, wl = sys.argv[1], sys.argv[2]
office = msoffcrypto.OfficeFile(open(f, 'rb'))
with open(wl, encoding='latin1', errors='ignore') as fh:
    for i, line in enumerate(fh):
        pw = line.rstrip('\n')
        try:
            office.load_key(password=pw)
            office.decrypt(open(f + '.decrypted', 'wb'))
            print(f'PASSWORD FOUND: {pw!r} -> {f}.decrypted')
            sys.exit(0)
        except Exception:
            continue
        if i % 200000 == 0 and i:
            print(f'  ...tried {i} passwords, no luck yet')
print('not found in wordlist')
PY
    ;;
  *)
    echo "unrecognized extension '$ext' - supported: zip, pdf, docx/xlsx/pptx/doc/xls/ppt"
    exit 1
    ;;
esac
