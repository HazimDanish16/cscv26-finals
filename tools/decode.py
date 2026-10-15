#!/home/jimmy/ctfenv/bin/python
"""Recursive decoder: decode.py <string|@file>
BFS over base64/32/85, hex, url, rot-N, atbash, binary, morse, reverse, single-byte xor, zlib/gzip/bz2.
Prints any chain that yields a flag."""
import sys, os, base64, binascii, zlib, gzip, bz2, urllib.parse, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags


def tryf(fn):
    def w(x):
        try:
            r = fn(x)
            return r if r and r != x else None
        except Exception:
            return None
    return w


MORSE = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
         '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
         '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
         '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
         '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'}
AB = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def rotn(x, n):
    return bytes((c - 65 + n) % 26 + 65 if 65 <= c <= 90 else (c - 97 + n) % 26 + 97 if 97 <= c <= 122 else c
                 for c in x)


D = {
    'b64': tryf(lambda x: base64.b64decode(x.strip() + b'=' * (-len(x.strip()) % 4))),
    'b64url': tryf(lambda x: base64.urlsafe_b64decode(x.strip() + b'=' * (-len(x.strip()) % 4))),
    'b32': tryf(lambda x: base64.b32decode(x.strip().upper() + b'=' * (-len(x.strip()) % 8))),
    'b85': tryf(lambda x: base64.b85decode(x.strip())),
    'a85': tryf(lambda x: base64.a85decode(x.strip())),
    'hex': tryf(lambda x: binascii.unhexlify(re.sub(rb'[\s:]|0x', b'', x))),
    'url': tryf(lambda x: urllib.parse.unquote_to_bytes(x)),
    'rev': tryf(lambda x: x[::-1]),
    'bin': tryf(lambda x: bytes(int(c, 2) for c in re.findall(rb'[01]{8}', x))
                if re.fullmatch(rb'[01\s]+', x) else None),
    'zlib': tryf(zlib.decompress), 'gzip': tryf(gzip.decompress), 'bz2': tryf(bz2.decompress),
    'morse': tryf(lambda x: ''.join(MORSE.get(t, '?') for t in x.decode().split()).encode()
                  if re.fullmatch(rb'[.\-/\s]+', x) else None),
    'atbash': tryf(lambda x: x.translate(bytes.maketrans(AB, AB[:26][::-1] + AB[26:][::-1]))),
}
for n in range(1, 26):
    D[f'rot{n}'] = tryf(lambda x, n=n: rotn(x, n))
for k in range(1, 256):
    D[f'xor{k:02x}'] = tryf(lambda x, k=k: bytes(c ^ k for c in x))


def printable(x):
    return len(x) > 0 and sum(32 <= c < 127 or c in (9, 10, 13) for c in x) / len(x) > .85


def main():
    s = sys.argv[1]
    s = open(s[1:], 'rb').read() if s.startswith('@') else s.encode()
    seen = {s}
    q = [(s, [])]
    hits = 0
    fl = find_flags(s)
    if fl:
        print('CANDIDATE (unverified) in input:', fl)
    while q and hits < 20:
        cur, path = q.pop(0)
        if len(path) >= 6:
            continue
        for name, fn in D.items():
            if name.startswith(('xor', 'rot', 'atb')) and any(s.startswith(('xor', 'rot', 'atb')) for s in path):
                continue  # at most one substitution cipher per chain, avoids junk explosion
            r = fn(cur)
            if r is None or r in seen or len(r) > 1_000_000:
                continue
            seen.add(r)
            p = path + [name]
            fl = find_flags(r)
            if fl:
                print('CANDIDATE (unverified)', ' > '.join(p), fl)
                hits += 1
            elif printable(r) and (not name.startswith(('xor', 'rot')) or len(p) < 3):
                q.append((r, p))
                if not name.startswith(('xor', 'rot')):
                    print(' ', ' > '.join(p), r[:70])
    if not hits:
        print('no flag via simple chains; try Vigenere / xor key / other schemes')


main()
