#!/home/jimmy/ctfenv/bin/python
"""Memory-forensics key/wordlist generator.
Scrapes volatility3 pslist/cmdline/envars output (or any text dump) for hostnames, PIDs,
campaign/job IDs, usernames, GUIDs, hex blobs - then emits candidate key strings using the
common CTF pattern seen before: concatenations/joins of (hostname, pid, separator, tag, ...).

Usage: memkey_candidates.py <vol_output.txt> [--try-decrypt enc_file]
Prints candidate strings and, combined with any 16/24/32-byte hex blobs found (candidate IVs/keys),
tries AES-CBC/ECB/CTR decryption against the target file if given, looking for valid magic bytes
or a flag pattern.
"""
import sys, os, re, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags

MAGIC = {
    b'\xff\xd8\xff': 'jpeg', b'\x89PNG': 'png', b'PK\x03\x04': 'zip',
    b'%PDF': 'pdf', b'GIF8': 'gif', b'BM': 'bmp', b'\x50\x4b': 'zip',
}


def looks_valid(b):
    for m in MAGIC:
        if b.startswith(m):
            return MAGIC[m]
    pr = sum(32 <= c < 127 or c in (9, 10, 13) for c in b[:300]) / max(1, len(b[:300]))
    return 'text' if pr > .9 else None


def main():
    path = sys.argv[1]
    txt = open(path, encoding='utf-8', errors='ignore').read()
    hostnames = set(re.findall(r'\b(?:desktop|win|host|pc|dc|srv)-[a-z0-9]+\b', txt, re.I))
    pids = set(re.findall(r'\b\d{2,6}\b', txt))
    tags = set(re.findall(r'\b[A-Z0-9]{5,10}\b', txt))  # campaign-id-looking tokens
    hexblobs = sorted(set(re.findall(r'\b[0-9a-fA-F]{32,64}\b', txt)), key=len)
    users = set(re.findall(r'(?:user|owner)[=:]\s*([A-Za-z0-9_.\\-]+)', txt, re.I))
    print(f'hostnames={hostnames}\nusers={users}\nsample pids={list(pids)[:10]}\nsample tags={list(tags)[:10]}')
    print(f'hex blobs found: {len(hexblobs)} (candidate keys/IVs, lengths {sorted(set(len(h) for h in hexblobs))})')

    seps = ['', '|', '-', '_', ':']
    cands = set()
    for h in hostnames or {''}:
        for p in (pids or {''}):
            for s in seps:
                for t in (tags or {''}):
                    if h or p or t:
                        cands.add(f'{h}{p}{s}{t}')
                        cands.add(f'{h}{s}{p}{s}{t}')
    print(f'generated {len(cands)} candidate key strings -> saved to memkeys.txt')
    out = os.path.join(os.path.dirname(path), 'memkeys.txt')
    open(out, 'w').write('\n'.join(sorted(cands)))

    if '--try-decrypt' in sys.argv:
        target = sys.argv[sys.argv.index('--try-decrypt') + 1]
        data = open(target, 'rb').read()
        from Crypto.Cipher import AES
        ivs = [bytes.fromhex(h) for h in hexblobs if len(h) == 32]
        keys8 = [bytes.fromhex(h) for h in hexblobs if len(h) in (32, 48, 64)]
        keys_from_str = [c.encode().ljust(32, b'\0')[:32] for c in cands] + \
                         [c.encode().ljust(16, b'\0')[:16] for c in cands]
        tried = 0
        for key in keys8 + keys_from_str:
            for iv in (ivs or [key[:16]]):
                for mode, kw in ((AES.MODE_CBC, {'iv': iv[:16]}), (AES.MODE_CTR, {'nonce': iv[:8]}),
                                  (AES.MODE_ECB, {})):
                    try:
                        pt = AES.new(key[:len(key) if len(key) in (16, 24, 32) else 32], mode, **kw).decrypt(data)
                    except Exception:
                        continue
                    tried += 1
                    kind = looks_valid(pt)
                    fl = find_flags(pt)  # check regardless of magic/printable - padding can mask a hit
                    if kind or fl:
                        outp = target + f'.dec_{kind or "raw"}'
                        open(outp, 'wb').write(pt)
                        print(f'HIT key={key.hex()[:20]}.. iv/nonce={iv.hex()[:20] if iv else None} mode={mode} -> {kind} -> {outp}')
                        if fl:
                            print('CANDIDATE (unverified) flag in decrypted data:', fl)
        print(f'tried {tried} key/iv/mode combos')


main()
