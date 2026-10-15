#!/home/jimmy/ctfenv/bin/python
"""Quick AES decrypt attempt. Usage: aes_try.py <enc_file> key=<hex|str> [iv=<hex>] [mode=cbc|ecb|ctr]
If key doesn't look like hex, it's utf-8 encoded then padded/truncated to 16/24/32 (tries all three)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags
from Crypto.Cipher import AES

enc = sys.argv[1]
a = dict(x.split('=', 1) for x in sys.argv[2:])
data = open(enc, 'rb').read()


def as_bytes(s):
    try:
        return bytes.fromhex(s)
    except ValueError:
        return s.encode()


key_raw = as_bytes(a['key'])
iv = as_bytes(a['iv']) if 'iv' in a else None
modes = [a['mode']] if 'mode' in a else ['cbc', 'ecb', 'ctr']
MAGIC = {b'\xff\xd8\xff': 'jpeg', b'\x89PNG': 'png', b'PK\x03\x04': 'zip', b'%PDF': 'pdf', b'GIF8': 'gif'}

for klen in (16, 24, 32):
    key = key_raw.ljust(klen, b'\0')[:klen] if len(key_raw) != klen else key_raw
    for mode in modes:
        try:
            if mode == 'cbc':
                pt = AES.new(key, AES.MODE_CBC, iv=(iv or b'\0' * 16)[:16]).decrypt(data)
            elif mode == 'ctr':
                pt = AES.new(key, AES.MODE_CTR, nonce=(iv or b'\0' * 8)[:8]).decrypt(data)
            else:
                pt = AES.new(key, AES.MODE_ECB).decrypt(data)
        except Exception:
            continue
        kind = next((v for m, v in MAGIC.items() if pt.startswith(m)), None)
        pr = sum(32 <= c < 127 for c in pt[:200]) / max(1, len(pt[:200]))
        fl = find_flags(pt)  # check regardless of printable ratio - padding/nulls can drag the ratio down
        if kind or pr > .9 or fl:
            outp = enc + f'.dec_{mode}'
            open(outp, 'wb').write(pt)
            print(f'[{mode} klen={klen}] kind={kind} printable={pr:.2f} -> {outp}')
            if fl:
                print('CANDIDATE (unverified) flag:', fl)
print('done (tried cbc/ecb/ctr x keylens; if nothing hit, your key/iv derivation is likely wrong - recheck source)')
