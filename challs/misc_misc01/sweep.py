import hashlib, itertools
from Crypto.Cipher import AES

data = open('ctf_super_agent_can_solve_this.challage', 'rb').read()

key_strings = [
    b'CHALLAGE', b'789513', b'50b1ede142e115f38f9f098d6687f36c',
    b'338af6b4092e34a5b7f97c053d963c98f11763ea9b187c4855693846e653d68b',
    b'164a1eff92e2f3c90bbabf965d314857', b'8afd499eeff8b738afeb8b35f4ef09cb',
    b'ctf_super_agent_can_solve_this.challage', b'ctf-super-agent', b'super_mode',
    b'Yobdas', b'aes_256_ecb', b'CSCV2026',
]

def derive_keys(s):
    return {
        'raw16': s.ljust(16, b'\0')[:16], 'raw32': s.ljust(32, b'\0')[:32],
        'sha256': hashlib.sha256(s).digest(), 'sha1_16': hashlib.sha1(s).digest()[:16],
        'md5': hashlib.md5(s).digest(), 'md5x2': hashlib.md5(s).digest() * 2,
    }

def printable_score(b):
    if not b:
        return 0
    return sum(32 <= c < 127 for c in b) / len(b)

hits = []
tried = 0
for s in key_strings:
    for kname, key in derive_keys(s).items():
        for strip in (0, 8, 16, 24, 32, 40):
            body = data[strip:]
            if len(body) % 16 != 0:
                continue
            tried += 1
            try:
                pt = AES.new(key, AES.MODE_ECB).decrypt(body)
            except Exception:
                continue
            sc = printable_score(pt)
            if sc > 0.85:
                hits.append((s, kname, strip, 'ECB', sc, pt))
            # CBC with various IV sources
            for iv_src_name, iv in (('zero', b'\0' * 16), ('first16ofbody', body[:16] if len(body) >= 16 else None)):
                if iv is None or len(body) <= 16:
                    continue
                try:
                    pt2 = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(body[16:] if iv_src_name == 'first16ofbody' else body)
                except Exception:
                    continue
                sc2 = printable_score(pt2)
                if sc2 > 0.85:
                    hits.append((s, kname, strip, f'CBC-{iv_src_name}', sc2, pt2))

print(f'tried {tried} key/offset combos (ECB) + CBC variants')
if hits:
    for s, kname, strip, mode, sc, pt in hits:
        print(f'HIT key_str={s} kname={kname} strip={strip} mode={mode} score={sc:.2f}\n  {pt}')
else:
    print('no hits above 0.85 printable threshold')
    # also show the best (highest-scoring) attempts even if below threshold, for inspection
    best = []
    for s in key_strings:
        for kname, key in derive_keys(s).items():
            body = data[8:]
            if len(body) % 16 != 0:
                continue
            try:
                pt = AES.new(key, AES.MODE_ECB).decrypt(body)
                best.append((printable_score(pt), s, kname, pt))
            except Exception:
                pass
    best.sort(reverse=True)
    print('\ntop 5 by printable score (strip=8, ECB):')
    for sc, s, kname, pt in best[:5]:
        print(f'  {sc:.2f} {s} {kname}: {pt[:40]}')
