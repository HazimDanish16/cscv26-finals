#!/home/jimmy/ctfenv/bin/python
"""Hastad broadcast attack: same small-e RSA plaintext encrypted under >=e different moduli.
Usage: hastad_broadcast.py e=<small e, e.g. 3> n1=<..> c1=<..> n2=<..> c2=<..> [n3=<..> c3=<..> ...]
CRT-combines the ciphertexts, takes the integer e-th root (allows a small wrap-search in case
padding pushed it slightly over a perfect e-th power), and prints the recovered plaintext."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags
from gmpy2 import mpz, iroot

a = dict(x.split('=', 1) for x in sys.argv[1:])
e = int(a['e'], 0)
ns = [int(a[k], 0) for k in sorted((k for k in a if k.startswith('n')), key=lambda k: int(k[1:]))]
cs = [int(a[k], 0) for k in sorted((k for k in a if k.startswith('c')), key=lambda k: int(k[1:]))]
assert len(ns) == len(cs) >= e, f'need at least e={e} (modulus, ciphertext) pairs, got {len(ns)}'


def crt(residues, moduli):
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r, m in zip(residues, moduli):
        Ni = N // m
        x += r * Ni * pow(Ni, -1, m)
    return x % N


combined = crt(cs[:e], ns[:e])
for k in range(0, 1000):
    N = 1
    for m in ns[:e]:
        N *= m
    r, exact = iroot(mpz(combined) + k * N, e)
    if exact:
        m = int(r)
        bs = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        print(f'recovered plaintext (wrap k={k}): {bs!r}')
        fl = find_flags(bs)
        if fl:
            print('CANDIDATE (unverified):', fl)
        break
else:
    print('no exact e-th root found in a small wrap search - check moduli/ciphertext order match, '
          'or try with more (n,c) pairs')
