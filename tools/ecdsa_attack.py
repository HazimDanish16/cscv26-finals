#!/home/jimmy/ctfenv/bin/python
"""ECDSA attack kit. Usage:
  nonce reuse (two sigs, same k, same curve order n):
    ecdsa_attack.py reuse n=<order> r=<hex> s1=<hex> s2=<hex> h1=<hex> h2=<hex> [pub=<hex>]
      - h1/h2 are the message hashes (as integers, already reduced mod n if needed)
  known k (nonce leaked/predictable):
    ecdsa_attack.py knownk n=<order> r=<hex> s=<hex> h=<hex> k=<hex>
Recovers the private key d; verifies against pub (Q = d*G) if a known generator/curve point is given
via common named curves (secp256k1/secp256r1/secp384r1) - pass curve=secp256k1 etc.
"""
import sys
from gmpy2 import mpz, invert

CURVES = {
    # name: (p, a, b, Gx, Gy, n)
    'secp256k1': (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0, 7,
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
}


def ec_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + a) * invert(2 * P[1], p) % p
    else:
        lam = (Q[1] - P[1]) * invert(Q[0] - P[0], p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    y = (lam * (P[0] - x) - P[1]) % p
    return (int(x), int(y))


def ec_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P, p, a)
        P = ec_add(P, P, p, a)
        k >>= 1
    return R


def main():
    args = dict(x.split('=', 1) for x in sys.argv[2:])
    n = int(args['n'], 0)

    def h(k):
        return int(args[k], 16) if not args[k].startswith('0x') else int(args[k], 0)

    if sys.argv[1] == 'reuse':
        r, s1, s2, h1, h2 = (h(k) for k in ('r', 's1', 's2', 'h1', 'h2'))
        s_diff = (s1 - s2) % n
        if s_diff == 0:
            print('s1 == s2, nothing to recover (signatures identical or not actually nonce-reuse)')
            return
        k = (h1 - h2) * invert(s_diff, n) % n
        d = (s1 * k - h1) * invert(r, n) % n
        print(f'recovered nonce k = {hex(int(k))}')
        print(f'recovered private key d = {hex(int(d))}')
    elif sys.argv[1] == 'knownk':
        r, s, hh, k = (h(k) for k in ('r', 's', 'h', 'k'))
        d = (s * k - hh) * invert(r, n) % n
        print(f'recovered private key d = {hex(int(d))}')
    else:
        print(__doc__)
        return

    if 'curve' in args and 'pub' in args:
        curve = CURVES.get(args['curve'])
        if curve:
            p, a, b, gx, gy, _ = curve
            Q = ec_mul(int(d), (gx, gy), p, a)
            pub_hex = args['pub'].replace('0x', '')
            print(f'computed pubkey from recovered d: 04{Q[0]:064x}{Q[1]:064x}')
            print(f'given pubkey:                      {pub_hex}')
            print('MATCH' if pub_hex.lower().endswith(f'{Q[0]:064x}{Q[1]:064x}') else 'no match - check inputs/curve')


main()
