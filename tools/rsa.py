#!/home/jimmy/ctfenv/bin/python
"""RSA attack kit. Usage: rsa.py n=<int> e=<int> c=<int> [p=.. q=.. dp=.. n2=.. e2=.. c2=..]
Tries: given p/q, dp leak, shared prime (n2), common modulus (e2,c2), e-th root, Fermat, Wiener, factordb."""
import sys, os, json, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags
import gmpy2
from gmpy2 import mpz, iroot, invert, gcd, isqrt

a = {k: int(v, 0) for k, v in (x.split('=') for x in sys.argv[1:])}
n, e, c = a.get('n'), a.get('e', 65537), a.get('c')


def show(m, how):
    m = int(m)
    bs = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    print(f'[{how}] {bs!r}', find_flags(bs) or '')
    sys.exit(0)


def from_pq(p, q, how):
    p, q = int(p), int(q)
    show(pow(c, int(invert(e, (p - 1) * (q - 1))), n), how)


if 'p' in a:
    from_pq(a['p'], n // a['p'], 'given p')
if 'q' in a:
    from_pq(n // a['q'], a['q'], 'given q')
if 'dp' in a:
    p = int(gcd(pow(2, e * a['dp'], n) - 2, n))
    if 1 < p < n:
        from_pq(p, n // p, 'dp leak')
if 'n2' in a:
    p = int(gcd(n, a['n2']))
    if 1 < p < n:
        from_pq(p, n // p, 'shared prime')
if 'e2' in a and 'c2' in a:
    g, x, y = gmpy2.gcdext(e, a['e2'])
    if g == 1:
        def pw(b, k):
            return pow(b, int(k), n) if k >= 0 else pow(int(invert(b, n)), -int(k), n)
        show(pw(c, x) * pw(a['c2'], y) % n, 'common modulus')

for k in range(0, 1000 if e <= 17 else 1):
    r, exact = iroot(mpz(c) + k * n, e)
    if exact:
        show(r, f'{e}-th root (wrap k={k})')

x = isqrt(n) + 1
for _ in range(1_000_000):
    y, ex = iroot(x * x - n, 2)
    if ex:
        from_pq(x - y, x + y, 'fermat')
    x += 1


def cf(a_, b_):
    while b_:
        yield a_ // b_
        a_, b_ = b_, a_ % b_


h0, h1, k0, k1 = 0, 1, 1, 0
for q_ in cf(e, n):
    h0, h1 = h1, q_ * h1 + h0
    k0, k1 = k1, q_ * k1 + k0
    if h1 and (e * k1 - 1) % h1 == 0:
        phi = (e * k1 - 1) // h1
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            p = (s + isqrt(disc)) // 2
            from_pq(p, n // p, 'wiener')

try:
    j = json.load(urllib.request.urlopen(f'http://factordb.com/api?query={n}', timeout=15))
    fs = [int(p) for p, m in j['factors'] for _ in range(m)]
    print('factordb status', j['status'], fs if len(fs) < 6 else f'{len(fs)} factors')
    if len(fs) >= 2:
        phi = 1
        for p in fs:
            phi *= p - 1
        show(pow(c, int(invert(e, phi)), n), 'factordb')
except Exception as ex:
    print('factordb failed:', ex)
print('no luck: try ECM/msieve, Coppersmith/LLL (sage not installed), or check for oracle/leak in source')
