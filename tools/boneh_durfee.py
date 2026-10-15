#!/home/jimmy/ctfenv/bin/python
"""Boneh-Durfee attack: recovers RSA private exponent d when d < N^0.292 (beyond Wiener's
N^0.25 bound). Usage: boneh_durfee.py n=<N> e=<e> [m=5] [t=2]
Derivation: ed-1 = k*phi(N) for integer k, so k*phi(N)+1 ≡ 0 (mod e). With phi(N)=N+1+y where
y=-(p+q), this gives f(x,y) = x*(N+1+y)+1 ≡ 0 (mod e), x=k bounded ~N^0.292, y bounded ~2*sqrt(N).
Standard x/y-shift lattice construction, LLL, resultant of two reduced rows to solve for (x,y)
exactly (the equation holds as an exact integer identity at the true root, not just mod e), then
phi(N)=N+1+y, d=(k*phi(N)+1)/e."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags
from fpylll import IntegerMatrix, LLL
import sympy
from sympy.abc import x, y


def boneh_durfee_roots(N, e, m=5, t=2):
    X = int(2 * N ** 0.292) + 10
    Y = int(3 * N ** 0.5) + 10

    fx = x * (N + 1 + y) + 1

    polys = []
    for k in range(m + 1):
        for i in range(m - k + 1):
            polys.append(sympy.expand(x ** i * fx ** k * e ** (m - k)))
    for k in range(m + 1):
        for j in range(1, t + 1):
            polys.append(sympy.expand(y ** j * fx ** k * e ** (m - k)))

    monos = set()
    for p in polys:
        monos |= set(sympy.Poly(p, x, y).monoms())
    monos = sorted(monos, key=lambda mn: (mn[0], mn[1]))
    idx = {mn: i for i, mn in enumerate(monos)}

    rows = []
    for p in polys:
        row = [0] * len(monos)
        pd = sympy.Poly(p, x, y)
        for mono, coeff in zip(pd.monoms(), pd.coeffs()):
            row[idx[mono]] = int(coeff) * (X ** mono[0]) * (Y ** mono[1])
        rows.append(row)

    M = IntegerMatrix(len(rows), len(monos))
    for i, row in enumerate(rows):
        for j, v in enumerate(row):
            M[i, j] = v
    LLL.reduction(M)

    def row_to_poly(ridx):
        p = 0
        for j, mono in enumerate(monos):
            val = M[ridx, j]
            if val == 0:
                continue
            xd, yd = mono
            p += sympy.Rational(int(val), (X ** xd) * (Y ** yd)) * x ** xd * y ** yd
        return sympy.expand(p)

    results = []
    nrows = min(6, len(rows))
    for a in range(nrows):
        for b in range(a + 1, nrows):
            p1, p2 = row_to_poly(a), row_to_poly(b)
            try:
                res = sympy.resultant(sympy.Poly(p1, x, y), sympy.Poly(p2, x, y), y)
                if res == 0:
                    continue
                res = sympy.Poly(res, x)
                for r in sympy.real_roots(res):
                    if not r.is_Integer:
                        continue
                    kx = int(r)
                    if kx == 0:
                        continue
                    # substitute x=kx into p1 (now univariate in y) to solve for y
                    p1y = sympy.Poly(p1.subs(x, kx), y)
                    if p1y.degree() < 1:
                        continue
                    for ry in sympy.real_roots(p1y):
                        if ry.is_Integer:
                            results.append((kx, int(ry)))
            except Exception:
                continue
    return list(set(results))


def main():
    a = dict(v.split('=', 1) for v in sys.argv[1:])
    N, e = int(a['n'], 0), int(a['e'], 0)
    m, t = int(a.get('m', 5)), int(a.get('t', 2))
    c = int(a['c'], 0) if 'c' in a else None

    for kx, ry in boneh_durfee_roots(N, e, m, t):
        phi = N + 1 + ry
        if phi <= 0 or (kx * phi + 1) % e != 0:
            continue
        d = (kx * phi + 1) // e
        if not (0 < d < phi):
            continue
        if (e * d) % phi != 1:
            continue
        print(f'FOUND: k={kx} phi={phi} d={d}')
        s = -ry  # p+q
        disc = s * s - 4 * N
        if disc >= 0:
            from gmpy2 import isqrt
            root = int(isqrt(disc))
            if root * root == disc:
                p = (s + root) // 2
                q = (s - root) // 2
                print(f'p={p} q={q}')
        if c is not None:
            m_dec = pow(c, d, N)
            bs = m_dec.to_bytes((m_dec.bit_length() + 7) // 8, 'big')
            print(f'decrypted: {bs!r}')
            fl = find_flags(bs)
            if fl:
                print('CANDIDATE (unverified):', fl)
        return
    print('no valid (k,phi,d) found - try increasing m/t (slower but stronger), or d may not '
          'actually be in the N^0.292 range this attack covers')


main()
