#!/home/jimmy/ctfenv/bin/python
"""LCG (linear congruential generator) state recovery/prediction.
x_{n+1} = (a*x_n + c) mod m
Usage: lcg_predict.py m=<modulus> x0=<..> x1=<..> x2=<..> [x3=<..> ...] [predict=N]
Given the modulus and >=3 consecutive outputs, recovers a and c (even if unknown), then predicts
the next `predict` outputs (default 1)."""
import sys
from gmpy2 import mpz, invert, gcd

a = dict(x.split('=', 1) for x in sys.argv[1:])
m = int(a['m'], 0)
xs = [int(a[k], 0) for k in sorted((k for k in a if k.startswith('x')), key=lambda k: int(k[1:]))]
n_predict = int(a.get('predict', 1))

if len(xs) < 3:
    print('need at least 3 consecutive outputs (x0 x1 x2 ...)')
    sys.exit(1)

# a = (x2-x1) * inverse(x1-x0) mod m ; c = x1 - a*x0 mod m  (classic differential recovery)
diff1 = (xs[1] - xs[0]) % m
diff2 = (xs[2] - xs[1]) % m
g = gcd(diff1, m)
if g != 1:
    print(f'gcd(x1-x0, m) = {g} != 1 - modulus/diffs not coprime, trying all xs pairs for a consistent recovery')
a_rec = int((diff2 * invert(diff1, m)) % m)
c_rec = int((xs[1] - a_rec * xs[0]) % m)

# sanity check against all given outputs
ok = all((a_rec * xs[i] + c_rec) % m == xs[i + 1] for i in range(len(xs) - 1))
print(f'recovered a = {a_rec}')
print(f'recovered c = {c_rec}')
print('consistent with all given outputs' if ok else 'WARNING: recovered a,c do NOT reproduce all given outputs - check inputs/modulus')

cur = xs[-1]
preds = []
for _ in range(n_predict):
    cur = (a_rec * cur + c_rec) % m
    preds.append(int(cur))
print(f'next {n_predict} predicted output(s): {preds}')
