#!/home/jimmy/ctfenv/bin/python
"""Discrete log solver (Pohlig-Hellman under the hood via sympy - fast when the group order is
smooth; falls back to BSGS/Pollard for the hard part, so slow if order has a large prime factor).
Usage: discrete_log.py p=<prime modulus> g=<generator> y=<target, want x where g^x=y mod p> [n=<group order, default p-1>]
"""
import sys
from sympy.ntheory.residue_ntheory import discrete_log

a = dict(x.split('=', 1) for x in sys.argv[1:])
p, g, y = int(a['p'], 0), int(a['g'], 0), int(a['y'], 0)
n = int(a['n'], 0) if 'n' in a else p - 1

x = discrete_log(p, y, g)
print(f'x = {x}')
print('verify: g^x mod p == y ->', pow(g, x, p) == y % p)
