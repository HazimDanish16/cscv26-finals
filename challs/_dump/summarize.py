import json
from collections import Counter

d = json.load(open('challs.json'))
chs = d['data']
print(f'total challenges: {len(chs)}')
print(Counter(c['category'] for c in chs))
for c in chs:
    print(f"{c['category']:12} {c['id']:10} {c['name']:20} {c['points']:5}pts solves={c['solves']:3} instancer={bool(c.get('instancerLifetime'))}")
