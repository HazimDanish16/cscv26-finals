import re, collections
cur = None
m = collections.defaultdict(set)
pat = re.compile(r'src[\\]+(\w+)\.rs')
with open("/tmp/phantom.txt", encoding="latin-1") as f:
    for l in f:
        if not l.startswith(".text:"):
            continue
        mm = re.match(r"\.text:([0-9A-F]+) (\w+)\s+proc", l)
        if mm:
            cur = mm.group(2)
            continue
        p = pat.search(l)
        if p and cur:
            m[p.group(1)].add(cur)
for k, v in m.items():
    print(k, sorted(v))
