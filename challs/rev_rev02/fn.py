"""fn.py <addr-hex> [maxlines] : print a function from /tmp/phantom.txt with junk (mov r,r / blank) removed.
fn.py --index : build /tmp/fnidx.txt (name start end)"""
import re, sys, os

TXT = "/tmp/phantom.txt"
IDX = "/tmp/fnidx.txt"

if sys.argv[1] == "--index":
    out = open(IDX, "w")
    cur = None
    with open(TXT, encoding="latin-1") as f:
        for i, l in enumerate(f, 1):
            if not l.startswith(".text:"):
                continue
            m = re.match(r"\.text:[0-9A-F]+ (\w+)\s+(proc|endp)", l)
            if m:
                if m.group(2) == "proc":
                    cur = (m.group(1), i)
                elif cur:
                    out.write("%s %d %d\n" % (cur[0], cur[1], i))
                    cur = None
    sys.exit()

name = "sub_" + sys.argv[1].upper().replace("SUB_", "")
mx = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
rng = None
for l in open(IDX):
    n, s, e = l.split()
    if n == name:
        rng = (int(s), int(e))
if not rng:
    sys.exit("not found")
print(name, rng, "lines", rng[1] - rng[0])
cnt = 0
with open(TXT, encoding="latin-1") as f:
    for i, l in enumerate(f, 1):
        if i < rng[0]:
            continue
        if i > rng[1]:
            break
        l = l.rstrip("\n")[16:].rstrip()  # drop ".text:0000000140"
        if not l.strip():
            continue
        m = re.match(r"(\w+)\s+mov\s+(\w+), (\w+)$", l.split(";")[0].strip().replace("  ", " ")) if False else None
        body = l[:200]
        mm = re.search(r"\smov\s+(\w+), (\w+)\s*(;.*)?$", body)
        if mm and mm.group(1) == mm.group(2):
            continue
        if "---------" in body:
            continue
        print(body)
        cnt += 1
        if cnt >= mx:
            break
