#!/home/jimmy/ctfenv/bin/python
"""Disk image forensics sweep (sleuthkit/TSK-based). Usage: disk_sweep.py <image.dd|.img|.E01|.raw>
Handles raw dd/img directly, and .E01 (EnCase) via ewfmount if available. Runs:
  mmls (partition table) -> fls -rp (recursive file listing incl. deleted, marked '*') ->
  tsk_recover -e (bulk-extract allocated+deleted files) -> flag grep over every recovered file ->
  fls -rm + mactime (timeline, bodyfile) for "when did this happen" questions.
Output in <image>.out/ (extracted files in <image>.out/recovered/)"""
import sys, os, re, subprocess, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags

f = os.path.abspath(sys.argv[1])
out = f + '.out'
os.makedirs(out, exist_ok=True)


def run(name, cmd, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        o = r.stdout + r.stderr
    except Exception as e:
        o = str(e).encode()
    open(f'{out}/{name}.txt', 'wb').write(o)
    fl = find_flags(o)
    print(f'[{name}] {len(o)}B', ('CANDIDATE (unverified): ' + str(fl)) if fl else '')
    return o


img = f
if f.lower().endswith('.e01'):
    mnt = out + '_ewf'
    os.makedirs(mnt, exist_ok=True)
    r = subprocess.run(['ewfmount', f, mnt], capture_output=True, timeout=60)
    if r.returncode == 0:
        img = os.path.join(mnt, 'ewf1')
        print(f'[ewfmount] E01 mounted as raw device -> {img}')
    else:
        print('[ewfmount] failed (is ewf-tools installed? apt install ewf-tools) -', r.stderr.decode()[:200])

print('== partition table ==')
mmls_out = run('mmls', ['mmls', img]).decode(errors='ignore')

# auto-detect a sector offset for tools when the image has a partition table (most full-disk
# images do) - without -o, fls/icat/tsk_recover only see the raw unpartitioned bytes and find nothing.
# mmls line format: "NNN:  slot   START   END   LENGTH   Description" - take the Start column of
# the first partition whose description names a real filesystem (skip Meta/Unallocated entries).
offset = None
for line in mmls_out.splitlines():
    if re.search(r'\b(Linux|NTFS|FAT|HFS|Win95|exFAT|ext[234])\b', line, re.I):
        m = re.search(r'\s(\d+)\s+\d+\s+\d+\s', line)
        if m:
            offset = int(m.group(1))
            break
oargs = ['-o', str(offset)] if offset else []
if offset:
    print(f'  detected partition offset {offset} sectors - using it for fls/tsk_recover/icat below')
else:
    print('  no partition table detected - treating image as a bare filesystem (offset 0)')

print('== file listing (recursive, * = deleted) ==')
listing = run('fls_recursive', ['fls', '-r', '-p'] + oargs + [img])
deleted = [l for l in listing.decode(errors='ignore').splitlines() if l.strip().startswith('*')]
print(f'  {len(deleted)} deleted-entry line(s) found' if deleted else '  no deleted entries listed')

print('== bulk recover (allocated + deleted) ==')
recdir = os.path.join(out, 'recovered')
os.makedirs(recdir, exist_ok=True)
run('tsk_recover', ['tsk_recover', '-e'] + oargs + [img, recdir])
recovered = [os.path.join(dp, fn) for dp, _, fns in os.walk(recdir) for fn in fns]
print(f'  recovered {len(recovered)} file(s) -> {recdir}')
for p in recovered:
    try:
        data = open(p, 'rb').read()
    except Exception:
        continue
    fl = find_flags(data)
    if fl:
        print(f'  CANDIDATE (unverified) in {p}:', fl)

print('== timeline (bodyfile -> mactime, if available) ==')
body = run('fls_bodyfile', ['fls', '-r', '-m', '/'] + oargs + [img])
if shutil.which('mactime'):
    open(f'{out}/bodyfile.txt', 'wb').write(body)
    run('timeline', ['mactime', '-b', f'{out}/bodyfile.txt'])
else:
    print('  mactime not found (part of sleuthkit - should be present); bodyfile saved for manual use')

print('outputs in', out)
print('if partition/filesystem not auto-detected: check mmls.txt for the right sector offset, then '
      're-run tools pointed at an offset slice, or `img_stat`/`fsstat` for filesystem details.')
