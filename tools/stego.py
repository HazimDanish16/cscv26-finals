#!/home/jimmy/ctfenv/bin/python
"""Stego/forensics sweep. Usage: stego.py <file>
Runs file/exiftool/strings/binwalk/foremost/zsteg/steghide(empty pw)/trailing-data/LSB bit-planes,
greps every output for flags. Output in <file>.out/"""
import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags

f = os.path.abspath(sys.argv[1])
out = f + '.out'
os.makedirs(out, exist_ok=True)


def run(name, cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=out)
        o = r.stdout + r.stderr
    except Exception as e:
        o = str(e).encode()
    open(f'{out}/{name}.txt', 'wb').write(o)
    fl = find_flags(o)
    print(f'[{name}] {len(o)}B', ('CANDIDATES (unverified): ' + str(fl)) if fl else '')
    return o


ft = run('file', ['file', f]).decode()
lo = ft.lower()
run('exiftool', ['exiftool', f])
run('strings', ['strings', '-n', '5', f])
run('strings16', ['strings', '-n', '5', '-el', f])
run('binwalk', ['binwalk', '-e', '-M', '-C', out + '/binwalk', f])
run('foremost', ['foremost', '-q', '-T', '-i', f, '-o', out + '/foremost_' + str(os.getpid())])
if any(k in lo for k in ('png', 'bitmap', 'jpeg', 'gif')):
    run('zbarimg', ['zbarimg', '--raw', f])  # QR codes / barcodes hidden in the image
if 'png' in lo or 'bitmap' in lo:
    run('zsteg', ['zsteg', '-a', f], 300)
if any(k in lo for k in ('jpeg', 'bitmap', 'wave', 'au ')):
    run('steghide_empty', ['steghide', 'extract', '-sf', f, '-p', '', '-f', '-xf', out + '/steghide.bin'])
    # stegseek: steghide-format rockyou crack, seconds on a typical wordlist - cheap, always worth it
    run('stegseek', ['stegseek', f, '/usr/share/wordlists/rockyou.txt', '-xf', out + '/stegseek.bin', '-f'], 60)

# data appended after the end-of-image marker
d = open(f, 'rb').read()
for name, mark in (('png', b'IEND\xaeB`\x82'), ('jpg', b'\xff\xd9')):
    i = d.rfind(mark)
    if i != -1 and i + len(mark) < len(d) and name in lo.replace('jpeg', 'jpg'):
        open(f'{out}/trailing.bin', 'wb').write(d[i + len(mark):])
        print(f'[trailing] {len(d) - i - len(mark)}B after EOF -> trailing.bin')

# LSB / bit-plane extraction for images
try:
    from PIL import Image
    im = Image.open(f).convert('RGBA')
    px = list(im.getdata())
    chans = {'R': 0, 'G': 1, 'B': 2, 'A': 3}
    combos = [('R',), ('G',), ('B',), ('A',), ('R', 'G', 'B'), ('R', 'G', 'B', 'A')]
    for bit in (0, 1, 2):
        for c in combos:
            for order in ('msb', 'lsb'):
                bits = ''.join(str((p[chans[x]] >> bit) & 1) for p in px for x in c)
                bs = bytes(int(bits[i:i + 8][::(1 if order == 'msb' else -1)], 2)
                           for i in range(0, len(bits) - 7, 8))
                fl = find_flags(bs)
                pr = sum(32 <= b < 127 for b in bs[:200]) / max(1, len(bs[:200]))
                if fl or pr > .9:
                    print(f'[LSB bit{bit} {"".join(c)} {order}] printable={pr:.2f}', fl or bs[:80])
    for k, ch in enumerate('RGBA'):
        plane = Image.new('L', im.size)
        plane.putdata([255 * (p[k] & 1) for p in px])
        plane.save(f'{out}/plane_{ch}_bit0.png')
    print('[planes] saved plane_*_bit0.png - look at them')
except Exception:
    pass

if 'wave' in lo or 'audio' in lo or f.endswith(('.wav', '.mp3', '.flac')):
    print('[audio] delegating to tools/audio_sweep.py for full data-mode coverage (DTMF/SSTV/FSK/LSB)')
    subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), 'audio_sweep.py'), f])
print('outputs in', out)
