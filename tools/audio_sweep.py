#!/home/jimmy/ctfenv/bin/python
"""Audio forensics/data-mode sweep. Usage: audio_sweep.py <file>
Covers: spectrogram (visual messages/SSTV hidden in freq domain), DTMF/pager/packet-radio
data modes (multimon-ng), old modem-style FSK data (minimodem at common bauds), morse-as-tone,
SSTV images, and plain LSB-in-audio-samples steganography.
Output in <file>.out/"""
import sys, os, subprocess, wave
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags

f = os.path.abspath(sys.argv[1])
out = f + '.out'
os.makedirs(out, exist_ok=True)

# normalize to a 48kHz mono wav multimon-ng/minimodem expect, keeps original too
wav = os.path.join(out, 'norm.wav')
subprocess.run(['ffmpeg', '-y', '-loglevel', 'error', '-i', f, '-ar', '48000', '-ac', '1', wav])


def run(name, cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        o = r.stdout + r.stderr
    except Exception as e:
        o = str(e).encode()
    open(f'{out}/{name}.txt', 'wb').write(o)
    fl = find_flags(o)
    print(f'[{name}] {len(o)}B', ('CANDIDATE (unverified): ' + str(fl)) if fl else '')
    return o


# 1. spectrogram - visual messages (text/images drawn in frequency domain) or SSTV-looking signal
run('spectrogram_wide', ['sox', wav, '-n', 'remix', '1', 'rate', '48k', 'spectrogram', '-x', '2000', '-y', '513',
                          '-o', f'{out}/spectrogram.png'])
print(f'[spectrogram] -> {out}/spectrogram.png - LOOK AT IT, visual text/image messages are common')

# 2. multimon-ng: DTMF, pagers (POCSAG/FLEX), packet radio (AFSK1200/APRS), morse-as-tone, etc.
run('multimon_all', ['multimon-ng', '-t', 'wav', '-a', 'DTMF', '-a', 'MORSE_CW', '-a', 'AFSK1200',
                      '-a', 'AFSK2400', '-a', 'AFSK2400_2', '-a', 'POCSAG512', '-a', 'POCSAG1200',
                      '-a', 'POCSAG2400', '-a', 'FSK9600', '-a', 'FLEX', '-a', 'ZVEI1', wav])

# 3. minimodem: old acoustic-modem-style FSK data at common bauds (300/1200 Bell103, 45.45 RTTY, etc.)
for baud in (300, 1200, 2400, 4800):
    run(f'minimodem_{baud}', ['minimodem', '--rx', str(baud), '-f', wav, '-q'], 60)

# 4. SSTV decode attempt (common modes auto-detected)
try:
    import sstv
    imgs = sstv.decode_from_wav(wav)  # returns a list of PIL Images, one per detected SSTV frame
    if imgs:
        for i, img in enumerate(imgs):
            img.save(f'{out}/sstv_decoded_{i}.png')
        print(f'[sstv] decoded {len(imgs)} frame(s) -> {out}/sstv_decoded_*.png (check visually)')
    else:
        print('[sstv] no SSTV frame detected')
except Exception as e:
    print('[sstv] decode attempt failed/no signal:', e)

# 5. LSB-in-samples steganography (raw PCM bit-stealing, analogous to image LSB)
try:
    wf = wave.open(wav, 'rb')
    frames = wf.readframes(wf.getnframes())
    import struct
    n = len(frames) // 2
    samples = struct.unpack(f'<{n}h', frames[:n * 2])
    bits = ''.join(str(s & 1) for s in samples)
    bs = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    fl = find_flags(bs)
    pr = sum(32 <= c < 127 for c in bs[:300]) / max(1, len(bs[:300]))
    if fl or pr > .85:
        open(f'{out}/lsb_samples.bin', 'wb').write(bs)
        print(f'[audio LSB] printable={pr:.2f}', fl or bs[:80], f'-> {out}/lsb_samples.bin')
except Exception as e:
    print('[audio LSB] skipped:', e)

print('outputs in', out)
print('if nothing hit: try DTMF/morse by ear via spectrogram, check for reversed audio, '
      'speed/pitch changes (sox speed/tempo), or SSTV at a non-default mode (Scottie/Martin/Robot)')
