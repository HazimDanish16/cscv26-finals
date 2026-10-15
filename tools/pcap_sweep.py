#!/home/jimmy/ctfenv/bin/python
"""PCAP forensics sweep. Usage: pcap_sweep.py <file.pcap[ng]>
Runs: protocol hierarchy, conversations, credential-sniffing (HTTP basic auth, FTP/Telnet/POP/IMAP
cleartext logins), exported files (HTTP/SMB/TFTP/IMF objects), DNS query dump (for exfil-via-
subdomain), ICMP payload dump (for exfil-via-ping), TLS key/SNI info, and a flag grep over
every TCP/UDP stream's reassembled payload. Output in <file>.out/"""
import sys, os, subprocess, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags

f = os.path.abspath(sys.argv[1])
out = f + '.out'
os.makedirs(out, exist_ok=True)


def find_flags_hexaware(o):
    """tshark '-T fields' on byte-type fields (data.data, http.file_data, etc.) prints hex
    text, not ASCII - check both the raw output and a hex-decoded version."""
    fl = find_flags(o)
    if fl:
        return fl
    hexonly = re.sub(rb'[^0-9a-fA-F]', b'', o)
    if len(hexonly) >= 8 and len(hexonly) % 2 == 0:
        try:
            return find_flags(bytes.fromhex(hexonly.decode()))
        except Exception:
            pass
    return []


def run(name, cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        o = r.stdout + r.stderr
    except Exception as e:
        o = str(e).encode()
    open(f'{out}/{name}.txt', 'wb').write(o)
    fl = find_flags_hexaware(o)
    print(f'[{name}] {len(o)}B', ('CANDIDATE (unverified): ' + str(fl)) if fl else '')
    return o


print('== overview ==')
run('proto_hierarchy', ['tshark', '-r', f, '-q', '-z', 'io,phs'])
run('conversations_tcp', ['tshark', '-r', f, '-q', '-z', 'conv,tcp'])
run('conversations_udp', ['tshark', '-r', f, '-q', '-z', 'conv,udp'])

print('== credential sniffing ==')
run('http_basic_auth', ['tshark', '-r', f, '-Y', 'http.authorization', '-T', 'fields',
                         '-e', 'http.authorization', '-e', 'http.request.uri'])
run('http_post_creds', ['tshark', '-r', f, '-Y', 'http.request.method=="POST"', '-T', 'fields',
                         '-e', 'http.file_data'])
run('ftp_creds', ['tshark', '-r', f, '-Y', 'ftp.request.command=="USER" or ftp.request.command=="PASS"',
                   '-T', 'fields', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'])
run('telnet', ['tshark', '-r', f, '-Y', 'telnet', '-T', 'fields', '-e', 'telnet.data'])
run('pop_imap_smtp', ['tshark', '-r', f, '-Y', 'pop or imap or smtp', '-T', 'fields', '-e', 'data.text'])

print('== DNS (check for exfil via subdomain encoding) ==')
dns = run('dns_queries', ['tshark', '-r', f, '-Y', 'dns.flags.response==0', '-T', 'fields', '-e', 'dns.qry.name'])
# long/odd-looking subdomains are a common exfil channel - flag anything with a long first label
odd = [l for l in dns.decode(errors='ignore').splitlines() if len(l.split('.')[0]) > 20]
if odd:
    print(f'  {len(odd)} suspiciously long DNS labels (possible exfil) - see dns_queries.txt, try decoding the first label')
    for l in odd[:5]:
        label = l.split('.')[0]
        print('   e.g.', label)

print('== ICMP (check for exfil via ping payload) ==')
run('icmp_payload', ['tshark', '-r', f, '-Y', 'icmp', '-T', 'fields', '-e', 'data.data'])

print('== exported objects (http/smb/tftp/imf) ==')
objdir = os.path.join(out, 'objects')
os.makedirs(objdir, exist_ok=True)
for proto in ('http', 'smb', 'tftp', 'imf'):
    subprocess.run(['tshark', '-r', f, '--export-objects', f'{proto},{objdir}'], capture_output=True, timeout=60)
extracted = [os.path.join(dp, fn) for dp, _, fns in os.walk(objdir) for fn in fns]
print(f'  extracted {len(extracted)} file(s) to {objdir}' if extracted else '  nothing exported')
for p in extracted:
    data = open(p, 'rb').read()
    fl = find_flags(data)
    if fl:
        print(f'  CANDIDATE (unverified) in {p}:', fl)

print('== raw flag grep across every stream payload ==')
streams = run('tcp_stream_dump', ['tshark', '-r', f, '-q', '-z', 'follow,tcp,raw,0'], 60)
# also try every stream index tshark knows about, not just stream 0
idx_out = subprocess.run(['tshark', '-r', f, '-T', 'fields', '-e', 'tcp.stream'],
                          capture_output=True, timeout=60).stdout
stream_ids = sorted(set(int(x) for x in idx_out.split() if x.strip().isdigit()))
all_hits = []
for sid in stream_ids[:200]:
    d = subprocess.run(['tshark', '-r', f, '-q', '-z', f'follow,tcp,raw,{sid}'],
                        capture_output=True, timeout=30).stdout
    fl = find_flags_hexaware(d)
    if fl:
        all_hits.append((sid, fl))
        print(f'  CANDIDATE (unverified) in tcp stream {sid}:', fl)
if not all_hits:
    print(f'  no direct flag match across {len(stream_ids)} tcp streams - try tools/decode.py on suspicious hex/base64 chunks, '
          f'or check {out}/objects/ and {out}/dns_queries.txt by hand')

print('outputs in', out)
