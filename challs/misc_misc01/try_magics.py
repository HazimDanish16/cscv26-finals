import subprocess, shutil

orig = open('ctf_super_agent_can_solve_this.challage', 'rb').read()
print(f'file size: {len(orig)} bytes, current prefix: {orig[:8]!r}')

candidates = {
    'PNG': bytes.fromhex('89504e470d0a1a0a'),
    '7z': bytes.fromhex('377abcaf271c0004'),
    'RAR5': bytes.fromhex('526172211a070100'),
    'GGUF_v3': b'GGUF' + (3).to_bytes(4, 'little'),
    'GGUF_v2': b'GGUF' + (2).to_bytes(4, 'little'),
    'GGUF_v1': b'GGUF' + (1).to_bytes(4, 'little'),
    'XZ': bytes.fromhex('fd377a585a0000') + b'\x00',  # pad to 8
    'ZSTD': bytes.fromhex('28b52ffd') + orig[4:8],  # 4-byte magic only, keep rest
    'GZIP': bytes.fromhex('1f8b08') + orig[3:8],
    'BZIP2': b'BZh9' + orig[4:8],
    'ELF': bytes.fromhex('7f454c4602010100'),
    'CLASS(java)': bytes.fromhex('cafebabe00000034'),
    'WASM': bytes.fromhex('0061736d01000000'),
    'SQLITE': b'SQLite f'[:8],
    'safetensors_hdrlen': len(orig).to_bytes(8, 'little'),  # safetensors: first 8 bytes = header json length (LE u64)
}

for name, magic in candidates.items():
    patched = magic + orig[len(magic):]
    open(f'/tmp/test_{name}.bin', 'wb').write(patched)
    r = subprocess.run(['file', f'/tmp/test_{name}.bin'], capture_output=True, text=True)
    print(f'{name:20} -> {r.stdout.strip()}')
