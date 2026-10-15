#!/home/jimmy/ctfenv/bin/python
"""SHA-256 length-extension attack, pure Python (hashpumpy's C ext is broken on py3.12 - verified
and replaced). Usage: length_extension.py <original_mac_hex> <known_message> <secret_byte_len> <data_to_append>
Forges a valid MAC for (secret || known_message || glue_padding || data_to_append) without
knowing the secret, for the vulnerable sha256(secret || message) keyed-prefix MAC construction."""
import sys, struct

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
MASK = 0xffffffff


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def sha256_compress(state, chunk):
    w = list(struct.unpack('>16L', chunk)) + [0] * 48
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + K[i] + w[i]) & MASK
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
    return [(x + y) & MASK for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def md_padding(total_len_bytes):
    ml = total_len_bytes * 8
    pad = b'\x80'
    pad += b'\x00' * ((56 - (total_len_bytes + 1) % 64) % 64)
    pad += struct.pack('>Q', ml)
    return pad


def sha256_from_state(state, data, processed_len):
    """Continue hashing `data` from a given 8-word state, as if `processed_len` bytes (a multiple
    of 64) were already compressed. Handles the final MD-padding for the real total length."""
    buf = data
    while len(buf) >= 64:
        state = sha256_compress(state, buf[:64])
        buf = buf[64:]
    buf += md_padding(processed_len + len(data))
    while len(buf) >= 64:
        state = sha256_compress(state, buf[:64])
        buf = buf[64:]
    return state


def state_from_digest(hexdigest):
    b = bytes.fromhex(hexdigest)
    return list(struct.unpack('>8L', b))


def digest_from_state(state):
    return struct.pack('>8L', *state).hex()


def self_test():
    """Verify the from-scratch compression function against hashlib on a plain (non-extended) hash."""
    import hashlib
    msg = b'the quick brown fox jumps over the lazy dog, repeated for length ' * 3
    expected = hashlib.sha256(msg).hexdigest()
    padded = msg + md_padding(len(msg))
    state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    while padded:
        state = sha256_compress(state, padded[:64])
        padded = padded[64:]
    got = digest_from_state(state)
    assert got == expected, f'self-test FAILED: {got} != {expected}'


def forge(orig_hex, known_msg, secret_len, append):
    self_test()
    original_total_len = secret_len + len(known_msg)
    glue = md_padding(original_total_len)
    state = state_from_digest(orig_hex)
    new_state = sha256_from_state(state, append, original_total_len + len(glue))
    new_mac = digest_from_state(new_state)
    new_message = known_msg + glue + append
    return new_mac, new_message


if __name__ == '__main__':
    orig_mac, known_msg, secret_len, append = sys.argv[1], sys.argv[2].encode(), int(sys.argv[3]), sys.argv[4].encode()
    new_mac, new_msg = forge(orig_mac, known_msg, secret_len, append)
    print(f'new MAC: {new_mac}')
    print(f'new message: {new_msg!r}')
    print(f'new message hex: {new_msg.hex()}')
