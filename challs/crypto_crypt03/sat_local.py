"""Test whether Z3 can finish key recovery after the integral stage.

Usage: python sat_local.py <local-test-key-hex>
   or: python sat_local.py <k5-column-hex> <k6-diagonal-hex> <pt-hex> <ct-hex>
The diagonal is in state positions 0, 7, 10, 13.
"""

import sys
import time

import z3

from aes import AES6, SBOX


def bv(value):
    return z3.BitVecVal(value, 8)


box = z3.K(z3.BitVecSort(8), bv(0))
for index, value in enumerate(SBOX):
    box = z3.Store(box, bv(index), bv(value))


def sb(value):
    return z3.Select(box, value)


def xtime(value):
    return (value << 1) ^ z3.If((value & bv(128)) != bv(0), bv(27), bv(0))


def mix(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    return [a[0] ^ t ^ xtime(a[0] ^ a[1]),
            a[1] ^ t ^ xtime(a[1] ^ a[2]),
            a[2] ^ t ^ xtime(a[2] ^ a[3]),
            a[3] ^ t ^ xtime(a[3] ^ a[0])]


def words_from_round5(round5):
    words = [None] * 28
    words[20:24] = [round5[i:i + 4] for i in range(0, 16, 4)]
    for i in range(23, 3, -1):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = [sb(x) for x in temp[1:] + temp[:1]]
            temp[0] ^= bv(1 << (i // 4 - 1))
        words[i - 4] = [x ^ y for x, y in zip(words[i], temp)]
    for i in range(24, 28):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = [sb(x) for x in temp[1:] + temp[:1]]
            temp[0] ^= bv(64)
        words[i] = [x ^ y for x, y in zip(words[i - 4], temp)]
    return words


def encrypt(block, words):
    state = [bv(x) ^ words[i // 4][i % 4] for i, x in enumerate(block)]
    for rnd in range(1, 7):
        state = [sb(x) for x in state]
        state = [state[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
        if rnd < 6:
            state = [x for c in range(4) for x in mix(state[4 * c:4 * c + 4])]
        state = [x ^ words[4 * rnd + i // 4][i % 4] for i, x in enumerate(state)]
    return state


def main():
    local = len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[2] == '--check')
    if local:
        aes = AES6(bytes.fromhex(sys.argv[1]))
        column = bytes(aes.keys[5][0])
        flat6 = bytes(x for word in aes.keys[6] for x in word)
        diagonal = bytes(flat6[i] for i in (0, 7, 10, 13))
        plain = bytes(16)
        cipher = aes.encrypt_block(plain)
    else:
        column = bytes.fromhex(sys.argv[1])
        diagonal = bytes.fromhex(sys.argv[2])
        plain = bytes.fromhex(sys.argv[3])
        cipher = bytes.fromhex(sys.argv[4])
    assert len(column) == len(diagonal) == 4 and len(plain) == len(cipher) == 16
    round5 = [z3.BitVec(f'k5_{i}', 8) for i in range(16)]
    words = words_from_round5(round5)
    if local:
        substitutions = [(x, bv(y)) for x, y in zip(round5, bytes(v for word in aes.keys[5] for v in word))]
        symbolic_key = bytes(z3.simplify(z3.substitute(x, substitutions)).as_long()
                             for word in words[:4] for x in word)
        symbolic_cipher = bytes(z3.simplify(z3.substitute(x, substitutions)).as_long()
                                for x in encrypt(plain, words))
        print('model_check', symbolic_key == bytes.fromhex(sys.argv[1]),
              symbolic_cipher == cipher, flush=True)
        if len(sys.argv) == 3:
            return
    solver = z3.Solver()
    solver.set(timeout=60000)
    for i, value in enumerate(column):
        solver.add(round5[i] == bv(value))
    for i, value in zip((0, 7, 10, 13), diagonal):
        solver.add(words[24 + i // 4][i % 4] == bv(value))
    for expression, value in zip(encrypt(plain, words), cipher):
        solver.add(expression == bv(value))
    start = time.monotonic()
    result = solver.check()
    print('result', result, 'seconds', round(time.monotonic() - start, 2), flush=True)
    if result == z3.sat:
        model = solver.model()
        print('round5', bytes(model.eval(x).as_long() for x in round5).hex())
        print('key', bytes(model.eval(x).as_long() for word in words[:4] for x in word).hex())


if __name__ == '__main__':
    main()
