"""Measure how much of an IDA function Keystone can reassemble.

This is a feasibility probe, not a complete PE rebuilder. It deliberately
reports encoding length mismatches because padding altered instructions would
make control flow unreliable.
"""

import re
import sys
from bisect import bisect_right

from keystone import KS_ARCH_X86, KS_MODE_64, Ks


LINE = re.compile(r"^\.text:([0-9A-F]{16})\s+(.+?)\s*$")
HEX = re.compile(r"(?<![\w])([0-9A-F]+)h\b", re.I)
AUTO = re.compile(r"\b(?:sub|loc|off|unk|byte|word|dword|qword|xmmword|ymmword|stru|jpt|def)_(140[0-9A-F]{6,})\b", re.I)
VAR = re.compile(r"\b(var|arg)_([0-9A-F]+)\b", re.I)
CODE = re.compile(r"^(?:[a-z][a-z0-9]*|rep\w*|lock)\s*(?:$|\s)", re.I)
LOCAL_DEF = re.compile(r"^([A-Za-z_]\w*)\s*=\s+(byte|word|dword|qword|xmmword|ymmword) ptr\s+([-+]?[0-9A-F]+h)", re.I)
IMPORT = re.compile(r"^\.idata:([0-9A-F]{16})\s+extrn __imp_(\w+):qword")
DATA_REF = re.compile(r"\b(byte|word|dword|qword|xmmword|ymmword|ymmword)_(140[0-9A-F]{6,})\b", re.I)
THUNK = re.compile(r"^\.text:([0-9A-F]{16})\s+; \[.*COLLAPSED FUNCTION (\w+)\.")


def normalize(body, address, locals_, imports, thunks):
    body = body.split(";", 1)[0].strip()
    body = body.replace("retn", "ret")
    body = body.replace("cs:", "").replace("ds:", "")
    for name in set(re.findall(r"\b[A-Za-z_]\w*\b", body)) & locals_.keys():
        value, kind = locals_[name]
        if re.search(rf"\[.*\b{re.escape(name)}\b.*\]\s*,\s*(?:[0-9A-F]+h|0x[0-9A-F]+|0)$", body, re.I):
            body = re.sub(r"\b(mov|cmp)\s+\[", rf"\1 {kind} ptr [", body, count=1, flags=re.I)
        body = re.sub(rf"\b{re.escape(name)}\b", value, body)
    body = re.sub(r"\b(?:short|near ptr|far ptr)\b\s*", "", body, flags=re.I)
    body = re.sub(r"\boffset\s+", "", body, flags=re.I)
    body = body.replace("$+5", f"0x{address + 5:X}")
    body = VAR.sub(lambda m: ("-0x" if m[1].lower() == "var" else "+0x") + m[2], body)
    imported = re.fullmatch(r"call\s+(\w+)", body, re.I)
    if imported and imported[1] in thunks:
        body = f"call 0x{thunks[imported[1]]:X}"
    elif imported and imported[1] in imports:
        target = imports[imported[1]]
        body = f"call qword ptr [rip + {target - address - 6}]"
    def data_operand(match):
        width = 7 if match[1].lower() in ("qword", "xmmword", "ymmword") else 6
        reference = f"[rip + {int(match[2], 16) - address - width}]"
        return reference if body[: match.start()].rstrip().endswith("ptr") else f"{match[1]} ptr {reference}"

    body = DATA_REF.sub(data_operand, body)
    body = AUTO.sub(lambda m: "0x" + m[1], body)
    body = HEX.sub(lambda m: "0x" + m[1], body)
    body = re.sub(
        r"\[rip \+ (-?\d+)\]\+0x([0-9A-F]+)",
        lambda match: f"[rip + {int(match[1]) + int(match[2], 16)}]",
        body,
        flags=re.I,
    )
    body = body.replace("+-", "-")
    # RIP-relative data operand; fixed seven-byte LEA or six-byte MOV here.
    lea = re.match(r"(lea\s+\w+,\s*)(0x[0-9A-F]+)(?:\+(0x[0-9A-F]+))?$", body, re.I)
    if lea:
        target = int(lea[2], 16) + (int(lea[3], 16) if lea[3] else 0)
        body = f"{lea[1]}[rip + {target - address - 7}]"
    memory = re.search(r"\b(byte|word|dword|qword|xmmword|ymmword) ptr\s+(0x[0-9A-F]+)\b", body, re.I)
    if memory:
        target = int(memory[2], 16)
        width = 7 if memory[1].lower() in {"qword", "xmmword", "ymmword"} else 6
        body = body[: memory.start()] + f"{memory[1]} ptr [rip + {target - address - width}]" + body[memory.end() :]
    return body


def main():
    listing, first, last = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
    rows = []
    locals_ = {}
    imports = {}
    thunks = {}
    with open(listing, encoding="latin-1") as source:
        for line in source:
            imported = IMPORT.match(line)
            if imported:
                imports[imported[2]] = int(imported[1], 16)
            thunk = THUNK.match(line)
            if thunk:
                thunks[thunk[2]] = int(thunk[1], 16)
            match = LINE.match(line)
            if not match:
                continue
            address = int(match[1], 16)
            if first <= address < last:
                body = match[2]
                definition = LOCAL_DEF.match(body)
                if definition:
                    locals_[definition[1]] = (definition[3], definition[2])
                    continue
                if CODE.match(body) and not body.startswith(("db ", "dw ", "dd ", "dq ", "align ")):
                    rows.append((address, body))
    assembler = Ks(KS_ARCH_X86, KS_MODE_64)
    okay = wrong = failed = 0
    addresses = [address for address, _ in rows]
    for address, body in rows:
        cleaned = normalize(body, address, locals_, imports, thunks)
        try:
            encoded, _ = assembler.asm(cleaned, addr=address)
        except Exception as exc:
            failed += 1
            if failed <= 30:
                print(f"FAIL {address:X} {cleaned!r}: {exc}")
            continue
        if not encoded:
            failed += 1
            continue
        # The following printed address is often the end of this instruction.
        next_index = bisect_right(addresses, address)
        span = addresses[next_index] - address if next_index < len(addresses) else None
        if span is not None and len(encoded) != span:
            wrong += 1
            if wrong <= 30:
                print(f"LENGTH {address:X} {len(encoded)} != {span}: {cleaned}")
        else:
            okay += 1
    print(f"matched={okay} length_mismatch={wrong} failed={failed} total={len(rows)}")


if __name__ == "__main__":
    main()
