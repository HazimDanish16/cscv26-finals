"""Best-effort reconstruction of phantom.exe's .text from its IDA listing.

Outputs a flat image at its original VA. The report lists unencoded locations;
the image must not be treated as runnable until those affecting a trace are fixed.
"""

import argparse
import re

from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from asm_probe import CODE, IMPORT, LINE, LOCAL_DEF, THUNK, normalize
from unpack_ida_data import DIRECTIVE, WIDTH, parse_values


FIRST = 0x140001000
LAST = 0x140112C00
LABEL = re.compile(r"^\.[A-Za-z]+:([0-9A-F]{16})\s+([A-Za-z_]\w+)\s+(?:db|dw|dd|dq|proc|equ)\b")
FUNCTION_START = re.compile(r"^sub_[0-9A-F]+\s+proc\b")
DATA_START = re.compile(r"^(?:db|dw|dd|dq|align|org|extrn|assume|segment|ends|endp)\b", re.I)


def symbol_replace(body, symbols):
    def replace(match):
        name = match[0]
        if re.match(r"^(?:sub|loc|locret|off|unk|byte|word|dword|qword|xmmword|ymmword|stru|jpt|def)_140[0-9A-F]+$", name, re.I):
            return name
        return f"0x{symbols[name]:X}" if name in symbols else name

    return re.sub(r"\b[A-Za-z_]\w*\b", replace, body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("listing")
    parser.add_argument("output")
    parser.add_argument("report")
    args = parser.parse_args()

    symbols = {}
    imports = {}
    thunks = {}
    lines = []
    with open(args.listing, encoding="latin-1") as source:
        for line in source:
            match = LABEL.match(line)
            if match:
                symbols[match[2]] = int(match[1], 16)
            match = IMPORT.match(line)
            if match:
                imports[match[2]] = int(match[1], 16)
            match = THUNK.match(line)
            if match:
                thunks[match[2]] = int(match[1], 16)
            if line.startswith(".text:"):
                lines.append(line)

    image = bytearray(b"\xCC" * (LAST - FIRST))
    occupied = bytearray(len(image))
    assembler = Ks(KS_ARCH_X86, KS_MODE_64)
    locals_ = {}
    failures = []
    stats = {"instructions": 0, "raw_bytes": 0, "thunks": 0, "failed": 0}

    for line in lines:
        match = LINE.match(line)
        if not match:
            continue
        address = int(match[1], 16)
        if not FIRST <= address < LAST:
            continue
        body = match[2].split(";", 1)[0].strip()
        if not body:
            continue
        if FUNCTION_START.match(body):
            locals_ = {}
            continue
        definition = LOCAL_DEF.match(body)
        if definition:
            locals_[definition[1]] = (definition[3], definition[2])
            continue
        offset = address - FIRST
        directive = DIRECTIVE.match(line)
        if directive:
            expression = directive[3].split(";", 1)[0].strip()
            try:
                chunk = parse_values(expression, WIDTH[directive[2]])
            except Exception as exc:
                failures.append((address, body, str(exc)))
                stats["failed"] += 1
                continue
            if offset + len(chunk) <= len(image):
                image[offset : offset + len(chunk)] = chunk
                occupied[offset : offset + len(chunk)] = b"\x01" * len(chunk)
                stats["raw_bytes"] += len(chunk)
            continue
        if DATA_START.match(body) or not CODE.match(body):
            continue
        head = body.split(None, 1)[0]
        if head.endswith(":") or head.startswith(("loc_", "algn_", "def_", "jpt_", "sub_", "var_", "arg_")):
            continue
        try:
            cleaned = normalize(symbol_replace(body, symbols), address, locals_, imports, thunks)
            encoded, _ = assembler.asm(cleaned, addr=address)
            if not encoded:
                raise ValueError("empty encoding")
            if offset + len(encoded) > len(image):
                raise ValueError("past .text end")
            image[offset : offset + len(encoded)] = bytes(encoded)
            occupied[offset : offset + len(encoded)] = b"\x01" * len(encoded)
            stats["instructions"] += 1
        except Exception as exc:
            failures.append((address, body, str(exc)))
            stats["failed"] += 1

    # Imported calls in the listing use five-byte calls to these six-byte thunks.
    for name, address in thunks.items():
        if name not in imports or not FIRST <= address + 6 <= LAST:
            continue
        offset = address - FIRST
        displacement = imports[name] - address - 6
        image[offset : offset + 6] = b"\xFF\x25" + (displacement & 0xFFFFFFFF).to_bytes(4, "little")
        occupied[offset : offset + 6] = b"\x01" * 6
        stats["thunks"] += 1

    with open(args.output, "wb") as output:
        output.write(image)
    with open(args.report, "w") as report:
        for address, body, error in failures:
            report.write(f"{address:016X}\t{body}\t{error}\n")
    print(stats)
    print(f"covered={sum(occupied)}/{len(image)} bytes")
    print(f"output={args.output} report={args.report}")


if __name__ == "__main__":
    main()
