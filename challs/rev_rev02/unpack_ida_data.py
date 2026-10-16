"""Recover a contiguous machine-code region from IDA's db/dw/dd/dq listing."""

import argparse
import re


DIRECTIVE = re.compile(r"^\.text:([0-9A-F]{16})\s+(d[bwdq])\s+(.+)$")
WIDTH = {"db": 1, "dw": 2, "dd": 4, "dq": 8}


def parse_number(value):
    value = value.strip()
    if value.endswith("h"):
        return int(value[:-1], 16)
    return int(value, 10)


def parse_values(expr, width):
    result = bytearray()
    for token in expr.split(","):
        token = token.strip()
        duplicate = re.fullmatch(r"(\d+)\s+dup\(([^)]+)\)", token)
        if duplicate:
            count = int(duplicate.group(1))
            value = parse_number(duplicate.group(2))
        else:
            count = 1
            value = parse_number(token)
        result.extend(value.to_bytes(width, "little") * count)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("listing")
    parser.add_argument("start", type=lambda x: int(x, 16))
    parser.add_argument("end", type=lambda x: int(x, 16))
    parser.add_argument("output")
    args = parser.parse_args()
    data = bytearray(args.end - args.start)
    present = bytearray(len(data))
    with open(args.listing, encoding="latin-1") as listing:
        for line in listing:
            match = DIRECTIVE.match(line)
            if not match:
                continue
            address = int(match.group(1), 16)
            if not (args.start <= address < args.end):
                continue
            expr = match.group(3).split(";", 1)[0].strip()
            chunk = parse_values(expr, WIDTH[match.group(2)])
            offset = address - args.start
            if offset + len(chunk) > len(data):
                raise ValueError(f"0x{address:X} extends past end")
            if any(present[offset : offset + len(chunk)]):
                raise ValueError(f"overlap at 0x{address:X}")
            data[offset : offset + len(chunk)] = chunk
            present[offset : offset + len(chunk)] = b"\x01" * len(chunk)
    # IDA decoded these six bytes as instructions inside the data island.
    decoded_island = {0x14005ADB5: bytes.fromhex("004c8d9c24f0")}
    for address, chunk in decoded_island.items():
        if args.start <= address and address + len(chunk) <= args.end:
            offset = address - args.start
            data[offset : offset + len(chunk)] = chunk
            present[offset : offset + len(chunk)] = b"\x01" * len(chunk)
    missing = [args.start + i for i, flag in enumerate(present) if not flag]
    if missing:
        raise ValueError(f"missing {len(missing)} bytes; first 0x{missing[0]:X}")
    with open(args.output, "wb") as output:
        output.write(data)
    print(f"wrote {len(data)} bytes to {args.output}")


if __name__ == "__main__":
    main()
