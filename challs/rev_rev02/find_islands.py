"""List groups of contiguous IDA dq data lines in a function address range."""

import re
import sys

start, end = (int(value, 16) for value in sys.argv[2:4])
pattern = re.compile(r"^\.text:([0-9A-F]{16})\s+dq\s")
addresses = []
with open(sys.argv[1], encoding="latin-1") as listing:
    for line in listing:
        match = pattern.match(line)
        if match:
            address = int(match.group(1), 16)
            if start <= address < end:
                addresses.append(address)

group_start = previous = addresses[0]
for address in addresses[1:]:
    if address - previous > 24:
        print(f"0x{group_start:X}..0x{previous:X}")
        group_start = address
    previous = address
print(f"0x{group_start:X}..0x{previous:X}")
