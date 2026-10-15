#!/home/jimmy/ctfenv/bin/python
# usage: python pwn_template.py [GDB] | [REMOTE HOST=x PORT=y]   (edit BIN)
from pwn import *

BIN = './chall'
context.binary = elf = ELF(BIN, checksec=True)
context.log_level = 'info'
libc = None  # ELF('./libc.so.6')


def start():
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    if args.GDB:
        return gdb.debug(BIN, 'b main\nc')
    return process(BIN)


io = start()
# offset = cyclic_find(...); rop = ROP(elf); rop.call(...)
io.interactive()
