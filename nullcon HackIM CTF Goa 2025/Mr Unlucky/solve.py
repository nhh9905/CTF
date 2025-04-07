#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

exe = ELF("./mr_unlucky", checksec=False)
libc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

libc.srand(libc.time(0))
# ko dung after

hero = ["Anti-Mage", "Axe", "Bane", "Bloodseeker", "Crystal Maiden", "Drow Ranger", "Earthshaker", "Juggernaut", "Mirana", "Morphling", 
"Phantom Assassin", "Pudge", "Shadow Fiend", "Sniper", "Storm Spirit", "Sven", "Tiny", "Vengeful Spirit", "Windranger", "Zeus"]

for i in range(50):
	p.sendline(hero[libc.rand() % 20]) 

p.interactive()