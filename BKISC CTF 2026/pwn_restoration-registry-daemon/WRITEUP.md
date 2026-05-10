# Restoration Registry Daemon writeup

## Running locally

The challenge Docker setup copies the files under `src/` into `/opt/chal`, exposes port `5000`, and starts:

```bash
/opt/chal/entrypoint.sh
```

The entrypoint creates the local flag:

```bash
echo "BKISC{FLAG}" > /opt/chal/flag.txt
```

Then it runs:

```bash
python3 /opt/chal/server.py
```

The service listens on `0.0.0.0:5000` by default. Connect with:

```bash
nc 127.0.0.1 5000
```

The prompt is:

```text
rrd>
```

## Process model

`server.py` is a TCP proxy. For each client session, it creates a socketpair and spawns two binaries:

```text
registryd   <->   directoryd
```

The TCP client talks only to `registryd` through stdin/stdout. `registryd` and `directoryd` communicate over the socketpair fd passed as `RRD_IPC_FD`.

`directoryd` has stdin/stdout/stderr redirected to `/dev/null`, so it cannot be reached directly from the client.

## Binary summary

Both binaries are stripped 64-bit PIE executables with NX, stack canaries, and full RELRO.

`registryd` imports heap and I/O functions such as `malloc`, `free`, `read`, `write`, `fgets`, `puts`, `fwrite`, `strncpy`, and the C23 integer parsers. `directoryd` imports `read`, `write`, `getrandom`, string helpers, and the C23 signed integer parser.

`registryd` also installs a seccomp policy that blocks `execve`, `execveat`, executable `mmap`, and `mprotect`-style permission changes. The exploit therefore uses open/read/write ROP instead of shellcode or `system("/bin/sh")`.

## Client protocol

The main commands are:

```text
HELLO <name>
RESERVE <slot> <type> <name>
NOTE <slot> <note>
STAGE <slot> <length>
SEAL <slot>
MIRROR <slot> <archive>
REPLAY <archive> <target-slot>
FETCH <slot> <length>
ARCHIVE <slot>
RETIRE <slot>
QUIT
```

`STAGE` is special. After the line is parsed, `registryd` prints `READY` and reads exactly the requested number of raw bytes.

The relevant type table is:

| Type | Allocation size | Max `STAGE` size |
|---:|---:|---:|
| 1 | `0x20` | `0x18` |
| 2 | `0x100` | `0xe8` |
| 3 | `0x430` | `0x338` |

## IPC protocol

The registry/directory IPC frame is `0x78` bytes and starts with magic `1DRR`.

The directory process tracks logical records and archives. The registry process tracks the actual heap buffers. This split is the source of the bug: directory operations can make the registry duplicate heap pointers without ownership tracking.

## Vulnerability

The vulnerability is a heap use-after-free caused by `MIRROR` and `REPLAY` aliasing a registry heap pointer.

The vulnerable flow is:

1. `RESERVE` allocates a heap buffer for a registry record.
2. `SEAL` makes the record eligible for mirroring.
3. `MIRROR` puts the record into an archive, but the registry archive stores the same heap pointer.
4. `REPLAY` creates a second registry record from the archive, again with the same heap pointer.
5. `RETIRE` frees only one local record's pointer.
6. The other local record still points to the freed chunk.
7. `FETCH` gives a UAF read and `STAGE` gives a UAF write.

This is the minimal shape:

```text
RESERVE A
SEAL A
MIRROR A -> archive
REPLAY archive -> B
RETIRE A
FETCH B / STAGE B   # B is now a UAF alias
```

## From UAF to arbitrary read/write

The exploit uses type-2 chunks, which allocate `0x100` bytes and are managed by tcache.

Two same-sized chunks are allocated, mirrored/replayed, and retired. The second freed chunk contains a safe-linked tcache `fd`. Because the two chunks were consecutive, the exploit solves the safe-linking equation and recovers both heap addresses:

```text
encoded_fd = A ^ (B >> 12)
B = A + 0x110
```

Then it poisons the tcache list so the next `malloc(0x100)` returns inside `registryd`'s own local record table. The target is `record[23].ptr - 8`, because glibc requires a 16-byte-aligned tcache pointer.

After that, slot 5 points at the metadata for record 23. By staging into slot 5, the exploit can set:

```text
record[23].ptr  = any address
record[23].size = large
record[23].type = 3
record[23].state = active
```

Now:

```text
FETCH 23 n
```

is an arbitrary read, and:

```text
STAGE 23 n
```

is an arbitrary write.

## Address discovery

The exploit avoids hardcoded libc offsets.

It derives the registry PIE base from the heap leak:

```text
heap_page = leaked_chunk & ~0xfff
registry_pie = heap_page - 0x7000
```

This works because the registry binary's writable load segment ends at `PIE + 0x6ba0`, and the process heap starts at the next page.

Then it reads `read@GOT` from `registryd`, scans backward to find libc's ELF header, and parses libc's in-memory dynamic section. It resolves:

```text
__libc_stack_end
open
read
write
exit
__libc_start_main
```

It also scans libc's executable load segment for the required ROP gadgets.

## Shadow-stack issue and bypass

A direct stack ROP overwrite of `main`'s saved return address is detected and terminates the process with:

```text
control protection fault
```

The reason is that `registryd` and `directoryd` implement a software shadow-stack protocol over IPC.

The bypass is to overwrite the saved return address of the live libc `read` call used by `STAGE` itself. The final step is:

1. Use the arbitrary read to locate the stack slot used by command-frame libc calls.
2. Point record 23 at that stack slot.
3. Send `STAGE 23 <payload length>`.
4. Wait for `READY`.
5. Send the ROP chain as raw bytes.

The ROP chain is copied over `read`'s return address while `read` is still executing. When `read` returns, it jumps directly into the ROP chain before the registry's software control-protection check can run.

## Final payload

The ROP chain does:

```text
open("/opt/chal/flag.txt", 0)
read(3, stack_buffer, 0x100)
write(1, stack_buffer, 0x100)
exit(...)
```

The script expects the opened flag fd to be `3`; in the server subprocess, fd 0/1/2 are the TCP proxy pipes and the IPC socketpair is passed at a higher fd, leaving fd 3 as the first available descriptor.

## Why no forbidden leak is used

The exploit does not read `/proc`, sysfs, Docker metadata, process environment strings, cwd, argv, or host-specific files. It obtains every address through the challenge bug:

- heap address through UAF tcache metadata,
- PIE base through the heap/`brk` relationship,
- libc pointer through `registryd`'s GOT using the arbitrary read,
- libc symbols by parsing libc in memory,
- a stack-range hint through libc/ld `__libc_stack_end` using the arbitrary read, without reading process environment strings or argv contents.

The final exploit only talks to the TCP service.

## Running the exploit

Local:

```bash
python3 solve.py --host 127.0.0.1 --port 5000
```

Remote:

```bash
python3 solve.py --host HOST --port PORT
```

Example successful output:

```text
[+] tcache fd leak: enc=..., A=..., B=...
[+] heap base ~= ..., PIE base = ...
[+] read@GOT = ...
[+] libc base = ...
[+] resolved symbols: __libc_stack_end=..., open=..., read=..., write=..., exit=...
[+] gadgets: ret=..., pop_rdi=..., pop_rsi=..., pop_rdx=...
[+] __libc_stack_end -> ...
[+] selected live read-return stack slot ...
[+] arming record 23 to overwrite live read return ...
[+] flag: BKISC{FLAG}
```
