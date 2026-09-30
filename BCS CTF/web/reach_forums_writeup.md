# Reach Forums — CTF Writeup

## Challenge Information

**Challenge name:** Reach Forums  
**Category:** OSINT / Web / Forensics  
**Flag format:** `bcsctf{Physical_Address}`  
**Final flag:**

```text
bcsctf{3c_Kalindi_Tower_Dhaka_Bangladesh}
```

---

## 1. Challenge Goal

The challenge asked us to investigate a hidden forum called **Reach Forums**. The objective was to identify a Reach Forums admin or seller and recover the **physical address** connected to the target.

The final flag rule was:

1. Take the physical address.
2. Remove commas.
3. Replace spaces with underscores.
4. Wrap it inside `bcsctf{}`.

---

## 2. Initial Access

The challenge provided a clearweb Reach Forums instance.

```text
http://172.16.38.22:8888
```

From the clearweb page, the active onion mirror was discovered:

```text
scxyokpjskaeufbggynttrrt4bm47qopdwez3v7cef4auwkqah77slad.onion
```

The forum required login. The register page asked for a 4-digit invite code. After testing, the valid invite code was found:

```text
0777
```

A new account was created and used for enumeration:

```text
username: u0777_rhttq
password: Pass12345
```

After login, the forum index became accessible.

---

## 3. Important Thread Discovery

Inside the forum, the most important thread was:

```text
/thread/5
```

Thread title:

```text
[WTS] Exclusive e-commerce bypass (No 3DS required)
```

The thread was started by the user:

```text
magstripe
```

The first post was redacted by the server and displayed only:

```text
This post has been taken down due to potential policy violations.
```

Early replies in the thread gave two useful hints:

```text
If that modified gateway name is anything to go by, I think I know exactly which site you are targeting. Watch your back.
```

and:

```text
You need to redact your proof better. Smart people can reverse-engineer that with less information.
```

These lines suggested that the answer was not directly visible in the redacted post, but there was probably some **proof image**, **gateway name**, or **partial leaked information** that could be used to recover the target.

---

## 4. Dead Ends and Failed Paths

Several common approaches were tested before finding the correct path.

### 4.1 SSTI Test

A basic Jinja/SSTI payload was posted in both the thread body and title:

```text
{{7*7}}
```

If SSTI worked, the output should have become:

```text
49
```

However, the payload rendered literally in both locations:

```html
<pre>{{7*7}}</pre>
```

and:

```html
<h2>{{7*7}}</h2>
```

So SSTI was not useful.

---

### 4.2 Hidden / Raw Thread Endpoints

Several raw, staff, admin, and API-like endpoints were checked:

```text
/thread/5/raw
/thread/5/original
/thread/5?raw=1
/thread/5?show=raw
/thread/5?unredacted=1
/thread/5?admin=1
/thread/5?staff=1
/thread/5?debug=1
/api/thread/5
/api/posts/5
/api/thread/5/raw
/admin/thread/5
/admin/posts
/moderate/thread/5
/redaction/thread/5
/audit/thread/5
/staff/thread/5
/staff/redaction/thread/5
```

Most of these either:

- redirected to a Wikipedia rabbit hole,
- returned 404,
- or displayed the same redacted post.

The visible thread also contained many prompt-injection style posts asking a redaction AI to reveal the original post. These were decoys and did not reveal the actual hidden content.

---

### 4.3 Flask Session Forgery Attempt

The Flask session cookie decoded to:

```json
{"user_id": 549}
```

A weak secret-key attack was attempted using `flask-unsign` with a small wordlist:

```bash
flask-unsign --unsign --cookie "$COOKIE" --wordlist secrets.txt
```

The tool decoded the session but failed to find the secret key:

```text
[*] Session decodes to: {'user_id': 549}
[!] Failed to find secret key after 24 attempts.
```

So session forgery was not the intended route.

---

## 5. Searching for the Real Clue

Because the thread hinted at a badly redacted proof, all downloaded forum pages were searched for words related to:

- gateway
- proof
- image
- bypass
- 3DS
- checkout
- payment
- site
- domain
- magstripe

The search command was:

```bash
grep -RniaE 'gateway|modified|targeting|target|reverse|less information|proof|bypass|3DS|No 3DS|e-commerce|checkout|payment|merchant|site|domain|URL|http|www|shop|store|cart|magstripe|hidden|original' \
all_threads thread5_full.html 2>/dev/null | head -300
```

This revealed an important image reference in another thread:

```html
<img src="http://reached4lhlibrqmzj7h2n4unu7wdzkg7gczcggufbqufwmefhdbkrd9.onion/images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png">
```

The old onion host was:

```text
reached4lhlibrqmzj7h2n4unu7wdzkg7gczcggufbqufwmefhdbkrd9.onion
```

The image path was:

```text
/images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png
```

This looked like a stored proof image from the old Reach Forums mirror.

---

## 6. Recovering the Proof Image

First, the old onion was tried:

```bash
OLD="reached4lhlibrqmzj7h2n4unu7wdzkg7gczcggufbqufwmefhdbkrd9.onion"
IMG="/images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png"

curl --proxy "$PROXY" -i -L --max-time 30 "http://$OLD$IMG" -o old_proof.out
```

This failed because the old onion was not reachable:

```text
curl: (97) cannot complete SOCKS5 connection
```

Then the same image path was tested on the active onion:

```bash
IMG="/images/60331f1fcbf9b44c3712c2efa87e81558a62b997.png"

curl --proxy "$PROXY" -i -L --max-time 30 "http://$ONION$IMG" -o active_proof.out
```

This worked and returned a PNG file:

```text
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 144130
```

Because the output file contained both HTTP headers and PNG data, the PNG had to be carved from the response.

```bash
python3 - <<'PY'
data=open("active_proof.out","rb").read()
idx=data.find(b"\x89PNG\r\n\x1a\n")
print("PNG offset:", idx)
open("active_proof.png","wb").write(data[idx:])
PY

file active_proof.png
identify active_proof.png 2>/dev/null
```

The recovered file was valid:

```text
active_proof.png: PNG image data, 838 x 486, 8-bit/color RGB, non-interlaced
```

---

## 7. Inspecting the Image

The image was opened locally:

```bash
xdg-open active_proof.png
```

It showed a terminal-style proof-of-concept output. The relevant text was:

```text
[+] Starting proof-of-concept
[+] Using profile: "main"
[+] Cart total: 1498.67
[+] Target charge amount: 0.01

[HTTP] POST /api/checkout/create
-> 200 OK (checkout_id=484b7cab-fc8d-4a21-2da4-a776e15a4e)
[HTTP] POST /api/payment/authorize
-> 200 OK (auth_id=AUTH-533874)
[HTTP] POST /api/payment/capture
-> 200 OK (captured_amount=0.01)
[HTTP] GET /api/order/summary?checkout_id=484b7cab-fc8d-4a21-2da4-a776e15a4e
-> 200 OK

Order summary
Order ID: 965979
Gateway: TLS-COMMERZ
Status: PAYMENT_CAPTURED
Total items: 7
Total charged: 0.01

Billing name: John
Billing email: card1ng.exp@protonmail.me
Shipping address: 3c, Kalindi Tower, Dhaka, Bangladesh
Shipping method: tracked courier
Shipping status: LABEL_CREATED

Notes:
merchant backend shows order as PAID_IN_FULL
You will receive the product within 24 hours in shipping address
```

The physical address was therefore:

```text
3c, Kalindi Tower, Dhaka, Bangladesh
```

---

## 8. Flag Construction

The challenge required:

- remove commas
- replace spaces with underscores
- wrap with `bcsctf{}`

Original address:

```text
3c, Kalindi Tower, Dhaka, Bangladesh
```

Remove commas:

```text
3c Kalindi Tower Dhaka Bangladesh
```

Replace spaces with underscores:

```text
3c_Kalindi_Tower_Dhaka_Bangladesh
```

Final flag:

```text
bcsctf{3c_Kalindi_Tower_Dhaka_Bangladesh}
```

---

## 9. Why This Was the Correct Route

The redacted first post did not reveal the address directly. However, the early replies gave the real solving direction:

1. The post contained a modified payment gateway name.
2. The proof was badly redacted.
3. The proof could be reverse-engineered.

The forum contained many fake posts and prompt-injection decoys, but the real evidence was the proof image left accessible under the old image path. Even though the old onion was down, the same file was still available from the active onion under the same `/images/` path.

The proof image revealed the actual shipping address, which matched the challenge requirement.

---

## Final Answer

```text
bcsctf{3c_Kalindi_Tower_Dhaka_Bangladesh}
```
