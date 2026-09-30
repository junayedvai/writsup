# Old 80s Trend — BCS CTF Writeup

**Category:** Misc · **Difficulty:** Medium · **Points:** 298 · **Author:** HxN0n3

**Flag:** `bcsctf{EASYTOFINDOUTTHESECIPHER}`

## Challenge

> The world is back in the 80's
>
> Find out the code and enclose it with bcsctf{} before submitting.

The attachment is `chall.png`, a picture of a retro 80s living room. An old CRT TV in it shows a screen full of coloured squares.

## Recon

I checked the file itself first:

- `file` and PIL: a plain 1000×707 RGBA PNG.
- `exiftool` and `strings`: nothing useful.

So the data is in what the image shows, not hidden in the file.

## Spotting the cipher

A close crop of the TV screen shows two kinds of area:

- **Top and bottom:** random blurred colour noise that acts as a decoy.
- **Middle:** a sharp band outlined in white. It holds **12 blocks, each 2 columns wide and 6 rows tall**.

Every square in the band is one of six colours: red, green, blue, yellow, cyan or magenta. Rectangular blocks built only from those six colours are the signature of **Hexahue**. In Hexahue, each letter is a **2×3 block**, and each of the six colours appears exactly once per block. That means each 2×6 block on the screen holds two letters stacked on top of each other.

## Extracting the grid

I cropped the screen and scaled it up 4× with nearest-neighbour resampling. Then I sampled the centre of each cell and rounded every channel to 0 or 1 to get the colour:

```python
from PIL import Image

im = Image.open('chall.png').convert('RGB')
im = im.crop((420, 150, 770, 420)).resize((1400, 1080), Image.NEAREST)

cols = {(1,0,0):'R', (0,1,0):'G', (0,0,1):'B',
        (1,1,0):'Y', (0,1,1):'C', (1,0,1):'M'}

for r in range(6):
    y = int(385 + r * 50.5)
    line = ''
    for b in range(12):
        for c in range(2):
            x = int(38 + b * 108.9 + 26 + c * 52)
            p = im.getpixel((x, y))
            line += cols[tuple(int(v > 128) for v in p)]
        line += ' '
    print(line)
```

Output:

```
RG MR BC CM BC YB RG GY YB RG YB BC
YB GY MY RG MR CM YB BR CG YM CM MR
MC BC RG BY YG GR CM CM MR BC GR GY
BC BC GY RG BC RG RG GY YB GY RG BC
MR MR RB YB MY YB MY BR CM RB YB YM
YG YG CM MC RG MC BC CM RG CM MC RG
```

## Decoding

I split each column into its top 3 rows and bottom 3 rows, then looked each 2×3 pattern up in the Hexahue alphabet. For example, `RG / YB / MC` is **E** and `MR / GY / BC` is **A**.

| Block      | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|------------|---|---|---|---|---|---|---|---|---|----|----|----|
| Top half   | E | A | S | Y | T | O | F | I | N | D  | O  | U  |
| Bottom half| T | T | H | E | S | E | C | I | P | H  | E  | R  |

Reading the top row, then the bottom row:

```
EASYTOFINDOU + TTHESECIPHER = EASYTOFINDOUTTHESECIPHER
```

That is "EASY TO FIND OUT THESE CIPHER".

## Flag

The flag is **case-sensitive**. The lowercase version is rejected; use the uppercase string exactly as decoded:

```
bcsctf{EASYTOFINDOUTTHESECIPHER}
```

## Takeaways

- "80s", "code" and a TV full of colour blocks all point to a colour-based cipher. Six pure RGB/CMY colours in 2×3 groups means Hexahue.
- Ignore the noisy decoy areas and focus on the sharp, bordered region.
- Sample the colours with code instead of reading them by eye, so no cell is misread.
- Submit the decoded text in its original case.
