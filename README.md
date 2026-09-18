# bitplane-extractor

Pull hidden data out of image bit planes. It is the StegOnline "Extract Data"
page as a local CLI — same semantics, byte for byte — plus the part that page
makes you do by hand: it tries every plane combination itself and tells you
which one held something.

```console
$ bitplane challenge.png
[*] 32 planes + contact sheet in challenge_planes_20260918-0021/
[*] image 1095x492 (RGBA)  planes=32  combinations=5488  runs=5488
[*] 8 worker processes

[TOKEN] R3,G1,B4 | order=row bits=msb planeorder=RGBA
        flag{banana_m0nkey_jqvz}

[*] 1 unique hit(s) from 5488 runs
```

You never had to know it was `R3,G1,B4` — that line is the output, not the
input. 5488 combinations, about two seconds.

## Install

```bash
git clone https://github.com/GoSlowPoke168/bitplane-extractor
cd bitplane-extractor
pip install --user -r requirements.txt
ln -sfn "$(pwd)/bitplane.py" ~/.local/bin/bitplane
```

Or as a package, which puts `bitplane` on your PATH for you:

```bash
pipx install .        # or: pip install --user .
```

Python 3.11+ (the path/URI patterns use possessive quantifiers so they
stay linear on long noise runs), numpy and pillow. Nothing else.

## Usage

```bash
bitplane img.png                  # sweep every plane combination (the default)
bitplane img.png --deep           # wider sweep when that finds nothing
bitplane img.png --bits R3,G1,B4  # extract one known combination
bitplane img.png --save out/      # dump hits as out/R3G1B4.bin
```

A sweep of 5488 combinations takes ~2s; `--deep` (49k runs: column order, LSB
order, every channel permutation, looser thresholds) takes ~12s.

## Recipes

**Work an unknown image, in order.** Stop as soon as something lands.

The bare command takes no options on purpose: it sweeps every 1-, 2- and
3-plane combination in row order, MSB first, and prints the planes of
whatever hits. You are not expected to know which planes to ask for - that
is what it tells you. It does not cover column order, LSB ordering, other
channel orderings, 4+ plane stacks, or anything past the first 64 KB of a
plane; that is what the later steps are for.

It also writes every single plane as a PNG into `<image>_planes_<date>/`,
with a labelled contact sheet of all of them. Look at the sheet: a QR code,
a block of drawn text or a logo sitting in one plane has no strings in it
and no detector will ever report it, but it is obvious to an eye. Images
over 4 MP skip this unless you pass `--render DIR`, since the planes of a
43 MP photo run to ~128 MB. `--no-render` turns it off.

```bash
bitplane img.png                        # 1. the sweep, ~2s
bitplane img.png --deep                 # 2. wider, ~16s
bitplane img.png --deep --min-score 0.35 --min-text 6    # 3. loosen the scorer
bitplane img.png --deep --raw-strings | less             # 4. every printable run
```

**Sweep a whole folder of challenge images.**

```bash
for f in *.png *.bmp; do echo "== $f"; bitplane "$f"; done
```

**Only the low bits** — where most LSB stego lives, and much faster than
`--deep` because it skips 30 of the 32 planes.

```bash
bitplane img.png --only-bits 0,1 --all-orders      # <1s
bitplane img.png --only-channels A                 # hiding in the alpha channel
```

**Carve out a file the sweep found.** A `FILE` hit prints the planes and the
orders it used — feed them straight back in, then let the usual tools at it.

```bash
bitplane img.png --bits G2,G3 --bit-order lsb -q --out payload.zip
unzip -l payload.zip
binwalk -e payload.zip        # or: foremost -i payload.zip -o carved/
```

**Pipe the raw bits somewhere else.** `-q --out -` writes the bytes to stdout
and nothing else, so it composes with anything that reads a stream.

```bash
bitplane img.png --bits R0,G0,B0 -q --out - | strings -n 8
bitplane img.png --bits R0,G0,B0 -q --out - | xxd | head
bitplane img.png --bits R0,G0,B0 -q --out - | grep -aio 'password.*'
```

(`binwalk` and `foremost` do not read stdin — write a file with `--out` first.)

**Dump every plane to disk** and go through them by hand, or with other tools.

```bash
bitplane img.png --max-planes 1 --save planes/ --save-all   # R0.bin ... A7.bin
bitplane img.png --deep --save hits/                        # only what hit
```

**See the planes rather than decode them.**

```bash
bitplane img.png --render shots/    # 32 PNGs + shots/contact-sheet.png
xdg-open shots/contact-sheet.png
bitplane img.png --no-render        # ...or skip them entirely
```

**Look at one extraction closely**, the way the StegOnline page shows it.

```bash
bitplane img.png --bits R0,G0,B0                   # ascii + hex, first 2500 bytes
bitplane img.png --bits R0,G0,B0 --scan            # ...plus the detectors
bitplane img.png --bits R0,G0,B0 --list-strings 6  # ...plus every string
bitplane img.png --bits R0 --show 0 | less         # the whole plane
```

**Hunt one specific format** when you already know the competition's flag
shape — this runs on top of the general detection, it does not replace it.

```bash
bitplane img.png --pattern 'HTB\{[^}]+\}'
bitplane img.png --deep --pattern '[A-Za-z0-9+/]{40,}={0,2}'   # base64 blobs
```

**Reproduce a StegOnline result exactly.** Its checkbox grid maps to `--bits`,
and the three dropdowns map one-to-one.

```bash
bitplane img.png --bits R3,G1,B4 --order row --bit-order msb --plane-order RGB
```

## What it reports

Detection is competition-agnostic — no flag prefixes or keyword lists. A
decoded stream is reported when it contains:

| kind | fires on |
| --- | --- |
| `FILE` | a known signature at its correct offset (PNG/ZIP/PDF/ELF/tar/...) |
| `TOKEN` | any `name{body}` — 2+ char tag, 4+ char body |
| `STRUCT` | a URI, email address, or unix/windows path |
| `ENCODED` | base64/base32/hex that actually decodes to text or a known file |
| `TEXT` | a printable run scoring high on a readable-text heuristic |
| `MATCH` | your own `--pattern`, if you pass one |

The text heuristic measures character statistics, never words, so it works for
any latin-script language: letter ratio, vowel ratio, vowel/consonant
alternation, case consistency, character-set ordinariness, single-character
dominance, strided repetition (what kills 0x55/0xAA bit noise), and whether a
long run contains spaces. Thresholds scale with length, since 8 random
printable bytes look like a word often enough to drown a sweep while 30 never
do. Tune with `--min-score` / `--min-text`, or bypass it with `--raw-strings`.

## Options

**Sweep scope** — `--max-planes N` (default 3), `--min-planes N`,
`--all-orders`, `--only-channels RGB`, `--only-bits 0,1,7`,
`--limit-bytes N` (bytes decoded per run, default 65536, `0` = whole plane),
`-j N` (worker processes, default 8).

**Sensitivity** — `--min-score F` (0-1, default 0.55), `--min-text N`
(default 12), `--min-str N` (default 8), `--raw-strings`, `--pattern RE`.

**Plane images** — written by default to `<image>_planes_<date>/` (skipped
above 4 MP), `--render DIR` to choose the directory or force it on a large
image, `--no-render` to skip.

**Single extraction** (with `--bits`) — `--order row|col`,
`--bit-order msb|lsb`, `--plane-order RGB|BGR`, `--trim`, `--out FILE` (`-`
for stdout), `--quiet`/`-q` (suppress the ascii/hex report, for piping),
`--scan` (run the sweep's detectors on this one extraction), `--show N`
(`0` = all), `--list-strings N`.

**Saving** — `--save DIR` writes each hitting run's full bytes, named by its
planes (`R3G1B4.bin`, with `_col` / `_lsb` / `_BGR` suffixes only when those
differ from the default, and a real extension when the content is recognised:
`G2G3_lsb.zip`). `--save-all` also writes runs that found nothing.

`--save-all` writes one file per *run*, not per plane combination, so the
orders count too: `--deep` turns each 3-plane combination into 14 runs (2
pixel orders x the distinct orderings of those planes). On a 1095x492 RGBA
image:

| sweep | files | disk at default `--limit-bytes` |
| --- | --- | --- |
| `--max-planes 1` | 32 | 2 MB |
| `--max-planes 2` | 528 | 35 MB |
| default (`--max-planes 3`) | 5488 | 360 MB |
| `--deep` | 49024 | 3.2 GB |

Hits are always written whole; runs that found nothing are truncated to
`--limit-bytes` (default 64 KB, `0` = whole plane). Anything projected over
2 GB stops with the estimate printed and needs `--force`.

## Notes

- Alpha planes are included automatically when the image has transparency.
- Plane order is channel-first: bits are grouped by `--plane-order`, then by
  significance within each channel, then packed MSB-first into bytes. That
  matches StegOnline byte for byte.

## Development

```bash
pip install --user -r requirements.txt pytest
python -m pytest tests/ -q
```

The tests hide payloads of each kind — a flag token, prose, a URL, base64,
hex, a ZIP — in known planes of a generated image, then assert the sweep finds
them; plus the negative half, that a pure-noise image reports nothing and that
known bit-noise strings never score as text. That second half is the one worth
keeping: every loosening of a detector gets measured against it.

## License

MIT, see [LICENSE](LICENSE).
