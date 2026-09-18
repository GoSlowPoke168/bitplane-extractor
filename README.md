# bitplane.py

Bit-plane extractor and brute-forcer for image steganography — the StegOnline
"Extract Data" page as a local CLI, plus a sweep that tries every plane
combination for you and reports what looks meaningful.

## Setup

```bash
pip install --user numpy pillow
ln -sfn "$(pwd)/bitplane.py" ~/.local/bin/bitplane
```

## Usage

```bash
bitplane img.png                  # sweep every plane combination (the default)
bitplane img.png --deep           # wider sweep when that finds nothing
bitplane img.png --bits R3,G1,B4  # extract one known combination
bitplane img.png --save out/      # dump hits as out/R3G1B4.bin
```

A sweep of 5488 combinations takes ~2s; `--deep` (33k runs: column order, LSB
order, every channel permutation, looser thresholds) takes ~16s.

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

**Single extraction** (with `--bits`) — `--order row|col`,
`--bit-order msb|lsb`, `--plane-order RGB|BGR`, `--trim`, `--out FILE`,
`--scan` (run the sweep's detectors on this one extraction), `--show N`,
`--list-strings N`.

**Saving** — `--save DIR` writes each hitting run's full bytes, named by its
planes (`R3G1B4.bin`, with `_col` / `_lsb` / `_BGR` suffixes only when those
differ from the default, and a real extension when the content is recognised:
`G2G3_lsb.zip`). `--save-all` also writes runs that found nothing — one file
per combination, truncated to `--limit-bytes`.

## Notes

- Alpha planes are included automatically when the image has transparency.
- Plane order is channel-first: bits are grouped by `--plane-order`, then by
  significance within each channel, then packed MSB-first into bytes. That
  matches StegOnline byte for byte.
