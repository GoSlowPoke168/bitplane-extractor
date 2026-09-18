#!/usr/bin/env python3
r"""
bitplane.py - bit-plane extractor and brute-forcer for image steganography.

Single extraction (mirrors the StegOnline "Extract Data" page):
    python3 bitplane.py img.png --bits R3,G1,B4
    python3 bitplane.py img.png --bits R0,G0,B0 --order col --bit-order lsb \
            --plane-order BGR --out blob.bin
    python3 bitplane.py img.png --bits R0,G0,B0 --scan     # run the detectors on it

Brute force every plane combination and report whatever looks meaningful:
    python3 bitplane.py img.png                      # sweep - the usual first move
    python3 bitplane.py img.png --deep               # widen it when that finds nothing
    python3 bitplane.py img.png --deep --save out/   # ... and dump hits to out/R3G1B4.bin
    python3 bitplane.py img.png --pattern 'MYCOMP\{[^}]+\}'   # narrow to one format

Detection is competition-agnostic - no flag prefixes or keyword lists anywhere.
A decoded stream is reported when it contains:
    FILE     a known file signature (PNG/ZIP/PDF/ELF/tar/... at the right offset)
    TOKEN    a delimited token of any name, e.g. anything{...}
    STRUCT   a URI, email address, or unix/windows path
    ENCODED  base64/base32/hex that actually decodes to text or a known file
    TEXT     a run scoring high enough on a readable-text heuristic
    MATCH    your own --pattern, if you supply one
"""
import argparse
import base64
import functools
import itertools
import multiprocessing
import os
import re
import sys
from collections import Counter
from datetime import datetime

import numpy as np
from PIL import Image

# ---------------------------------------------------------------- file magics
MAGICS = [
    (0, b"\x89PNG\r\n\x1a\n", "PNG image"),
    (0, b"\xff\xd8\xff", "JPEG image"),
    (0, b"GIF87a", "GIF image"),
    (0, b"GIF89a", "GIF image"),
    (0, b"BM", "BMP image"),
    (0, b"%PDF-", "PDF document"),
    (0, b"PK\x03\x04", "ZIP archive (zip/docx/jar/apk)"),
    (0, b"PK\x05\x06", "ZIP archive (empty)"),
    (0, b"Rar!\x1a\x07", "RAR archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"\x1f\x8b", "GZIP archive"),
    (0, b"BZh", "BZIP2 archive"),
    (0, b"\xfd7zXZ\x00", "XZ archive"),
    (0, b"\x7fELF", "ELF executable"),
    (0, b"MZ", "DOS/PE executable"),
    (0, b"RIFF", "RIFF container (wav/avi/webp)"),
    (0, b"OggS", "OGG media"),
    (0, b"fLaC", "FLAC audio"),
    (0, b"ID3", "MP3 audio"),
    (0, b"\x1aE\xdf\xa3", "Matroska/WebM"),
    (0, b"SQLite format 3\x00", "SQLite database"),
    (0, b"-----BEGIN ", "PEM / OpenSSH key block"),
    (0, b"\xed\xab\xee\xdb", "RPM package"),
    (0, b"!<arch>", "AR archive / .deb"),
    (0, b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
    (0, b"\x25\x21PS", "PostScript"),
    (0, b"<?xml", "XML document"),
    (0, b"<!DOCTYPE", "HTML document"),
    (257, b"ustar", "TAR archive"),
]


def identify(data: bytes):
    hits = []
    for off, sig, name in MAGICS:
        if data[off:off + len(sig)] == sig and _plausible(data, name):
            hits.append(name)
    return hits


def _plausible(data, name):
    """Two-byte magics (BM, MZ) hit by chance once every 64K runs; check a
    second field so a sweep does not report imaginary files."""
    if name == "BMP image":
        size = int.from_bytes(data[2:6], "little")
        return 26 <= size <= len(data) and data[6:10] == b"\x00\x00\x00\x00"
    if name == "DOS/PE executable":
        off = int.from_bytes(data[60:64], "little")
        return 64 <= off <= len(data) - 4 and data[off:off + 2] == b"PE"
    return True


# ---------------------------------------------------------------- image loading
def load_image(path):
    im = Image.open(path)
    if im.mode == "P":
        im = im.convert("RGBA" if "transparency" in im.info else "RGB")
    elif im.mode in ("L", "1", "I", "F"):
        im = im.convert("RGB")
    elif im.mode == "LA":
        im = im.convert("RGBA")
    elif im.mode not in ("RGB", "RGBA"):
        im = im.convert("RGB")
    arr = np.asarray(im, dtype=np.uint8)
    channels = "RGBA"[: arr.shape[2]]
    return arr, channels


class PlaneCache:
    """Flattened 0/1 arrays for every (channel, bit, pixel-order)."""

    def __init__(self, arr, channels):
        self.arr = arr
        self.channels = channels
        self.cache = {}

    def get(self, ch, bit, order):
        key = (ch, bit, order)
        if key not in self.cache:
            plane = self.arr[:, :, self.channels.index(ch)]
            if order == "col":
                plane = plane.T
            self.cache[key] = ((plane.ravel() >> bit) & 1).astype(np.uint8)
        return self.cache[key]

    @property
    def npixels(self):
        return self.arr.shape[0] * self.arr.shape[1]


# ---------------------------------------------------------------- extraction
def order_planes(planes, plane_order, bit_order):
    """planes: list of (channel, bit). Sort by channel priority, then bit significance."""
    prio = {c: i for i, c in enumerate(plane_order)}
    rev = bit_order == "msb"
    return sorted(planes, key=lambda p: (prio.get(p[0], 99), -p[1] if rev else p[1]))


def extract(cache, planes, pixel_order="row", bit_order="msb",
            plane_order="RGBA", trim=False, max_bytes=0):
    planes = order_planes(planes, plane_order, bit_order)
    npx = cache.npixels
    if max_bytes:
        need_px = -(-max_bytes * 8 // len(planes))  # ceil
        npx = min(npx, need_px)
    cols = [cache.get(c, b, pixel_order)[:npx] for c, b in planes]
    bits = np.stack(cols, axis=1).ravel()
    if trim:
        bits = bits[: (bits.size // 8) * 8]
    data = np.packbits(bits, bitorder="big").tobytes()
    if max_bytes:
        data = data[:max_bytes]
    return data


# ---------------------------------------------------------------- presentation
def ascii_view(data, width=64):
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return "\n".join(txt[i:i + width] for i in range(0, len(txt), width))


def hex_view(data, width=64):
    h = data.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


# ---------------------------------------------------------------- detection
# Nothing here knows about any competition, flag prefix or vocabulary. A run of
# bytes is reported when it is structurally interesting: it decodes as a known
# file, it contains an encoded blob that decodes to something real, it looks
# like a delimited token / URI / path, or it scores as human-readable text.

PRINTABLE = rb"[\x20-\x7e]{%d,}"
# tag{...} with any tag and any contents - no vocabulary. The tag and body
# shapes are what keep random braces in bit noise from matching.
DELIMITED = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{1,23}\{([\x20-\x7e]{5,160}?)\}")
BODY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- ")


def struct_ok(s):
    """A URI/email/path shape is cheap for noise to hit by accident - these are
    the properties real ones have: lowercase words, and enough of them."""
    letters = [c for c in s if c.isalpha()]
    lower = sum(c.islower() for c in letters) / len(letters) if letters else 0.0
    if "://" in s:
        return len(letters) >= 4 and lower >= 0.7
    if "@" in s:
        local, _, domain = s.partition("@")
        return len(local) >= 3 and len(domain) >= 5 and lower >= 0.7
    return len(s) >= 10 and len(letters) >= 0.5 * len(s) and lower >= 0.7


def token_ok(body):
    """Flag bodies are overwhelmingly alphanumeric; noise between two random
    braces is not. Rejects Vb{W&+XJ} without touching flag{th1s 1s 4 fl4g!}."""
    return sum(c in BODY_CHARS for c in body) >= 0.7 * len(body)
# scheme://..., user@host.tld, /unix/paths, C:\windows\paths
# possessive quantifiers keep these linear on long noise runs (no backtracking)
STRUCTURED = re.compile(
    r"[a-z][a-z0-9+.\-]{1,15}+://[\x21-\x7e]{3,}+"
    r"|[A-Za-z0-9._%+\-]{1,32}@(?:[A-Za-z0-9\-]{1,32}\.){1,4}[A-Za-z]{2,12}"
    r"|(?:/[A-Za-z0-9._\-]{2,}+){2,}+"
    r"|[A-Za-z]:\\(?:[A-Za-z0-9._\-]++\\?){2,}+")
B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
B32 = re.compile(r"[A-Z2-7]{40,}={0,6}")
HEXRUN = re.compile(r"(?:[0-9a-fA-F]{2}){20,}")

MIN_TEXT_LEN = 12       # below this, random printable runs are indistinguishable
VOWELS = frozenset("aeiouAEIOU")
COMMON = frozenset("abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:;'\"-_/()!?\n")


@functools.lru_cache(maxsize=16)
def _run_rx(minlen):
    return re.compile(PRINTABLE % minlen)


def printable_runs(data, minlen):
    return [m.decode("latin-1") for m in _run_rx(minlen).findall(data)]


def _clamp(x):
    return 0.0 if x < 0 else (1.0 if x > 1 else x)


_PRINT = "".join(chr(i) for i in range(32, 127))
_KEEP_LETTERS = str.maketrans("", "", "".join(c for c in _PRINT if not c.isalpha()))
_KEEP_VOWELS = str.maketrans("", "", "".join(c for c in _PRINT if c not in VOWELS))
_KEEP_COMMON = str.maketrans("", "", "".join(c for c in _PRINT if c not in COMMON))
SAMPLE = 400             # statistics converge long before this; keeps sweeps fast


def text_score(s, threshold=0.0):
    """0..1 estimate that a printable run is meaningful text rather than bit noise.

    Language-agnostic within latin script: it measures character composition,
    vowel/consonant alternation, case consistency and repetition - never words.
    `threshold` lets the cheap character-frequency stage bail out early before
    the per-character loops, which is what makes a full sweep tractable.
    """
    if len(s) < 4:
        return 0.0
    s = s[:SAMPLE]
    n = len(s)
    counts = Counter(s)
    if len(counts) < 4:
        return 0.0
    top = counts.most_common(1)[0][1] / n
    if top > 0.6:
        return 0.0
    for p in range(1, 5):                # pure repetition of a short period
        if n >= 4 * p and s[p:] == s[:-p]:
            return 0.0

    f_letter = len(s.translate(_KEEP_LETTERS)) / n
    f_common = len(s.translate(_KEEP_COMMON)) / n
    letters = len(s.translate(_KEEP_LETTERS))
    f_vowel = (len(s.translate(_KEEP_VOWELS)) / letters) if letters else 0.0

    # running text sits in a narrow band on all three: mostly letters, vowel
    # ratio near 0.36, and almost nothing outside the everyday character set
    cheap = (0.28 * _clamp((f_letter - 0.40) / 0.35)
             + 0.18 * min(_clamp(1 - (0.36 - f_vowel) / 0.22),
                          _clamp(1 - (f_vowel - 0.36) / 0.16))
             + 0.16 * _clamp((f_common - 0.80) / 0.18))
    if cheap + 0.38 < threshold:         # 0.38 = best possible from the rest
        return 0.0

    # adjacent letter pairs that alternate vowel/consonant: ~0.31 for random
    # letters, ~0.55-0.65 for real words in most latin-script languages.
    # Real text is also case-consistent; random letters flip case ~50% of the time.
    pairs = alt = case_flips = 0
    for a, b in zip(s, s[1:]):
        if a.isalpha() and b.isalpha():
            pairs += 1
            if (a in VOWELS) != (b in VOWELS):
                alt += 1
            if a.islower() != b.islower():
                case_flips += 1
    f_alt = alt / pairs if pairs >= 3 else 0.0
    f_case = case_flips / pairs if pairs >= 3 else 0.0

    # positional periodicity: bit noise made of repeating patterns (0x55, 0xAA)
    # drops the same character at a fixed stride; running text almost never does
    ac = 0.0
    for lag in (1, 2, 3, 4):
        if n > lag + 4:
            ac = max(ac, sum(a == b for a, b in zip(s, s[lag:])) / (n - lag))

    words = [w for w in re.split(r"[^A-Za-z']+", s) if w]
    f_word = sum(1 <= len(w) <= 14 for w in words) / len(words) if words else 0.0

    score = cheap + 0.26 * _clamp((f_alt - 0.34) / 0.24) + 0.12 * f_word
    if top > 0.35:                       # one character dominates the run
        score *= _clamp((0.6 - top) / 0.25)
    if f_case > 0.12:                    # aLtErNaTiNg case = noise
        score *= _clamp((0.32 - f_case) / 0.20)
    if ac > 0.22:                        # strided repetition = noise
        score *= _clamp((0.45 - ac) / 0.20)
    if n >= MIN_TEXT_LEN and " " not in s:
        score *= 0.55                    # a real message this long has spaces
    return score


def text_threshold(n, base):
    """Short runs need a higher score: 8 random printable bytes look like a word
    often enough to drown a sweep, 30 of them never do."""
    return min(0.99, base + max(0, 26 - n) * 0.018)


def encoded_blob(s):
    """Encoded payloads that actually decode to something - no false-positive soup."""
    for m in HEXRUN.finditer(s):
        try:
            raw = bytes.fromhex(m.group())
        except ValueError:
            continue
        if identify(raw) or _mostly_printable(raw):
            return "hex -> %r" % raw[:80]
    for rx, dec, name in ((B64, _b64, "base64"), (B32, _b32, "base32")):
        for m in rx.finditer(s):
            raw = dec(m.group())
            if raw and (identify(raw) or _mostly_printable(raw)):
                return "%s -> %r" % (name, raw[:80])
    return None


def _mostly_printable(raw, ratio=0.9):
    if len(raw) < 8:
        return False
    ok = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    return ok / len(raw) >= ratio


def _b64(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except Exception:
        return None


def _b32(s):
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        return None


def analyze(data, pattern=None, min_str=8, min_score=0.55, raw=False,
            min_text=MIN_TEXT_LEN):
    """Return [(kind, value)] for everything interesting in a decoded stream."""
    found = []
    if pattern is not None:
        for m in pattern.finditer(data):
            found.append(("MATCH", m.group().decode("latin-1", "replace")))
    for name in identify(data):
        found.append(("FILE", name))
    if not min_str:
        return found
    for s in printable_runs(data, min_str):
        if raw:
            found.append(("STRING", s))
            continue
        special = False
        for m in DELIMITED.finditer(s):
            if not token_ok(m.group(1)):
                continue
            found.append(("TOKEN", m.group()))
            special = True
        for m in STRUCTURED.finditer(s):
            if not struct_ok(m.group()):
                continue
            found.append(("STRUCT", m.group()))
            special = True
        enc = encoded_blob(s)
        if enc:
            found.append(("ENCODED", enc))
            special = True
        if not special and len(s) >= max(min_str, min_text):
            thr = text_threshold(len(s), min_score)
            if text_score(s, thr) >= thr:
                found.append(("TEXT", s))
    return found


EXTENSIONS = {"PNG image": ".png", "JPEG image": ".jpg", "GIF image": ".gif",
              "BMP image": ".bmp", "PDF document": ".pdf", "GZIP archive": ".gz",
              "BZIP2 archive": ".bz2", "XZ archive": ".xz", "RAR archive": ".rar",
              "7-Zip archive": ".7z", "TAR archive": ".tar", "OGG media": ".ogg",
              "FLAC audio": ".flac", "MP3 audio": ".mp3", "WAV/AVI/WebP": ".riff",
              "SQLite database": ".sqlite", "ELF executable": ".elf",
              "DOS/PE executable": ".exe", "XML document": ".xml",
              "HTML document": ".html", "Matroska/WebM": ".mkv",
              "ZIP archive (zip/docx/jar/apk)": ".zip"}


def run_name(planes, pixel_order, bit_order, plane_order, default_plane_order):
    """R3G1B4 for a default run, R3G1B4_col-lsb-BGR when the orders differ."""
    name = "".join("%s%d" % p for p in planes)
    tags = []
    if pixel_order != "row":
        tags.append(pixel_order)
    if bit_order != "msb":
        tags.append(bit_order)
    if plane_order != default_plane_order and len({c for c, _ in planes}) > 1:
        tags.append(plane_order)
    return name + ("_" + "-".join(tags) if tags else "")


def save_run(outdir, data, name, ids):
    ext = EXTENSIONS.get(ids[0], ".bin") if ids else ".bin"
    path = os.path.join(outdir, name + ext)
    with open(path, "wb") as f:
        f.write(data)
    return path


def label(planes, pixel_order, bit_order, plane_order):
    return "%s | order=%s bits=%s planeorder=%s" % (
        ",".join("%s%d" % p for p in planes), pixel_order, bit_order, plane_order)


# ---------------------------------------------------------------- brute force
def plan(cache, args):
    """Every (planes, pixel order, bit order, plane order) run the sweep will do."""
    all_planes = [(c, b) for c in cache.channels for b in range(8)]
    if args.only_channels:
        keep = set(args.only_channels.upper())
        all_planes = [p for p in all_planes if p[0] in keep]
    if args.only_bits:
        keep = set(int(x) for x in args.only_bits.split(","))
        all_planes = [p for p in all_planes if p[1] in keep]

    pixel_orders = ["row", "col"] if args.all_orders else [args.order]
    bit_orders = ["msb", "lsb"] if args.all_orders else [args.bit_order]
    plane_orders = (["".join(p) for p in itertools.permutations(cache.channels)]
                    if args.all_orders else [args.plane_order])

    combos = []
    for k in range(args.min_planes, args.max_planes + 1):
        combos.extend(itertools.combinations(all_planes, k))

    tasks = []
    for planes in combos:
        for po in pixel_orders:
            # Different (bit order, channel order) pairs often produce the exact
            # same plane sequence - one plane per channel makes MSB and LSB
            # identical, for instance. Keep one representative of each sequence
            # instead of decoding the same bytes several times.
            seq_seen = {}
            for bo in bit_orders:
                for plo in plane_orders:
                    seq = tuple(order_planes(list(planes), plo, bo))
                    seq_seen.setdefault(seq, (bo, plo))
            for bo, plo in seq_seen.values():
                tasks.append((planes, po, bo, plo))
    return all_planes, combos, tasks


_JOB = {}                                # inherited by forked workers, never pickled


def _init_worker(cache, args, pat):
    _JOB["cache"], _JOB["args"], _JOB["pat"] = cache, args, pat


def _run_one(task):
    planes, po, bo, plo = task
    cache, args, pat = _JOB["cache"], _JOB["args"], _JOB["pat"]
    data = extract(cache, list(planes), po, bo, plo, args.trim, args.limit_bytes)
    found = analyze(data, pat, args.min_str, args.min_score,
                    args.raw_strings, args.min_text)
    path = None
    if args.save and (found or args.save_all):
        name = run_name(order_planes(list(planes), plo, bo), po, bo, plo,
                        cache.channels)
        blob = data if args.save_all and not found else extract(
            cache, list(planes), po, bo, plo, args.trim, 0)
        path = save_run(args.save, blob, name, identify(blob))
    return task, found, path


def brute(cache, args):
    pat = re.compile(args.pattern.encode(), re.IGNORECASE) if args.pattern else None
    all_planes, combos, tasks = plan(cache, args)

    print("[*] image %dx%d (%s)  planes=%d  combinations=%d  runs=%d" % (
        cache.arr.shape[1], cache.arr.shape[0], cache.channels,
        len(all_planes), len(combos), len(tasks)), file=sys.stderr)
    print("[*] scanning first %s bytes per run" % (args.limit_bytes or "ALL"),
          file=sys.stderr)
    if args.limit_bytes:
        # the limit is in output bytes, so the deeper the stack of planes the
        # fewer pixels it reaches - say how much of the image that really is
        widest = max(len(t[0]) for t in tasks)
        covered = args.limit_bytes * 8 / widest / cache.npixels
        if covered < 0.9:
            print("[!] that is the first %.0f%% of the image at %d plane%s; a "
                  "payload past that point is missed - raise --limit-bytes, or "
                  "0 for whole planes" % (covered * 100, widest, "" if widest == 1 else "s"),
                  file=sys.stderr)
    if args.save:
        if args.save_all:
            nbytes = sum(min(args.limit_bytes or cache.npixels * len(t[0]) // 8,
                             cache.npixels * len(t[0]) // 8) for t in tasks)
            print("[*] saving every run to %s/: %d files, ~%.0f MB" % (
                args.save, len(tasks), nbytes / 1e6), file=sys.stderr)
            if nbytes > 2e9 and not args.force:
                sys.exit("[!] that is over 2 GB. Narrow it (--max-planes 1, "
                         "--only-bits 0,1, a smaller --limit-bytes), drop "
                         "--save-all to keep only hits, or pass --force.")
        else:
            print("[*] saving runs that hit to %s/" % args.save, file=sys.stderr)
        os.makedirs(args.save, exist_ok=True)

    jobs = min(args.jobs, len(tasks)) if args.jobs > 0 else 1
    if jobs > 1:
        print("[*] %d worker processes" % jobs, file=sys.stderr)
    print(file=sys.stderr)

    _init_worker(cache, args, pat)
    if jobs > 1:
        pool = multiprocessing.get_context("fork").Pool(jobs)
        results = pool.imap(_run_one, tasks, chunksize=16)
    else:
        pool = None
        results = map(_run_one, tasks)

    seen = set()
    hits = done = 0
    try:
        for task, found, path in results:
            done += 1
            if args.progress and done % 1000 == 0:
                print("    ... %d/%d runs" % (done, len(tasks)), file=sys.stderr)
            planes, po, bo, plo = task
            for kind, val in found:
                if (kind, val) in seen:
                    continue
                seen.add((kind, val))
                hits += 1
                print("[%s] %s" % (kind, label(list(planes), po, bo, plo)))
                print("        %s" % val[:400])
                if path:
                    print("        saved: %s" % path)
    finally:
        if pool is not None:
            pool.terminate()
            pool.join()

    sys.stdout.flush()
    if not hits:
        print("[-] nothing found. try --deep, a lower --min-score/--min-text, "
              "--raw-strings, or your own --pattern", file=sys.stderr)
    else:
        print("\n[*] %d unique hit(s) from %d runs" % (hits, done), file=sys.stderr)
    if args.save:
        print("[*] %d file(s) in %s/" % (len(os.listdir(args.save)), args.save),
              file=sys.stderr)


# ---------------------------------------------------------------- rendering
def default_render_dir(image_path):
    """<image>_planes_<date>, so two runs never quietly overwrite each other."""
    stem = os.path.splitext(os.path.basename(image_path))[0]
    return "%s_planes_%s" % (stem, datetime.now().strftime("%Y%m%d-%H%M"))



def render_planes(cache, outdir, tile=340):
    """Write every single bit plane as a black/white PNG, plus one contact
    sheet of all of them - some payloads are drawn in a plane (QR codes, text,
    logos) and are invisible to any amount of string analysis."""
    from PIL import ImageDraw

    os.makedirs(outdir, exist_ok=True)
    h, w = cache.arr.shape[:2]
    thumb_w = min(tile, w)
    thumb_h = max(1, round(h * thumb_w / w))
    pad, bar = 8, 16

    thumbs = {}
    for ci, c in enumerate(cache.channels):
        for b in range(8):
            bits = (cache.arr[:, :, ci] >> b) & 1
            img = Image.fromarray(bits.astype(bool))     # 1-bit: 8x faster to
            img.save(os.path.join(outdir, "%s%d.png" % (c, b)))   # write, 40% smaller
            thumbs[(c, b)] = img.convert("L").resize((thumb_w, thumb_h),
                                                     Image.NEAREST)

    cols, rows = len(cache.channels), 8
    cell_w, cell_h = thumb_w + pad, thumb_h + bar + pad
    sheet = Image.new("RGB", (cols * cell_w + pad, rows * cell_h + pad), "white")
    draw = ImageDraw.Draw(sheet)
    for ci, c in enumerate(cache.channels):
        for ri, b in enumerate(range(7, -1, -1)):          # bit 7 on top
            x, y = pad + ci * cell_w, pad + ri * cell_h
            draw.text((x, y), "%s%d" % (c, b), fill="black")
            sheet.paste(thumbs[(c, b)], (x, y + bar))
    path = os.path.join(outdir, "contact-sheet.png")
    sheet.save(path)
    print("[*] %d planes + contact sheet in %s/" % (len(thumbs), outdir),
          file=sys.stderr)
    return path


# ---------------------------------------------------------------- main
def parse_bits(spec, channels):
    planes = []
    for tok in re.split(r"[,\s]+", spec.strip()):
        if not tok:
            continue
        m = re.fullmatch(r"([RGBArgba])\s*([0-7])", tok)
        if not m:
            sys.exit("bad --bits token %r (expected e.g. R3, G1, B4)" % tok)
        c, b = m.group(1).upper(), int(m.group(2))
        if c not in channels:
            sys.exit("image has no %s channel (channels: %s)" % (c, channels))
        planes.append((c, b))
    if not planes:
        sys.exit("--bits selected no planes")
    return planes


def main():
    ap = argparse.ArgumentParser(
        description="Bit-plane extractor and brute-forcer for image steganography.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("image")
    ap.add_argument("--bits", help="planes to extract, e.g. R3,G1,B4")
    ap.add_argument("--brute", action="store_true",
                    help="try every plane combination (the default when no "
                         "--bits is given)")
    ap.add_argument("--deep", action="store_true",
                    help="thorough sweep: --all-orders --max-planes 3 "
                         "--min-score 0.45 --min-text 8 (add --limit-bytes 0 "
                         "to decode whole planes - much slower)")
    ap.add_argument("--order", choices=["row", "col"], default="row",
                    help="pixel order (default row)")
    ap.add_argument("--bit-order", choices=["msb", "lsb"], default="msb",
                    help="bit significance order within a channel (default msb)")
    ap.add_argument("--plane-order", default="RGBA",
                    help="channel grouping order, e.g. RGB / BGR (default RGBA)")
    ap.add_argument("--trim", action="store_true", help="trim trailing partial byte")
    ap.add_argument("--out", metavar="FILE",
                    help="write raw extracted bytes to FILE, or to stdout with "
                         "'-' so you can pipe them into binwalk/foremost/strings")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="suppress the ascii/hex report (use when piping --out -)")
    ap.add_argument("--show", type=int, default=2500,
                    help="bytes of hex/ascii to print (0 = all, default 2500)")
    ap.add_argument("--list-strings", type=int, metavar="N", default=0,
                    help="also print every printable string of length >= N")
    ap.add_argument("--render", nargs="?", const="bitplanes", metavar="DIR",
                    help="directory for the plane images a sweep writes "
                         "(default: <image>_planes/); with --bits it renders "
                         "them instead of extracting")
    ap.add_argument("--no-render", action="store_true",
                    help="skip the plane images and only run the sweep")
    ap.add_argument("--scan", action="store_true",
                    help="run the same detectors brute mode uses on this extraction")
    # brute options
    ap.add_argument("--min-planes", type=int, default=1,
                    help="fewest planes to combine per run (default 1)")
    ap.add_argument("--max-planes", type=int, default=3,
                    help="most planes to combine per run; cost grows fast "
                         "(default 3)")
    ap.add_argument("--all-orders", action="store_true",
                    help="also try column order, LSB order, and every channel permutation")
    ap.add_argument("--pattern", default=None,
                    help=r"extra regex to hunt for, e.g. 'SOMECTF\{[^}]+\}' "
                         "(optional; general detection runs regardless)")
    ap.add_argument("--limit-bytes", type=int, default=65536,
                    help="bytes to decode per brute run, 0 = whole image (default 65536)")
    ap.add_argument("--min-str", type=int, default=8, metavar="N",
                    help="minimum printable-run length to consider (0 = skip "
                         "string analysis entirely, default 8)")
    ap.add_argument("--min-score", type=float, default=0.55, metavar="F",
                    help="0..1 threshold for the readable-text score; lower = "
                         "more results and more noise (default 0.55)")
    ap.add_argument("--min-text", type=int, default=MIN_TEXT_LEN, metavar="N",
                    help="shortest run the readable-text scorer will accept; "
                         "below ~12 chars random noise is indistinguishable from "
                         "words, so lower it only if you expect a tiny message "
                         "(default %d)" % MIN_TEXT_LEN)
    ap.add_argument("--raw-strings", action="store_true",
                    help="report every printable run with no scoring at all")
    ap.add_argument("--only-channels", help="restrict brute to these channels, e.g. RGB")
    ap.add_argument("--only-bits", help="restrict brute to these bit indices, e.g. 0,1,7")
    ap.add_argument("--save", metavar="DIR",
                    help="write each hitting run's full bytes to DIR, named by "
                         "its planes (R3G1B4.bin, or R3G1B4.zip when the data "
                         "is a recognised file)")
    ap.add_argument("--save-all", action="store_true",
                    help="with --save, also write runs that produced no hit "
                         "(one file per combination - thousands of them, "
                         "truncated to --limit-bytes)")
    ap.add_argument("--jobs", "-j", type=int, default=min(8, os.cpu_count() or 1),
                    metavar="N", help="worker processes for the sweep "
                                      "(default %(default)d, 1 = no forking)")
    ap.add_argument("--force", action="store_true",
                    help="go ahead with a --save-all that would write over 2 GB")
    ap.add_argument("--progress", action="store_true")
    args = ap.parse_args()

    if args.save_all and not args.save:
        ap.error("--save-all needs a destination: --save DIR --save-all")

    if args.deep:                        # one flag instead of five
        args.all_orders = True
        args.max_planes = max(args.max_planes, 3)
        args.min_score = min(args.min_score, 0.45)
        args.min_text = min(args.min_text, 8)

    arr, channels = load_image(args.image)
    cache = PlaneCache(arr, channels)
    args.plane_order = "".join(c for c in args.plane_order.upper() if c in channels) or channels

    if args.brute or args.deep or not args.bits:
        sheet = None
        big = cache.npixels > 4e6
        if args.render is None and big and not args.no_render:
            # one plane is npixels/8 bytes and noise planes barely compress,
            # so channels*8 of them is up to npixels*channels bytes
            print("[*] %.0f MP image - skipping the plane images (up to %.0f MB "
                  "of them); pass --render DIR to write them anyway"
                  % (cache.npixels / 1e6,
                     cache.npixels * len(cache.channels) / 1e6), file=sys.stderr)
        elif not args.no_render:         # eyes first: some stego is only visible
            outdir = args.render or default_render_dir(args.image)
            sheet = render_planes(cache, outdir)
        brute(cache, args)               # sweeping is the default with no --bits
        if sheet:
            sys.stdout.flush()
            print("\n[*] look at %s for anything drawn into a plane" % sheet,
                  file=sys.stderr)
        return

    if args.render is not None:
        render_planes(cache, args.render)
        return

    planes = parse_bits(args.bits, channels)
    data = extract(cache, planes, args.order, args.bit_order,
                   args.plane_order, args.trim)

    if not args.quiet:
        print("Planes : %s" % label(order_planes(planes, args.plane_order, args.bit_order),
                                    args.order, args.bit_order, args.plane_order))
        print("Size   : %d bytes" % len(data))
        ids = identify(data)
        print("Type   : %s" % (", ".join(ids) if ids else "No file types identified."))
        shown = data if args.show == 0 else data[:args.show]
        print("\nAscii (readable only):\n%s" % ascii_view(shown))
        print("\nHex (accurate):\n%s" % hex_view(shown))
    if args.scan:
        pat = re.compile(args.pattern.encode(), re.IGNORECASE) if args.pattern else None
        found = analyze(data, pat, args.min_str, args.min_score,
                        args.raw_strings, args.min_text)
        print("\nDetections:")
        seen = set()
        for kind, val in found:
            if (kind, val) in seen:
                continue
            seen.add((kind, val))
            print("  [%s] %s" % (kind, val[:400]))
        if not found:
            print("  (none)")
    if args.list_strings:
        print("\nStrings (>=%d):" % args.list_strings)
        for s in printable_runs(data, args.list_strings):
            print("  %s" % s)
    if args.out == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    elif args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        print("[+] wrote %d bytes to %s" % (len(data), args.out),
              file=sys.stderr if args.quiet else sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        sys.exit(130)
