"""Round-trip tests: hide a payload in known planes, then check the tool finds it."""
import io
import os
import subprocess
import sys
import zipfile

import numpy as np
import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bitplane as bp

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "bitplane.py")


def embed(path, payload, planes, size=(140, 140), seed=7):
    """Write an image whose given (channel index, bit) planes carry payload."""
    rng = np.random.default_rng(seed)
    h, w = size
    flat = rng.integers(0, 256, (h, w, 3), dtype=np.uint8).reshape(-1, 3)
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    assert -(-len(bits) // len(planes)) <= flat.shape[0], "payload too big for image"

    def put(v, b, x):
        return np.uint8((v & np.uint8(255 - (1 << b))) | np.uint8(x << b))

    for i, bit in enumerate(bits):
        px, slot = divmod(i, len(planes))
        c, b = planes[slot]
        flat[px, c] = put(flat[px, c], b, int(bit))
    for px in range(len(bits) // len(planes) + 1, flat.shape[0]):
        for c, b in planes:
            flat[px, c] = put(flat[px, c], b, 0)
    Image.fromarray(flat.reshape(h, w, 3)).save(path)
    return path


def sweep(path, *extra):
    out = subprocess.run([sys.executable, SCRIPT, str(path), "--no-render", *extra],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    return out.stdout


# ---------------------------------------------------------------- extraction
def test_matches_stegonline_semantics(tmp_path):
    """Channel-grouped, MSB-first, row order - byte for byte what the site gives."""
    img = embed(tmp_path / "a.png", b"flag{banana_m0nkey_jqvz}",
                [(0, 3), (1, 1), (2, 4)])
    arr, channels = bp.load_image(img)
    data = bp.extract(bp.PlaneCache(arr, channels), [("R", 3), ("G", 1), ("B", 4)])
    assert data.startswith(b"flag{banana_m0nkey_jqvz}")


def test_bit_order_and_pixel_order_change_the_result(tmp_path):
    img = embed(tmp_path / "a.png", b"flag{abcdefgh}", [(0, 3), (0, 1)])
    arr, channels = bp.load_image(img)
    cache = bp.PlaneCache(arr, channels)
    two_in_one_channel = [("R", 3), ("R", 1)]
    assert (bp.extract(cache, two_in_one_channel, bit_order="lsb")
            != bp.extract(cache, two_in_one_channel))
    assert (bp.extract(cache, two_in_one_channel, pixel_order="col")
            != bp.extract(cache, two_in_one_channel))


def test_one_plane_per_channel_makes_bit_order_a_no_op(tmp_path):
    """Why the sweep can collapse those runs instead of decoding them twice."""
    img = embed(tmp_path / "a.png", b"flag{abcdefgh}", [(0, 3), (1, 1), (2, 4)])
    arr, channels = bp.load_image(img)
    cache = bp.PlaneCache(arr, channels)
    planes = [("R", 3), ("G", 1), ("B", 4)]
    assert bp.extract(cache, planes, bit_order="lsb") == bp.extract(cache, planes)


# ---------------------------------------------------------------- the sweep
@pytest.mark.parametrize("payload,planes,expect", [
    (b"flag{banana_m0nkey_jqvz}", [(0, 3), (1, 1), (2, 4)], "flag{banana_m0nkey_jqvz}"),
    (b"CTF{any_tag_at_all}", [(1, 0)], "CTF{any_tag_at_all}"),
    (b"The rendezvous is at the north pier just after midnight.", [(0, 0)],
     "rendezvous"),
    (b"https://internal.example.org/dropbox/q4.tar.gz", [(2, 7)], "https://"),
    (b"dGhpcyBwYXlsb2FkIHdhcyBiYXNlNjQgZW5jb2RlZCBiZWZvcmUgaGlkaW5n",
     [(0, 5), (2, 1)], "base64 ->"),
    (b"48656c6c6f2c20686964696e672064617461206173206865782064696769747321",
     [(1, 6)], "hex ->"),
])
def test_sweep_finds_payload(tmp_path, payload, planes, expect):
    img = embed(tmp_path / "a.png", payload, planes)
    assert expect in sweep(img)


def test_sweep_finds_embedded_file(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secret.txt", "contents")
    img = embed(tmp_path / "a.png", buf.getvalue(), [(1, 2), (1, 3)])
    assert "ZIP archive" in sweep(img, "--all-orders", "--max-planes", "2")


def test_clean_image_reports_nothing(tmp_path):
    rng = np.random.default_rng(3)
    Image.fromarray(rng.integers(0, 256, (140, 140, 3), dtype=np.uint8)).save(
        tmp_path / "noise.png")
    assert sweep(tmp_path / "noise.png").strip() == ""


# ---------------------------------------------------------------- detectors
@pytest.mark.parametrize("text", [
    "The quick brown fox jumps over the lazy dog",
    "Das ist eine geheime Nachricht fuer dich",
    "THIS MESSAGE IS ENTIRELY UPPERCASE TEXT",
    "password is hunter2 do not share",
])
def test_scores_real_text(text):
    assert bp.analyze(text.encode()), text


@pytest.mark.parametrize("noise", [
    "UeRUaVUP", "aUP%IXUMXUIUTUXURUrUV", "UUUUUUUUUUUUUUUU", "GtOjWiYpUaVe",
    "DT@EDPDUETEQT", "5uTUTUu]UUVU]p", "PAOQ@P7e'bu1>4i`g+nd1;qfU",
])
def test_rejects_bit_noise(noise):
    assert not bp.analyze(noise.encode()), noise


def test_two_byte_magics_need_a_second_field():
    assert bp.identify(b"BM" + bytes(range(60))) == []
    assert bp.identify(b"MZ" + bytes(200)) == []
    real = io.BytesIO()
    Image.new("RGB", (4, 4)).save(real, "BMP")
    assert "BMP image" in bp.identify(real.getvalue())


# ---------------------------------------------------------------- plumbing
def test_run_names_encode_planes_and_orders():
    planes = [("R", 3), ("G", 1), ("B", 4)]
    assert bp.run_name(planes, "row", "msb", "RGB", "RGB") == "R3G1B4"
    assert bp.run_name(planes, "col", "lsb", "BGR", "RGB") == "R3G1B4_col-lsb-BGR"


def test_save_writes_named_file(tmp_path):
    img = embed(tmp_path / "a.png", b"flag{saved_to_disk}", [(0, 3), (1, 1), (2, 4)])
    out = tmp_path / "out"
    sweep(img, "--save", str(out))
    assert (out / "R3G1B4.bin").read_bytes().startswith(b"flag{saved_to_disk}")


def test_save_all_needs_a_destination(tmp_path):
    img = embed(tmp_path / "a.png", b"x" * 8, [(0, 0)])
    out = subprocess.run([sys.executable, SCRIPT, str(img), "--save-all"],
                         capture_output=True, text=True)
    assert out.returncode != 0 and "--save DIR" in out.stderr


def test_render_writes_every_plane(tmp_path):
    img = embed(tmp_path / "a.png", b"x" * 8, [(0, 0)])
    shots = tmp_path / "shots"
    subprocess.run([sys.executable, SCRIPT, str(img), "--render", str(shots)],
                   capture_output=True, text=True, check=True)
    pngs = sorted(p.name for p in shots.glob("*.png"))
    assert "contact-sheet.png" in pngs and len(pngs) == 25   # 3 channels x 8 + sheet


def test_sweep_deduplicates_identical_plane_sequences(tmp_path):
    """Every planned run must decode a distinct byte sequence."""
    img = embed(tmp_path / "a.png", b"x" * 8, [(0, 0)])
    arr, channels = bp.load_image(img)
    cache = bp.PlaneCache(arr, channels)
    args = type("A", (), dict(only_channels=None, only_bits=None, order="row",
                              bit_order="msb", plane_order=channels, all_orders=True,
                              min_planes=1, max_planes=2))()
    _, _, tasks = bp.plan(cache, args)
    seqs = {(tuple(bp.order_planes(list(p), plo, bo)), po) for p, po, bo, plo in tasks}
    assert len(seqs) == len(tasks)
