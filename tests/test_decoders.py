"""Tests for the magic decoder and flag scanner. Run: python -m pytest, or
python3 tests/test_decoders.py"""
import base64
import binascii
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.decoders import magic, d_morse, d_base58  # noqa: E402
from ctfsolver.flags import scan_text  # noqa: E402


def test_nested_base64_hex():
    inner = b"flag{magic_bfs_decoder}"
    enc = base64.b64encode(base64.b64encode(binascii.hexlify(inner)))
    r = magic(enc)
    assert r["found"]
    assert any(f["flag"] == "flag{magic_bfs_decoder}" for f in r["flags"])


def test_xor_single_byte():
    data = bytes(c ^ 0x42 for c in b"flag{xor_brute_works}")
    r = magic(data)
    assert r["found"]
    assert r["flags"][0]["flag"] == "flag{xor_brute_works}"


def test_embedded_token_in_prose():
    # A briefing is prose *around* the ciphertext — the decoder must still peel
    # the embedded blob (regression: previously only the whole text was tried).
    blob = base64.b64encode(b"picoCTF{prose_embedded}").decode()
    briefing = f"Agent, the intercept reads: {blob} — decode it before 0600."
    r = magic(briefing.encode())
    assert r["found"]
    assert any(f["flag"] == "picoCTF{prose_embedded}" for f in r["flags"])


def test_whole_blob_still_decodes():
    # Seeding tokens must not regress the plain whole-input path.
    enc = base64.b64encode(b"flag{plain_blob}")
    r = magic(enc)
    assert r["found"]
    assert any(f["flag"] == "flag{plain_blob}" for f in r["flags"])


def test_morse():
    assert d_morse(b"..-. .-.. .- --.") == b"FLAG"


def test_base58_roundtrip():
    # base58('hello') -> Cn8eVZg ; decode should recover b'hello'
    assert d_base58(b"Cn8eVZg") == b"hello"


def test_flag_strict_excludes_generic():
    assert scan_text("noise{maybe}", strict=True) == []
    assert scan_text("flag{yes}", strict=True)


def _caesar(s, k):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def test_caesar_arbitrary_shift():
    # shift 3 (NOT rot13) — previously never decoded.
    for k in (3, 7, 19, 25):
        ct = _caesar("picoCTF{caesar_%d}" % k, k)
        r = magic(ct.encode())
        assert r["found"], f"shift {k} not found"
        assert any(f["flag"] == "picoCTF{caesar_%d}" % k for f in r["flags"])


def test_layered_base64_then_caesar():
    ct = _caesar("flag{layered_caesar}", 3)
    r = magic(base64.b64encode(ct.encode()))
    assert r["found"]
    assert any(f["flag"] == "flag{layered_caesar}" for f in r["flags"])


def test_multibyte_repeating_xor():
    # multi-byte key recovered from the known flag prefix (crib).
    for pt, key in [(b"flag{multibyte_xor_key}", b"KEY"),
                    (b"picoCTF{repeating_xor_ftw}", b"SECRET")]:
        ct = bytes(pt[i] ^ key[i % len(key)] for i in range(len(pt)))
        r = magic(ct)
        assert r["found"], f"key {key!r} not recovered"
        assert any(f["flag"] == pt.decode() for f in r["flags"])


def test_base64url_token():
    raw = b'{"flag":"flag{base64url_ok}"}'
    enc = base64.urlsafe_b64encode(raw).replace(b"=", b"")
    r = magic(enc)
    assert r["found"]
    assert any(f["flag"] == "flag{base64url_ok}" for f in r["flags"])


def test_no_false_flag_on_random_bytes():
    # The crib-based XOR must NOT invent a flag from arbitrary data: forcing the
    # first bytes to a crib used to fabricate flag{<junk>}.
    import random
    random.seed(1)
    for _ in range(5):
        blob = bytes(random.randrange(256) for _ in range(200))
        assert not magic(blob)["found"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all decoder tests passed")
