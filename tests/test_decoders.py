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


def test_morse():
    assert d_morse(b"..-. .-.. .- --.") == b"FLAG"


def test_base58_roundtrip():
    # base58('hello') -> Cn8eVZg ; decode should recover b'hello'
    assert d_base58(b"Cn8eVZg") == b"hello"


def test_flag_strict_excludes_generic():
    assert scan_text("noise{maybe}", strict=True) == []
    assert scan_text("flag{yes}", strict=True)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all decoder tests passed")
