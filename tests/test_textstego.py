"""Tests for hidden-in-text extraction."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ctfsolver.solvers.textstego import zero_width, acrostics  # noqa: E402


def test_zero_width_roundtrip():
    msg = "HI"
    bits = "".join(format(ord(c), "08b") for c in msg)
    zw = "".join("​" if b == "0" else "‌" for b in bits)
    assert "HI" in zero_width("cover" + zw)


def test_acrostic_first_line():
    text = "Please\nInteresting\nCome\nOpen\n"
    got = dict(acrostics(text))
    assert got.get("first-letter-of-each-line") == "PICO"


if __name__ == "__main__":
    for n, fn in sorted(globals().items()):
        if n.startswith("test_") and callable(fn):
            fn(); print("ok", n)
    print("all textstego tests passed")
