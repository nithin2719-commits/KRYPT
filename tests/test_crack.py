"""Tests for crack.py's `john --show` password parsing. Run: python -m pytest,
or python3 tests/test_crack.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.crack import _extract_password  # noqa: E402


def test_simple():
    assert _extract_password("archive.zip:hunter2") == "hunter2"


def test_trailing_metadata():
    # john appends empty fields + a repeated filename
    assert _extract_password("archive.zip:s3cret:::::archive.zip") == "s3cret"


def test_password_with_colon():
    # regression: the old split(':')[1] truncated this to "pa"
    assert _extract_password("archive.zip:pa:ss:word:::::archive.zip") == "pa:ss:word"


def test_skips_summary_line():
    out = "archive.zip:letmein\n1 password hash cracked, 0 left"
    assert _extract_password(out) == "letmein"


def test_no_crack():
    assert _extract_password("0 password hashes cracked, 1 left") == ""
    assert _extract_password("No password hashes left to crack (see FAQ)") == ""
    assert _extract_password("") == ""


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all crack tests passed")
