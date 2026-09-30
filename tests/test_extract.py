"""Tests for extracting targets from a challenge briefing."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ctfsolver.detect import extract_targets  # noqa: E402


def test_nc_command():
    t = extract_targets("Connect to nc 34.40.133.67 6768 to access.")
    assert ("netcat", "34.40.133.67", 6768) in t


def test_hostport_and_url():
    t = extract_targets("visit https://ctf.io/x and host.example.org:1337")
    assert ("url", "https://ctf.io/x", 0) in t
    assert ("netcat", "host.example.org", 1337) in t


def test_none_when_plain():
    assert extract_targets("just some words, no targets here") == []


if __name__ == "__main__":
    for n, fn in sorted(globals().items()):
        if n.startswith("test_") and callable(fn):
            fn(); print("ok", n)
    print("all extract tests passed")
