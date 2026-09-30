"""Tests for the Brainfuck solver."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ctfsolver.solvers.brainfuck import run  # noqa: E402


def _gen(msg):
    code, cur = [], 0
    for ch in msg:
        t = ord(ch); d = t - cur
        code.append(("+" * d) if d >= 0 else ("-" * -d)); code.append("."); cur = t
    return "".join(code)


def test_hello_a():
    assert run("++++++++[>++++++++<-]>+.") == b"A"


def test_generated_message():
    assert run(_gen("h4ck3r")) == b"h4ck3r"


def test_unbalanced_returns_none():
    assert run("+++[>+++") is None


if __name__ == "__main__":
    for n, fn in sorted(globals().items()):
        if n.startswith("test_") and callable(fn):
            fn(); print("ok", n)
    print("all brainfuck tests passed")
