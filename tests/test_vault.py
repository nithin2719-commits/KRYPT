"""Tests for the Vault writeup generation + export rendering."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.vault import make_writeup  # noqa: E402
from ctfsolver import export  # noqa: E402

_RES = {
    "target": {"kind": "file", "subkind": "binary", "raw": "/tmp/chal",
               "mime": "application/x-executable"},
    "briefing": "Find the win function.",
    "steps": [
        {"step": "file", "summary": "ELF 64-bit", "output": "ELF", "flags": []},
        {"step": "strings", "summary": "flag in strings", "output": "flag{x}",
         "flags": [{"flag": "flag{x}", "confidence": 80, "kind": "named"}]},
    ],
}


def test_writeup_has_sections():
    md = make_writeup(_RES, "flag{x}", "picoCTF 2026")
    for section in ("# chal", "## Challenge", "## TL;DR", "## Flag",
                    "## Tools & method", "picoCTF 2026", "flag{x}"):
        assert section in md, section


def test_writeup_marks_winning_step():
    md = make_writeup(_RES, "flag{x}", "E")
    assert "`strings`" in md


def test_md_to_html_renders_code_and_headings():
    html = export.md_to_html("# Title\n\n```\ncode\n```\n- item", "t")
    assert "<h1>Title</h1>" in html
    assert "<pre><code>" in html and "code" in html
    assert "<li>item</li>" in html


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all vault tests passed")
