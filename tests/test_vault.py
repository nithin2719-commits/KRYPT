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


def test_writeup_cooked_format():
    md = make_writeup(_RES, "flag{x}", "picoCTF 2026", engine="claude-api")
    # flag is stated up top, before the first section heading
    assert md.index("**Flag** · `flag{x}`") < md.index("## Overview")
    # new sections + metadata the cooked format adds
    for token in ("## Overview", "## Solve path", "## Reproduce",
                  "**Flag format:** `flag{...}`", "engine `claude-api`", "🚩"):
        assert token in md, token


def test_writeup_encoding_note():
    res = {"target": {"kind": "file", "subkind": "text", "raw": "/tmp/c.txt"},
           "steps": [{"step": "flag-sweep(encoded)", "summary": "1 after decode",
                      "flags": [{"flag": "flag{e}", "confidence": 90,
                                 "kind": "base64", "encoded": True}]}]}
    md = make_writeup(res, "flag{e}", "E")
    assert "base64" in md and "decoded it automatically" in md


def test_md_to_html_renders_code_and_headings():
    html = export.md_to_html("# Title\n\n```\ncode\n```\n- item", "t")
    assert "<h1>Title</h1>" in html
    assert "<pre><code>" in html and "code" in html
    assert "<li>item</li>" in html


def test_md_to_html_is_krypt_branded():
    html = export.md_to_html("# Chal\n\nbody", "picoCTF 2026")
    # KRYPT masthead + brand fonts + full-bleed dark theme + footer
    assert "class='brand'" in html and "KRYPT" in html
    assert "Orbitron" in html and "JetBrains Mono" in html
    assert "class='page'" in html          # full-bleed wrapper
    assert "PICOCTF 2026" in html          # title stamp
    assert "github.com/nithin2719-commits/KRYPT" in html


def test_md_to_html_flag_hero_and_ordered_list():
    md = "# C\n\n**Flag** · `flag{hero}`\n\n1. first step\n2. second step"
    html = export.md_to_html(md, "t")
    assert "flaghero" in html and "flag{hero}" in html
    assert "Flag Captured" in html
    # the literal "**Flag** ·" line must become the hero, not a plain paragraph
    assert "<p>**Flag**" not in html
    assert "<ol>" in html and "<li>first step</li>" in html


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all vault tests passed")
