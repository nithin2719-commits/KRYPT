#!/usr/bin/env python3
"""Hidden-message extraction from text — the tricks CTF "read the text" puzzles
use when there's no visible flag:

  - zero-width Unicode steganography (U+200B/C/D, U+FEFF)
  - trailing-whitespace steganography (space/tab bits, snow-style)
  - acrostics: first letter of each line, first letter of each word
  - capital-letters-only, and the reverse of each

Prints every candidate hidden string. Deterministic; no LLM tokens.
    python3 textstego.py <file>
"""
import sys

ZW = {"​", "‌", "‍", "﻿", "⁠"}


def _bits_to_text(bits: str) -> str:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode("latin-1", "replace")


def zero_width(text: str):
    seq = [c for c in text if c in ZW]
    if len(seq) < 8:
        return []
    kinds = list(dict.fromkeys(seq))          # distinct, in order
    res = []
    if len(kinds) == 2:
        a, b = kinds
        for zero, one in ((a, b), (b, a)):
            bits = "".join("0" if c == zero else "1" for c in seq)
            t = _bits_to_text(bits)
            if t.strip():
                res.append(t)
    return res


def whitespace(text: str):
    bits = []
    for line in text.split("\n"):
        stripped = line.rstrip(" \t")
        trail = line[len(stripped):]
        for ch in trail:
            bits.append("0" if ch == " " else "1")
    if len(bits) < 8:
        return []
    return [_bits_to_text("".join(bits))]


def acrostics(text: str):
    lines = [ln for ln in text.split("\n") if ln.strip()]
    out = []
    first_line = "".join(ln.strip()[0] for ln in lines if ln.strip())
    if len(first_line) >= 4:
        out.append(("first-letter-of-each-line", first_line))
        out.append(("^ reversed", first_line[::-1]))
    words = text.split()
    first_word = "".join(w[0] for w in words if w)
    if 4 <= len(first_word) <= 400:
        out.append(("first-letter-of-each-word", first_word))
    caps = "".join(c for c in text if c.isupper())
    if 4 <= len(caps) <= 400:
        out.append(("capital-letters-only", caps))
    return out


def main():
    if len(sys.argv) < 2:
        print("USAGE: textstego.py <file>")
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(2_000_000)
    except OSError as e:
        print(f"READ_FAILED {e}")
        return 2

    found = False
    for t in zero_width(text):
        print("ZERO-WIDTH:", t[:300]); found = True
    for t in whitespace(text):
        if t.strip():
            print("WHITESPACE:", t[:300]); found = True
    for label, t in acrostics(text):
        print(f"{label}:", t[:300]); found = True
    if not found:
        print("NO_HIDDEN_TEXT")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
