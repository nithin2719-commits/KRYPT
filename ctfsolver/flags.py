"""Flag detection: sweep arbitrary text/bytes for CTF flag patterns."""
from __future__ import annotations

import os
import re

# Common CTF flag wrappers. Override the generic one with CTF_FLAG_FORMAT
# (a Python regex) when you know the event's exact format, e.g.:
#   export CTF_FLAG_FORMAT='picoCTF\{[^}]+\}'
_NAMED = [
    r"flag\{[^}]{1,200}\}",
    r"FLAG\{[^}]{1,200}\}",
    r"CTF\{[^}]{1,200}\}",
    r"[A-Za-z0-9_]{2,20}CTF\{[^}]{1,200}\}",   # picoCTF{}, HTB{}, redpwnCTF{}...
    r"HTB\{[^}]{1,200}\}",
    r"key\{[^}]{1,200}\}",
]
# Last-resort generic: any short token followed by {...}. Noisier, ranked lower.
_GENERIC = r"[A-Za-z0-9_]{2,32}\{[^}{]{2,200}\}"


def _patterns() -> list[tuple[str, re.Pattern]]:
    pats: list[tuple[str, re.Pattern]] = []
    custom = os.environ.get("CTF_FLAG_FORMAT")
    if custom:
        try:
            pats.append(("custom", re.compile(custom)))
        except re.error:
            pass
    for p in _NAMED:
        pats.append(("named", re.compile(p)))
    pats.append(("generic", re.compile(_GENERIC)))
    return pats


def scan_text(text: str, strict: bool = False) -> list[dict]:
    """Return de-duplicated flag candidates ranked by confidence.

    strict=True keeps only named/custom formats (confidence >= 80) — use it for
    noisy sources like XOR brute-force where the loose generic {..} pattern
    produces false positives on random bytes.
    """
    seen: dict[str, dict] = {}
    for kind, rx in _patterns():
        if strict and kind == "generic":
            continue
        for m in rx.finditer(text):
            val = m.group(0)
            if val not in seen:
                conf = {"custom": 100, "named": 80, "generic": 30}[kind]
                seen[val] = {"flag": val, "kind": kind, "confidence": conf}
    return sorted(seen.values(), key=lambda d: -d["confidence"])


def scan_bytes(data: bytes) -> list[dict]:
    return scan_text(data.decode("latin-1", "replace"))


def scan_file(path: str, max_bytes: int = 64 * 1024 * 1024) -> list[dict]:
    try:
        with open(path, "rb") as fh:
            return scan_bytes(fh.read(max_bytes))
    except OSError:
        return []
