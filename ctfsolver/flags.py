"""Flag detection: sweep text/bytes for CTF flags — precisely.

Priority:
  1. custom  (CTF_FLAG_FORMAT env, the event's exact format)  -> conf 100
  2. named   (flag{}, FLAG{}, CTF{}, <word>CTF{}, HTB{}, key{}) -> conf 90
  3. semi    (a wrapper that literally contains 'flag' or 'ctf') -> conf 55

There is deliberately NO "any word{...}" pattern — that matched code like
`win(){...}` and random `token{...}` and produced false flags. Content is also
validated (no newlines, not a placeholder like X{...}).
"""
from __future__ import annotations

import os
import re

# high-confidence, well-known CTF flag wrappers (content excludes newlines)
_NAMED = [
    r"flag\{[^}\n]{1,200}\}",
    r"FLAG\{[^}\n]{1,200}\}",
    r"CTF\{[^}\n]{1,200}\}",
    r"[A-Za-z0-9_]{1,20}CTF\{[^}\n]{1,200}\}",   # picoCTF{}, redpwnCTF{}, ...
    r"HTB\{[^}\n]{1,200}\}",
    r"[Kk][Ee][Yy]\{[^}\n]{1,200}\}",
]
# fallback 1: the wrapper token contains 'flag' or 'ctf'
_SEMI = re.compile(r"(?i)[a-z0-9_]{0,18}(?:flag|ctf)[a-z0-9_]{0,18}\{[^}{\n]{1,200}\}")
# fallback 2: a WRAPPER{content} that looks like a real flag, not code — the
# wrapper is letters/digits directly before '{', and content has no spaces.
_FALLBACK = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,19})\{([^}\s]{2,100})\}")
_CODE_WORDS = {
    "struct", "class", "enum", "union", "namespace", "if", "for", "while",
    "switch", "function", "void", "int", "char", "main", "return", "else",
    "def", "typedef", "public", "private", "static", "const", "new", "do",
    "try", "catch", "interface", "impl", "fn", "match", "case",
}
_PLACEHOLDER = re.compile(r"^[.\s…xX*?_\-]+$")


def _fallback_flag(wrapper: str, content: str) -> bool:
    """Does WRAPPER{content} look like a real (custom-format) flag?"""
    if wrapper.lower() in _CODE_WORDS:
        return False
    if "_" in content or any(c.isdigit() for c in content):
        return True
    # uppercase event prefix (CSSA, HTB, DUCTF...) with a wordy body
    return wrapper.isupper() and len(wrapper) >= 2 and len(content) >= 4


def _inner(val: str) -> str | None:
    try:
        return val[val.index("{") + 1:val.rindex("}")]
    except ValueError:
        return None


def _valid(val: str) -> bool:
    inner = _inner(val)
    if inner is None:
        return False
    s = inner.strip()
    return bool(s) and not _PLACEHOLDER.match(s)


def scan_text(text: str, strict: bool = False) -> list[dict]:
    """De-duplicated flag candidates ranked by confidence.

    strict=True keeps only custom + named formats (drops the 'semi' fallback) —
    used for noisy sources like XOR brute-force.
    """
    seen: dict[str, dict] = {}

    def add(val: str, kind: str, conf: int):
        if val in seen or not _valid(val):
            return
        seen[val] = {"flag": val, "kind": kind, "confidence": conf}

    custom = os.environ.get("CTF_FLAG_FORMAT")
    if custom:
        try:
            for m in re.finditer(custom, text):
                add(m.group(0), "custom", 100)
        except re.error:
            pass
    for p in _NAMED:
        for m in re.finditer(p, text):
            add(m.group(0), "named", 90)
    if not strict:
        for m in _SEMI.finditer(text):
            add(m.group(0), "semi", 55)
        for m in _FALLBACK.finditer(text):
            if _fallback_flag(m.group(1), m.group(2)):
                add(m.group(0), "guess", 50)

    # drop shorter matches that are substrings of a longer one
    # (e.g. CTF{x} inside picoCTF{x}, flag{x} inside myflag{x})
    vals = list(seen.values())
    allf = [v["flag"] for v in vals]
    vals = [v for v in vals
            if not any(o != v["flag"] and v["flag"] in o for o in allf)]
    return sorted(vals, key=lambda d: -d["confidence"])


def scan_bytes(data: bytes) -> list[dict]:
    return scan_text(data.decode("latin-1", "replace"))


def scan_file(path: str, max_bytes: int = 64 * 1024 * 1024) -> list[dict]:
    try:
        with open(path, "rb") as fh:
            return scan_bytes(fh.read(max_bytes))
    except OSError:
        return []
