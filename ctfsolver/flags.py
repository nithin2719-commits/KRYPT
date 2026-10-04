"""Flag detection: sweep text/bytes for CTF flags — precisely.

Priority:
  1. custom  (CTF_FLAG_FORMAT env, the event's exact format)   -> conf 100
  2. named   (flag{}, FLAG{}, CTF{}, <word>CTF{}, HTB{}, key{}) -> conf 90
  3. semi    (a wrapper that literally contains 'flag' or 'ctf') -> conf 55
  4. guess   (an UPPERCASE event acronym, e.g. CSSA{...})        -> conf 50

The "guess" tier is deliberately narrow: only an all-caps acronym wrapper with
a flag-ish body counts. A generic "any word{...}" pattern is rejected because it
matched ordinary code/markup — `struct Point{x_0}`, `dict{key_1}`, CSS
`div{margin_0}`, LaTeX `\\frac{a_1}` — and produced false flags. Content is also
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
# fallback 2: a WRAPPER{content} candidate; _fallback_flag() then decides if it
# is a real custom flag (uppercase acronym + flag-ish body) vs. code/markup.
_FALLBACK = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,19})\{([^}\s]{2,100})\}")
_CODE_WORDS = {
    "struct", "class", "enum", "union", "namespace", "if", "for", "while",
    "switch", "function", "void", "int", "char", "main", "return", "else",
    "def", "typedef", "public", "private", "static", "const", "new", "do",
    "try", "catch", "interface", "impl", "fn", "match", "case",
}
_PLACEHOLDER = re.compile(r"^[.\s…xX*?_\-]+$")


def _fallback_flag(wrapper: str, content: str) -> bool:
    """Does WRAPPER{content} look like a real custom-format flag (no declared
    format) rather than code/markup?

    Only an UPPERCASE event acronym (CSSA, DUCTF, UIUCTF...) with a plausible,
    flag-ish body qualifies. Lowercase/mixed-case wrappers are deliberately NOT
    guessed: they collide with ordinary code and markup — `struct Point{x_0}`,
    `dict{key_1}`, `set{a_1}`, CSS `div{margin_0}`, LaTeX `\\frac{a_1}` — which
    the old "any underscore/digit → flag" rule turned into false positives.
    Lowercase custom formats (e.g. `sun{...}`) are still caught the right way:
    via CTF_FLAG_FORMAT or a briefing-derived format (conf 100).
    """
    if wrapper.lower() in _CODE_WORDS:
        return False
    letters = sum(c.isalpha() for c in wrapper)
    # wrapper must be an all-caps acronym with ≥2 letters and NO underscore.
    # Real event prefixes are single tokens (CSSA, HTB, DUCTF, UIUCTF); an
    # underscore means a C macro/constant (MAX_BUF, BUF_SIZE), not a flag.
    if not (wrapper.isupper() and letters >= 2 and "_" not in wrapper):
        return False
    # body must be clean flag-ish text, not binary noise. Scanning raw bytes of
    # an image/ELF throws up junk like LK{;ïâ9Wuñ®k} — a 2-letter wrapper with a
    # body full of high/non-ASCII bytes. Require printable ASCII dominated by the
    # usual flag charset, and (as before) at least one lowercase ASCII letter so
    # UPPER_SNAKE constants ({BUF_SIZE}, {FIXME}) are still rejected.
    if len(content) < 3 or not content.isascii():
        return False
    good = sum((c.isalnum() or c in "_-") for c in content)
    if good / len(content) < 0.9:
        return False
    return any("a" <= c <= "z" for c in content)


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


def _fmt_to_regex(fmt: str) -> str:
    """Turn an operator-typed flag format into an anchored regex.

    Accepts either a ready regex (contains a real char class / quantifier) or a
    friendly template like `picoCTF{...}`, `flag{}` or `CTF{FILL}` — the inside
    is treated as a placeholder and replaced with 'one or more non-}' so any
    body matches. Mirrors how the sweep's _format_to_regex works in server.py.
    """
    fmt = (fmt or "").strip()
    if not fmt:
        return ""
    # already a regex? (has a class/quantifier/escape beyond a plain wrapper)
    if re.search(r"\[|\]|\\[dws]|\.\*|\.\+|\{\d|\(\?", fmt):
        return fmt
    m = re.match(r"^([^{]+)\{(.*)\}$", fmt)
    if m:
        return re.escape(m.group(1)) + r"\{[^}\n]{1,200}\}"
    return re.escape(fmt)


def validate_flag(flag: str, fmt: str = "") -> dict:
    """Judge a manually-entered flag before you save or submit it.

    -> {"valid": bool, "reason": str, "kind": str, "confidence": int}

    With a format given, the flag must match it exactly (full-string). With no
    format, it must look like a real flag — a known wrapper (flag{}, picoCTF{},
    HTB{}…) or a clean custom acronym wrapper — not prose or a placeholder.
    """
    flag = (flag or "").strip()
    if not flag:
        return {"valid": False, "reason": "empty", "kind": "", "confidence": 0}
    if "\n" in flag or "\r" in flag:
        return {"valid": False, "reason": "flag contains a newline", "kind": "", "confidence": 0}
    if len(flag) > 512:
        return {"valid": False, "reason": "too long to be a flag", "kind": "", "confidence": 0}

    if fmt and fmt.strip():
        rx = _fmt_to_regex(fmt)
        try:
            if re.fullmatch(rx, flag):
                return {"valid": True, "reason": f"matches format {fmt.strip()}",
                        "kind": "custom", "confidence": 100}
            return {"valid": False, "reason": f"does not match format {fmt.strip()}",
                    "kind": "", "confidence": 0}
        except re.error:
            return {"valid": False, "reason": f"bad format regex: {fmt.strip()}",
                    "kind": "", "confidence": 0}

    # no declared format — is it a recognised flag on its own?
    hits = scan_text(flag)
    exact = next((h for h in hits if h["flag"] == flag), None)
    if exact:
        return {"valid": True, "reason": f"looks like a {exact['kind']} flag",
                "kind": exact["kind"], "confidence": exact["confidence"]}
    if "{" in flag and flag.endswith("}") and _valid(flag):
        return {"valid": True, "reason": "wrapper{body} shape — no event format set to confirm it",
                "kind": "shape", "confidence": 40}
    return {"valid": False,
            "reason": "doesn't look like a flag — set a FLAG FMT to confirm a custom format",
            "kind": "", "confidence": 0}


def scan_bytes(data: bytes) -> list[dict]:
    return scan_text(data.decode("latin-1", "replace"))


def scan_file(path: str, max_bytes: int = 64 * 1024 * 1024) -> list[dict]:
    try:
        with open(path, "rb") as fh:
            return scan_bytes(fh.read(max_bytes))
    except OSError:
        return []
