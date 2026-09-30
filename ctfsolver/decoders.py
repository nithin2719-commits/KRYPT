"""A CyberChef-style "magic" recursive decoder.

BFS over a set of reversible transforms, peeling encoding layers until a flag
appears or the search budget is spent. Single-byte XOR is handled as a terminal
flag-check at each node (brute all 256 keys) rather than a BFS branch, to keep
the tree from exploding.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import zlib
from collections import deque

from .flags import scan_text

_WS = re.compile(rb"\s+")


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)
    return good / len(b)


def _looks_text(b: bytes) -> bool:
    return _printable_ratio(b) > 0.90


# --- individual transforms: bytes -> bytes | None -------------------------

def d_base64(b):
    s = _WS.sub(b"", b)
    if not s or len(s) % 4 == 1 or not re.fullmatch(rb"[A-Za-z0-9+/=]+", s):
        return None
    try:
        out = base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
        return out or None
    except (binascii.Error, ValueError):
        return None


def d_base32(b):
    s = _WS.sub(b"", b).upper()
    if not s or not re.fullmatch(rb"[A-Z2-7=]+", s):
        return None
    try:
        return base64.b32decode(s + b"=" * (-len(s) % 8)) or None
    except (binascii.Error, ValueError):
        return None


def d_base85(b):
    s = _WS.sub(b"", b)
    try:
        return base64.b85decode(s) or None
    except (ValueError, Exception):
        return None


def d_ascii85(b):
    s = _WS.sub(b"", b)
    try:
        return base64.a85decode(s) or None
    except (ValueError, Exception):
        return None


def d_hex(b):
    s = _WS.sub(b"", b)
    if not s or len(s) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", s):
        return None
    try:
        return binascii.unhexlify(s) or None
    except (binascii.Error, ValueError):
        return None


def d_decimal(b):
    parts = b.split()
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    try:
        vals = [int(p) for p in parts]
        if all(0 <= v <= 255 for v in vals):
            return bytes(vals)
    except ValueError:
        pass
    return None


def d_binary(b):
    s = _WS.sub(b"", b)
    if not s or len(s) % 8 or not re.fullmatch(rb"[01]+", s):
        return None
    try:
        return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8)) or None
    except ValueError:
        return None


def d_url(b):
    if b"%" not in b:
        return None
    try:
        from urllib.parse import unquote_to_bytes
        out = unquote_to_bytes(b)
        return out if out != b else None
    except Exception:
        return None


def d_rot13(b):
    try:
        return codecs.encode(b.decode("ascii"), "rot_13").encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None


def d_rot47(b):
    try:
        out = bytes((33 + (c - 33 + 47) % 94) if 33 <= c <= 126 else c for c in b)
        return out if out != b else None
    except Exception:
        return None


def d_atbash(b):
    def f(c):
        if 65 <= c <= 90:
            return 90 - (c - 65)
        if 97 <= c <= 122:
            return 122 - (c - 97)
        return c
    out = bytes(f(c) for c in b)
    return out if out != b else None


def d_reverse(b):
    return b[::-1] if len(b) > 1 else None


def d_gzip(b):
    try:
        return gzip.decompress(b) or None
    except Exception:
        return None


def d_zlib(b):
    try:
        return zlib.decompress(b) or None
    except Exception:
        return None


_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def d_base58(b):
    s = _WS.sub(b"", b)
    if not s or len(s) < 4 or any(c not in _B58 for c in s):
        return None
    try:
        num = 0
        for c in s:
            num = num * 58 + _B58.index(c)
        raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        pad = len(s) - len(s.lstrip(b"1"))
        return b"\x00" * pad + raw or None
    except Exception:
        return None


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def d_morse(b):
    try:
        s = b.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if not s or not re.fullmatch(r"[.\-/ ]+", s) or (" " not in s and "/" not in s):
        return None
    words = re.split(r"\s*/\s*| {3,}", s)
    out = []
    for w in words:
        out.append("".join(_MORSE.get(sym, "") for sym in w.split()))
    res = " ".join(x for x in out if x)
    return res.encode() if res.strip() else None


TRANSFORMS = [
    ("base64", d_base64), ("base32", d_base32), ("base85", d_base85),
    ("ascii85", d_ascii85), ("base58", d_base58), ("hex", d_hex),
    ("decimal", d_decimal), ("binary", d_binary), ("morse", d_morse),
    ("url", d_url), ("rot13", d_rot13),
    ("rot47", d_rot47), ("atbash", d_atbash), ("reverse", d_reverse),
    ("gzip", d_gzip), ("zlib", d_zlib),
]


def xor_bruteforce(b: bytes) -> list[dict]:
    """Try every single-byte key; keep decodings with a NAMED flag (strict, to
    avoid the generic {..} pattern matching random XOR output)."""
    hits = []
    for k in range(256):
        dec = bytes(c ^ k for c in b)
        fl = scan_text(dec.decode("latin-1", "replace"), strict=True)
        if fl:
            hits.append({"key": k, "text": dec.decode("latin-1", "replace"),
                         "flags": fl})
    return hits


def magic(data: bytes, max_depth: int = 8, max_nodes: int = 500) -> dict:
    """BFS decode. Returns {found, flags, path:[method,...], sample}."""
    start = data if isinstance(data, bytes) else str(data).encode()
    seen: set[bytes] = set()
    q: deque[tuple[bytes, list[str]]] = deque([(start, [])])
    nodes = 0
    best_path: list[str] = []

    while q and nodes < max_nodes:
        cur, path = q.popleft()
        nodes += 1
        key = cur[:2048]
        if key in seen:
            continue
        seen.add(key)

        # flag check at this layer (strict: decoded layers are noisy)
        fl = scan_text(cur.decode("latin-1", "replace"), strict=True)
        if fl and path:
            return {"found": True, "flags": fl, "path": path,
                    "sample": cur[:400].decode("latin-1", "replace")}
        # xor terminal check
        for hit in xor_bruteforce(cur) if len(cur) <= 4096 else []:
            return {"found": True, "flags": hit["flags"],
                    "path": path + [f"xor(0x{hit['key']:02x})"],
                    "sample": hit["text"][:400]}

        if len(path) >= max_depth:
            continue
        for name, fn in TRANSFORMS:
            try:
                out = fn(cur)
            except Exception:
                out = None
            if not out or out == cur or out[:2048] in seen:
                continue
            # only pursue branches that stay plausibly decodable/text-ish
            if _printable_ratio(out) < 0.6 and name not in ("gzip", "zlib",
                                                            "base64", "hex"):
                continue
            newp = path + [name]
            if not best_path or len(newp) < len(best_path):
                best_path = newp
            q.append((out, newp))

    return {"found": False, "flags": [], "path": best_path, "sample": ""}
