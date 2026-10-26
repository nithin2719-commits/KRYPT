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
import os
import re
import zlib
from collections import deque

from .flags import scan_text

_WS = re.compile(rb"\s+")
# Nodes larger than this are still flag-checked but never *expanded*: applying
# the transforms to large blobs — especially the letter rotations (rot13/47,
# atbash), which keep emitting fresh all-alphabet strings that every base-N
# decoder then re-expands — makes the BFS blow up to minutes on a ~1 MB input.
# Real chained encodings hide a flag in small ciphertext, well under this.
_BRANCH_MAX = 64 * 1024


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
    if not s or len(s) % 4 == 1:
        return None
    # standard alphabet
    if re.fullmatch(rb"[A-Za-z0-9+/=]+", s):
        try:
            out = base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
            return out or None
        except (binascii.Error, ValueError):
            return None
    # URL-safe alphabet (-, _) — common for JWTs and web tokens
    if re.fullmatch(rb"[A-Za-z0-9_\-=]+", s) and (b"-" in s or b"_" in s):
        try:
            out = base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
            return out or None
        except (binascii.Error, ValueError):
            return None
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
    except Exception:
        return None


def d_ascii85(b):
    s = _WS.sub(b"", b)
    try:
        return base64.a85decode(s) or None
    except Exception:
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
    # base58 decode is big-integer O(n²); a multi-KB run (which is never a real
    # base58 flag) would stall the BFS for seconds. Cap the length — addresses,
    # keys and flag ciphertext are all well under this.
    if not s or len(s) < 4 or len(s) > 2048 or any(c not in _B58 for c in s):
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


_BACON_24 = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "K",
    "ABABA": "L", "ABABB": "M", "ABBAA": "N", "ABBAB": "O", "ABBBA": "P",
    "ABBBB": "Q", "BAAAA": "R", "BAAAB": "S", "BAABA": "T", "BAABB": "U",
    "BABAA": "W", "BABAB": "X", "BABBA": "Y", "BABBB": "Z"
}

_BACON_26 = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
    "BBAAB": "Z"
}


def d_bacon(b: bytes) -> bytes | None:
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    raw = re.sub(r"\s+", "", s)
    if not raw or len(raw) < 5:
        return None
    candidates = []
    if all(c in "01" for c in raw):
        candidates.append(raw.replace("0", "A").replace("1", "B"))
        candidates.append(raw.replace("1", "A").replace("0", "B"))
    elif all(c in "abAB" for c in raw):
        u = raw.upper()
        candidates.append(u)
        candidates.append(u.translate(str.maketrans("AB", "BA")))
    else:
        return None

    for cand in candidates:
        if len(cand) % 5 != 0:
            continue
        for mapping in (_BACON_26, _BACON_24):
            res = []
            valid = True
            for i in range(0, len(cand), 5):
                chunk = cand[i:i + 5]
                ch = mapping.get(chunk)
                if not ch:
                    valid = False
                    break
                res.append(ch)
            if valid and res:
                return "".join(res).encode()
    return None


_B62 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def d_base62(b: bytes) -> bytes | None:
    s = _WS.sub(b"", b)
    if not s or len(s) < 4 or len(s) > 2048 or any(c not in _B62 for c in s):
        return None
    try:
        num = 0
        for c in s:
            num = num * 62 + _B62.index(c)
        raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        pad = len(s) - len(s.lstrip(b"0"))
        return b"\x00" * pad + raw or None
    except Exception:
        return None


_BRAILLE_MAP = {
    "\u2801": "a", "\u2803": "b", "\u2809": "c", "\u2819": "d", "\u2811": "e",
    "\u280b": "f", "\u281b": "g", "\u2813": "h", "\u280a": "i", "\u281a": "j",
    "\u2805": "k", "\u2807": "l", "\u280d": "m", "\u281d": "n", "\u2815": "o",
    "\u280f": "p", "\u281f": "q", "\u2817": "r", "\u280e": "s", "\u281e": "t",
    "\u2825": "u", "\u2827": "v", "\u283a": "w", "\u282d": "x", "\u283d": "y",
    "\u2835": "z", "\u2800": " ", "\u2824": "-", "\u2804": "'", "\u2802": ",",
    "\u2806": ";", "\u2812": ":", "\u2832": ".", "\u2826": "?", "\u2816": "!"
}


def d_braille(b: bytes) -> bytes | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not any(c in _BRAILLE_MAP for c in s):
        return None
    out = "".join(_BRAILLE_MAP.get(c, c) for c in s)
    return out.encode("utf-8") if out != s else None


TRANSFORMS = [
    ("base64", d_base64), ("base32", d_base32), ("base85", d_base85),
    ("ascii85", d_ascii85), ("base58", d_base58), ("base62", d_base62),
    ("hex", d_hex), ("decimal", d_decimal), ("binary", d_binary),
    ("morse", d_morse), ("bacon", d_bacon), ("braille", d_braille),
    ("url", d_url), ("rot13", d_rot13), ("rot47", d_rot47),
    ("atbash", d_atbash), ("reverse", d_reverse),
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


def _caesar(s: str, k: int) -> str:
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def caesar_bruteforce(b: bytes) -> list[dict]:
    """Try all 25 Caesar shifts; keep any yielding a NAMED/custom flag.

    rot13 (shift 13) is also a BFS transform, but a Caesar with any other shift
    (3, 7, …) — extremely common in beginner crypto — otherwise never decodes,
    because only the single shift-13 rotation was ever tried.
    """
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return []
    if not any(c.isalpha() for c in s):
        return []
    hits = []
    for k in range(1, 26):
        dec = _caesar(s, k)
        fl = scan_text(dec, strict=True)
        if fl:
            hits.append({"shift": k, "text": dec, "flags": fl})
    return hits


_AFFINE_A = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)
_AFFINE_INV = {a: pow(a, -1, 26) for a in _AFFINE_A}


def affine_bruteforce(b: bytes) -> list[dict]:
    """Try all 312 Affine cipher keys (12 coprimes * 26 shifts).
    C = (a * P + b) % 26 -> P = (a_inv * (C - b)) % 26.
    Strict scan guarantees zero false positives.
    """
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return []
    if not any(c.isalpha() for c in s):
        return []
    hits = []
    for a in _AFFINE_A:
        if a == 1:
            continue  # a=1 is Caesar brute-force, already tested
        a_inv = _AFFINE_INV[a]
        for shift in range(26):
            out = []
            for c in s:
                if "a" <= c <= "z":
                    out.append(chr((a_inv * (ord(c) - 97 - shift)) % 26 + 97))
                elif "A" <= c <= "Z":
                    out.append(chr((a_inv * (ord(c) - 65 - shift)) % 26 + 65))
                else:
                    out.append(c)
            dec = "".join(out)
            fl = scan_text(dec, strict=True)
            if fl:
                hits.append({"a": a, "b": shift, "text": dec, "flags": fl})
    return hits


def vigenere_crib(b: bytes) -> list[dict]:
    """Recover a repeating alphabetic key using known flag crib prefixes.
    For key length 1 <= klen < len(crib_alpha), derives the key and verifies
    that it matches across all crib characters (overconstrained check),
    ensuring no false positives.
    """
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return []
    s_alpha = [c for c in s if c.isalpha()]
    if len(s_alpha) < 5:
        return []
    for raw_crib in _xor_cribs():
        try:
            crib = raw_crib.decode("ascii")
        except Exception:
            continue
        c_alpha = [c for c in crib if c.isalpha()]
        clen = len(c_alpha)
        if len(s_alpha) < clen + 1:
            continue
        for klen in range(1, clen):
            k = [(ord(s_alpha[i].lower()) - ord(c_alpha[i].lower())) % 26 for i in range(klen)]
            # Verify repeating key reproduces the ENTIRE crib
            if not all((ord(s_alpha[i].lower()) - 97 - k[i % klen]) % 26 == (ord(c_alpha[i].lower()) - 97)
                       for i in range(clen)):
                continue
            keystr = "".join(chr(x + 97) for x in k)
            # Decrypt full string
            res = []
            ki = 0
            for c in s:
                if "a" <= c <= "z":
                    res.append(chr((ord(c) - 97 - k[ki % klen]) % 26 + 97))
                    ki += 1
                elif "A" <= c <= "Z":
                    res.append(chr((ord(c) - 65 - k[ki % klen]) % 26 + 65))
                    ki += 1
                else:
                    res.append(c)
            dec = "".join(res)
            fl = scan_text(dec, strict=True)
            if fl:
                return [{"key": keystr, "text": dec, "flags": fl}]
    return []


def _xor_cribs() -> list[bytes]:
    """Known-plaintext prefixes a flag is likely to start with."""
    cribs = [b"flag{", b"FLAG{", b"CTF{", b"picoCTF{", b"HTB{",
             b"key{", b"KEY{"]
    fmt = os.environ.get("CTF_FLAG_FORMAT", "")
    if fmt:
        m = re.match(r"([A-Za-z0-9_]{1,24})\\?\{", fmt)
        if m:
            cribs.insert(0, (m.group(1) + "{").encode())
    seen, out = set(), []
    for c in cribs:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def xor_repeating_crib(b: bytes) -> list[dict]:
    """Recover a repeating-key XOR when the plaintext starts with a known flag
    prefix (crib) — the common 'whole blob is XOR(flag)' case with a multi-byte
    key, which single-byte brute force can't touch.

    For each crib and key length klen < len(crib), derive the key from the first
    klen bytes (key[i] = ct[i] ^ crib[i]) and VERIFY that this length-klen key,
    when repeated, reproduces the *entire* crib — not just the first klen bytes,
    which match by construction. Without that check any long blob would appear to
    "decode" to flag{<whatever happens to follow a stray '}'>}, since forcing the
    first bytes to the crib guarantees the prefix. The key must also be printable
    (CTF xor keys are words; non-printable keys are covered by single-byte brute)
    and the full plaintext must be text. Returns at most one hit.
    """
    if len(b) < 5:
        return []
    for crib in _xor_cribs():
        clen = len(crib)
        if len(b) < clen + 1:  # need ≥1 byte beyond the key to verify
            continue
        for klen in range(1, clen):
            key = bytes(b[i] ^ crib[i] for i in range(klen))
            # the repeating key must reproduce the WHOLE crib, and be printable
            if any(b[i] ^ key[i % klen] != crib[i] for i in range(clen)):
                continue
            if not all(32 <= k <= 126 for k in key):
                continue
            dec = bytes(b[i] ^ key[i % klen] for i in range(len(b)))
            if _printable_ratio(dec) < 0.9:
                continue
            fl = scan_text(dec.decode("latin-1", "replace"), strict=True)
            if fl:
                return [{"key": key, "text": dec.decode("latin-1", "replace"),
                         "flags": fl}]
    return []


# A long run of encoding-alphabet characters — base64/32/58/85, hex, base64url.
_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/_=\-]{12,}")


def _seed_tokens(data: bytes, limit: int = 12) -> list[bytes]:
    """Long encoded-looking substrings worth decoding on their own.

    A challenge briefing is usually prose *around* the ciphertext ("decode
    this: <blob>"), so transforming the whole text fails. Pulling the embedded
    blobs out as extra BFS seeds lets those peel too.
    """
    whole = _WS.sub(b"", data)
    out: list[bytes] = []
    seen: set[bytes] = set()
    for m in _TOKEN_RE.finditer(data):
        tok = m.group(0)
        if tok == whole or tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= limit:
            break
    return out


def magic(data: bytes, max_depth: int = 8, max_nodes: int = 500) -> dict:
    """BFS decode. Returns {found, flags, path:[method,...], sample}."""
    start = data if isinstance(data, bytes) else str(data).encode()
    seen: set[bytes] = set()
    q: deque[tuple[bytes, list[str]]] = deque([(start, [])])
    # Also seed any encoded-looking token embedded in surrounding prose.
    for tok in _seed_tokens(start):
        q.append((tok, []))
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
        # xor terminal check (single-byte, brute all 256)
        for hit in xor_bruteforce(cur) if len(cur) <= 4096 else []:
            return {"found": True, "flags": hit["flags"],
                    "path": path + [f"xor(0x{hit['key']:02x})"],
                    "sample": hit["text"][:400]}
        # caesar terminal check (all 25 shifts)
        for hit in caesar_bruteforce(cur) if len(cur) <= 4096 else []:
            return {"found": True, "flags": hit["flags"],
                    "path": path + [f"caesar(shift={hit['shift']})"],
                    "sample": hit["text"][:400]}
        # repeating-key XOR recovered from a known flag-prefix crib
        for hit in xor_repeating_crib(cur) if len(cur) <= 8192 else []:
            return {"found": True, "flags": hit["flags"],
                    "path": path + [f"xor-key({hit['key'].hex()})"],
                    "sample": hit["text"][:400]}
        # affine terminal check (all 312 keys)
        for hit in affine_bruteforce(cur) if len(cur) <= 4096 else []:
            return {"found": True, "flags": hit["flags"],
                    "path": path + [f"affine(a={hit['a']},b={hit['b']})"],
                    "sample": hit["text"][:400]}
        # vigenere crib recovery
        for hit in vigenere_crib(cur) if len(cur) <= 8192 else []:
            return {"found": True, "flags": hit["flags"],
                    "path": path + [f"vigenere(key={hit['key']})"],
                    "sample": hit["text"][:400]}

        if len(path) >= max_depth or len(cur) > _BRANCH_MAX:
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
