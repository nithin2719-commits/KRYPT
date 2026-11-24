"""Comprehensive XOR cryptanalysis suite for CTF challenges.

Implements:
1. single_byte_xor(data) -> list[dict]: Try all 256 single-byte keys, score each result
   by English character frequency (ETAOINSHRDLU), return top 5 results sorted by score.
2. repeating_key_xor(data, max_keylen) -> list[dict]: Kasiski examination and Hamming
   distance method to determine key length, then single-byte XOR each column.
3. known_plaintext_xor(ciphertext, known) -> bytes: Recover key given known plaintext fragment.
4. xor_with_key(data, key) -> bytes: Apply repeating XOR encryption/decryption.
5. multi_time_pad(ciphertexts) -> list[dict]: Crib-dragging and many-time pad attack when
   multiple messages are encrypted with the same key.
6. detect_xor_encrypted(data) -> bool: Statistical test (high entropy + no null bytes +
   not valid UTF-8).
7. solve(target, workdir) -> dict: Read file, detect if XOR encrypted, try single-byte
   then repeating-key, scan all results for flags.
"""
from __future__ import annotations

from collections import Counter
import math
import os
import re
from typing import Any

try:
    from ..flags import scan_bytes, scan_text
    from ..runner import have, run
except (ImportError, ValueError):
    try:
        from ctfsolver.flags import scan_bytes, scan_text
        from ctfsolver.runner import have, run
    except ImportError:
        def scan_text(text: str, strict: bool = False) -> list[dict]:
            flags = []
            for p in [r"flag\{[^}\n]+\}", r"FLAG\{[^}\n]+\}", r"CTF\{[^}\n]+\}"]:
                for m in re.finditer(p, text):
                    flags.append({"flag": m.group(0), "confidence": 90})
            return flags

        def scan_bytes(data: bytes) -> list[dict]:
            return scan_text(data.decode("latin-1", "replace"))

        def have(cmd: str) -> bool:
            import shutil
            return shutil.which(cmd) is not None

        def run(cmd: list[str], timeout: int = 30) -> None:
            pass


# Standard English letter frequencies (ETAOINSHRDLU...)
ENGLISH_FREQ: dict[str, float] = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702,
    "f": 0.02228, "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153,
    "k": 0.00772, "l": 0.04025, "m": 0.02406, "n": 0.06749, "o": 0.07507,
    "p": 0.01929, "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150, "y": 0.01974,
    "z": 0.00074, " ": 0.13000,
}

COMMON_CRIBS: list[bytes] = [
    b"flag{", b"FLAG{", b"CTF{", b" the ", b"The ", b" that ",
    b" with ", b" this ", b" from ", b" have ", b"http://", b"https://",
    b"is ", b" in ", b" of ", b" to ",
]


def score_text(data: bytes) -> float:
    """Score a byte sequence based on English character frequency (ETAOINSHRDLU)."""
    if not data:
        return 0.0
    total = 0.0
    for byte in data:
        if byte in (10, 13, 9):  # whitespace: \n, \r, \t
            total += 1.0
        elif byte == 32:  # space
            total += 13.0
        elif 65 <= byte <= 90:  # uppercase A-Z
            total += ENGLISH_FREQ.get(chr(byte).lower(), 0.0) * 100.0
        elif 97 <= byte <= 122:  # lowercase a-z
            total += ENGLISH_FREQ.get(chr(byte), 0.0) * 100.0
        elif byte in b"_{}-!?,.'\"/:;()[]0123456789":
            total += 1.5
        elif byte in b"^\\`~|@#$%=+<>*&":
            total -= 10.0
        elif 32 <= byte <= 126:
            total += 0.5
        else:
            total -= 30.0
    return round(total, 2)


def xor_with_key(data: bytes, key: bytes) -> bytes:
    """Apply repeating-key XOR encryption/decryption."""
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def single_byte_xor(data: bytes) -> list[dict[str, Any]]:
    """Try all 256 single-byte keys, score each result by English character frequency,
    and return the top 5 results sorted by score with {"key": int, "plaintext": str, "score": float}.
    """
    if not data:
        return []
    candidates: list[dict[str, Any]] = []
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        score = score_text(dec)
        candidates.append({
            "key": k,
            "plaintext": dec.decode("latin-1", "replace"),
            "score": score,
        })
    candidates.sort(key=lambda r: r["score"], reverse=True)
    return candidates[:5]


def _find_repeating_key(keystream: bytes) -> bytes:
    """Find the shortest repeating primitive key pattern."""
    n = len(keystream)
    if n <= 1:
        return keystream
    for p in range(1, n // 2 + 1):
        if keystream == (keystream[:p] * (n // p + 1))[:n]:
            return keystream[:p]
    for p in range(n // 2 + 1, n - 1):
        if keystream == (keystream[:p] * 2)[:n]:
            return keystream[:p]
    return keystream


def known_plaintext_xor(ciphertext: bytes, known: bytes, offset: int = 0) -> bytes:
    """Recover key given known plaintext fragment."""
    if not ciphertext or not known or offset >= len(ciphertext):
        return b""
    raw_key = bytes(c ^ p for c, p in zip(ciphertext[offset:], known))
    return _find_repeating_key(raw_key)


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate the Hamming distance (number of differing bits) between two byte strings."""
    return sum((x ^ y).bit_count() for x, y in zip(b1, b2))


def _index_of_coincidence(data: bytes) -> float:
    """Calculate the Index of Coincidence of a byte slice."""
    if len(data) <= 1:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _kasiski_examination(data: bytes, max_keylen: int = 40) -> list[int]:
    """Find likely key lengths via Kasiski examination (repeated n-grams)."""
    positions: dict[bytes, list[int]] = {}
    for n in (3, 4, 5):
        for i in range(len(data) - n + 1):
            ngram = data[i : i + n]
            positions.setdefault(ngram, []).append(i)
    factors: Counter[int] = Counter()
    for _, pos_list in positions.items():
        if len(pos_list) < 2:
            continue
        for i in range(len(pos_list) - 1):
            diff = pos_list[i + 1] - pos_list[i]
            for factor in range(2, max_keylen + 1):
                if diff % factor == 0:
                    factors[factor] += 1
    return [k for k, _ in factors.most_common(8)]


def repeating_key_xor(data: bytes, max_keylen: int = 40) -> list[dict[str, Any]]:
    """Determine key length using Hamming distance and Kasiski examination,
    then single-byte XOR each column. Return top candidates with
    {"key": bytes, "plaintext": str, "score": float}.
    """
    if not data or len(data) < 2:
        return []
    max_k = min(max_keylen, max(2, len(data) // 2))

    # Evaluate candidate key lengths using normalized Hamming distance and IoC
    length_scores: dict[int, float] = {}
    for klen in range(2, max_k + 1):
        m = len(data) // klen
        if m >= 2:
            num_pairs = min(m - 1, 6)
            dists = [
                hamming_distance(data[i * klen : (i + 1) * klen], data[(i + 1) * klen : (i + 2) * klen]) / klen
                for i in range(num_pairs)
            ]
            avg_d = sum(dists) / len(dists)
        else:
            avg_d = 4.0

        avg_ioc = sum(_index_of_coincidence(data[i::klen]) for i in range(klen)) / klen
        # Higher IoC and lower Hamming distance indicate likely key length
        length_scores[klen] = avg_ioc / max(0.1, avg_d)

    ranked_lengths = sorted(length_scores.keys(), key=lambda k: length_scores[k], reverse=True)
    candidate_lengths = ranked_lengths[:8]

    # Incorporate Kasiski examination suggestions
    kasiski_lens = _kasiski_examination(data, max_keylen=max_k)
    for kl in kasiski_lens:
        if kl not in candidate_lengths:
            candidate_lengths.append(kl)

    if not candidate_lengths:
        candidate_lengths = list(range(2, min(max_k + 1, 10)))

    results: list[dict[str, Any]] = []
    seen_keys: set[bytes] = set()

    for klen in candidate_lengths:
        col_keys = []
        for i in range(klen):
            col = data[i::klen]
            best_k = max(range(256), key=lambda k: score_text(bytes(b ^ k for b in col)))
            col_keys.append(best_k)

        cand_key = _find_repeating_key(bytes(col_keys))
        if cand_key in seen_keys:
            continue
        seen_keys.add(cand_key)

        dec = xor_with_key(data, cand_key)
        score = score_text(dec)
        results.append({
            "key": cand_key,
            "plaintext": dec.decode("latin-1", "replace"),
            "score": score,
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:5]


def multi_time_pad(ciphertexts: list[bytes], cribs: list[bytes] | None = None) -> list[dict[str, Any]]:
    """Crib-dragging attack when multiple messages are encrypted with the same key.
    XOR pairs and look for valid ASCII in the differences.
    """
    if not ciphertexts or len(ciphertexts) < 2:
        return []

    active_cribs = cribs or COMMON_CRIBS
    max_len = max(len(c) for c in ciphertexts)
    recovered_keystream: list[int | None] = [None] * max_len
    results: list[dict[str, Any]] = []
    seen_keys: set[bytes] = set()

    # 1. Multi-Time Pad Space Correlation Attack (when >= 3 ciphertexts)
    if len(ciphertexts) >= 3:
        for pos in range(max_len):
            avail = [c for c in ciphertexts if pos < len(c)]
            if len(avail) < 3:
                continue
            for j, cj in enumerate(avail):
                matches = 0
                for k, ck in enumerate(avail):
                    if j == k:
                        continue
                    diff = cj[pos] ^ ck[pos]
                    if chr(diff).isalpha() or diff == 0:
                        matches += 1
                if matches >= 0.7 * (len(avail) - 1):
                    recovered_keystream[pos] = cj[pos] ^ 0x20
                    break

    # 2. Pairwise Crib-Dragging across differences
    for a in range(len(ciphertexts)):
        for b in range(a + 1, len(ciphertexts)):
            ca, cb = ciphertexts[a], ciphertexts[b]
            pair_len = min(len(ca), len(cb))
            diff = bytes(ca[k] ^ cb[k] for k in range(pair_len))

            for crib in active_cribs:
                clen = len(crib)
                if clen > pair_len:
                    continue
                for pos in range(pair_len - clen + 1):
                    cand_frag = bytes(d ^ c for d, c in zip(diff[pos : pos + clen], crib))
                    if all(32 <= byte <= 126 or byte in (10, 13, 9) for byte in cand_frag):
                        s = score_text(cand_frag)
                        if s > 0:
                            k_a = bytes(x ^ y for x, y in zip(ca[pos : pos + clen], crib))
                            k_b = bytes(x ^ y for x, y in zip(cb[pos : pos + clen], crib))

                            for k_frag in (k_a, k_b):
                                rep_k = _find_repeating_key(k_frag)
                                for cand_k in (rep_k, k_frag):
                                    if cand_k and cand_k not in seen_keys:
                                        seen_keys.add(cand_k)
                                        for idx, ct in enumerate(ciphertexts):
                                            pt_bytes = xor_with_key(ct, cand_k)
                                            results.append({
                                                "index": idx,
                                                "key": cand_k,
                                                "plaintext": pt_bytes.decode("latin-1", "replace"),
                                                "score": score_text(pt_bytes),
                                            })

                            for offset_idx, kb in enumerate(k_a):
                                if recovered_keystream[pos + offset_idx] is None:
                                    recovered_keystream[pos + offset_idx] = kb

    # 3. Decrypt all ciphertexts with the recovered keystream (if high recovery)
    matched_count = sum(1 for k in recovered_keystream if k is not None)
    if matched_count > 0 and (matched_count / max_len >= 0.5 or len(ciphertexts) >= 3):
        full_key_bytes = []
        for pos, kb in enumerate(recovered_keystream):
            if kb is not None:
                full_key_bytes.append(kb)
            else:
                best_b = 0
                best_s = -1e9
                for cand_b in range(256):
                    s = 0.0
                    for ct in ciphertexts:
                        if pos < len(ct):
                            pt_b = ct[pos] ^ cand_b
                            if 65 <= pt_b <= 90 or 97 <= pt_b <= 122:
                                s += ENGLISH_FREQ.get(chr(pt_b).lower(), 0.0) * 100
                            elif pt_b == 32:
                                s += 13.0
                            elif 32 <= pt_b <= 126:
                                s += 0.5
                            else:
                                s -= 20.0
                    if s > best_s:
                        best_s = s
                        best_b = cand_b
                full_key_bytes.append(best_b)

        recovered_key = bytes(full_key_bytes)
        rep_key = _find_repeating_key(recovered_key)

        for cand_k in (recovered_key, rep_key):
            if cand_k and cand_k not in seen_keys:
                seen_keys.add(cand_k)
                for idx, ct in enumerate(ciphertexts):
                    pt_bytes = xor_with_key(ct, cand_k)
                    results.append({
                        "index": idx,
                        "key": cand_k,
                        "plaintext": pt_bytes.decode("latin-1", "replace"),
                        "score": score_text(pt_bytes),
                    })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def detect_xor_encrypted(data: bytes) -> bool:
    """Statistical test — high entropy + no null bytes + not valid UTF-8 suggests XOR."""
    if not data or len(data) < 8:
        return False

    # 1. No null bytes
    if b"\x00" in data:
        return False

    # 2. Not valid UTF-8 text (or invalid control-character density)
    is_valid_utf8_text = True
    try:
        decoded = data.decode("utf-8")
        control_chars = sum(1 for c in decoded if ord(c) < 32 and c not in "\r\n\t")
        if len(decoded) > 0 and (control_chars / len(decoded)) > 0.03:
            is_valid_utf8_text = False
    except UnicodeDecodeError:
        is_valid_utf8_text = False

    if is_valid_utf8_text:
        return False

    # 3. High entropy test
    n = len(data)
    counts = Counter(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    min_entropy = min(3.2, 0.75 * math.log2(min(n, 256)))

    return entropy >= min_entropy


from .registry import register_solver


def match_xor(ctx) -> bool:
    if ctx.category == "crypto":
        return True
    if ctx.combined_text:
        return True
    if ctx.target:
        lower = ctx.target.lower()
        return lower.endswith((".xor", ".bin", ".dat", ".txt", ".enc", ".raw", ".cipher")) or "." not in os.path.basename(ctx.target)
    return False


@register_solver(
    name="xor_solver",
    category="crypto",
    priority=75,
    match_fn=match_xor,
    description="Pure-Python XOR cryptanalysis (single-byte, repeating-key Kasiski, many-time pad)",
)
def solve(target: str, workdir: str = "") -> dict[str, Any]:
    """Read file or input data, detect if XOR encrypted, try single-byte then
    repeating-key, scan all results for flags.
    Return {"step": "xor-crypto", "flags": [...], "output": "..."}.
    """
    flags: list[dict[str, Any]] = []
    notes: list[str] = []
    raw_data: bytes = b""
    cipher_lines: list[bytes] = []

    # 1. Read target (file path, hex string, base64, or raw data)
    if os.path.isfile(target):
        try:
            with open(target, "rb") as fh:
                raw_data = fh.read()
            notes.append(f"Read {len(raw_data)} bytes from {os.path.basename(target)}")
        except OSError as e:
            return {"step": "xor-crypto", "flags": [], "output": f"Failed to read file {target}: {e}"}
    elif isinstance(target, str):
        target_stripped = target.strip()
        try:
            raw_data = bytes.fromhex(target_stripped)
            notes.append(f"Parsed hex string input ({len(raw_data)} bytes)")
        except ValueError:
            import base64
            try:
                raw_data = base64.b64decode(target_stripped, validate=True)
                notes.append(f"Decoded base64 string input ({len(raw_data)} bytes)")
            except Exception:
                raw_data = target.encode("latin-1")
                notes.append("Using raw string input")

    if not raw_data:
        return {"step": "xor-crypto", "flags": [], "output": "No data provided to solve"}

    # 2. Check if input contains hex-encoded lines (e.g. multi-line hex or multi-time pad)
    try:
        text_content = raw_data.decode("ascii")
        lines = [line.strip() for line in text_content.splitlines() if line.strip()]
        if len(lines) > 1 and all(len(l) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in l) for l in lines):
            cipher_lines = [bytes.fromhex(l) for l in lines]
            notes.append(f"Detected {len(cipher_lines)} hex-encoded ciphertext lines")
        elif len(lines) == 1 and len(lines[0]) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in lines[0]):
            raw_data = bytes.fromhex(lines[0])
            notes.append("Unwrapped single hex-encoded line")
    except UnicodeDecodeError:
        pass

    # 3. Statistical detection
    is_xor = detect_xor_encrypted(raw_data)
    notes.append(f"Statistical XOR detection: {is_xor}")

    # Flag collection helper
    seen_flag_strings: set[str] = set()

    def add_flags(found_list: list[dict[str, Any]], method: str) -> None:
        for f in found_list:
            flag_str = f.get("flag", "")
            if flag_str and flag_str not in seen_flag_strings:
                seen_flag_strings.add(flag_str)
                f["method"] = method
                flags.append(f)

    # 4. Single-byte XOR
    single_res = single_byte_xor(raw_data)
    for cand in single_res:
        fl = scan_text(cand["plaintext"], strict=True) or scan_text(cand["plaintext"])
        if fl:
            add_flags(fl, f"single-byte-xor(0x{cand['key']:02x})")
            notes.append(f"Flag found via single-byte XOR key 0x{cand['key']:02x}: {cand['plaintext'][:60]}")

    # 5. Repeating-key XOR
    if len(raw_data) >= 4:
        rep_res = repeating_key_xor(raw_data, max_keylen=40)
        for cand in rep_res:
            fl = scan_text(cand["plaintext"], strict=True) or scan_text(cand["plaintext"])
            if fl:
                key_repr = cand["key"].decode("latin-1", "replace") if cand["key"] else ""
                add_flags(fl, f"repeating-key-xor({cand['key'].hex()})")
                notes.append(f"Flag found via repeating key {key_repr!r} (0x{cand['key'].hex()}): {cand['plaintext'][:60]}")

    # 6. Known-plaintext XOR attack with standard flag headers
    if len(raw_data) >= 5:
        for prefix in (b"flag{", b"FLAG{", b"CTF{", b"htb{", b"HTB{", b"picoCTF{"):
            cand_key = known_plaintext_xor(raw_data, prefix)
            if cand_key:
                dec = xor_with_key(raw_data, cand_key)
                dec_text = dec.decode("latin-1", "replace")
                fl = scan_text(dec_text, strict=True) or scan_text(dec_text)
                if fl:
                    add_flags(fl, f"known-plaintext({prefix.decode()})")
                    notes.append(f"Flag found via known-plaintext {prefix.decode()} -> key {cand_key.hex()}: {dec_text[:60]}")

    # 7. If multiple ciphertexts exist, try multi-time pad attack and per-line attacks
    if cipher_lines:
        mtp_res = multi_time_pad(cipher_lines)
        for cand in mtp_res:
            fl = scan_text(cand["plaintext"], strict=True) or scan_text(cand["plaintext"])
            if fl:
                add_flags(fl, f"multi-time-pad(line_{cand.get('index', '?')})")
                notes.append(f"Flag found via multi-time-pad: {cand['plaintext'][:60]}")

        for idx, line in enumerate(cipher_lines):
            line_single = single_byte_xor(line)
            for cand in line_single:
                fl = scan_text(cand["plaintext"], strict=True) or scan_text(cand["plaintext"])
                if fl:
                    add_flags(fl, f"single-byte-xor(line_{idx},0x{cand['key']:02x})")
                    notes.append(f"Flag found in line {idx} via key 0x{cand['key']:02x}: {cand['plaintext'][:60]}")

    summary_msg = f"XOR cryptanalysis: found {len(flags)} flag(s)."
    if single_res and not flags:
        top = single_res[0]
        notes.append(f"Top single-byte candidate (key 0x{top['key']:02x}, score {top['score']}): {top['plaintext'][:80]}")

    return {
        "step": "xor-crypto",
        "flags": flags,
        "summary": summary_msg,
        "output": "\n".join(notes),
    }
