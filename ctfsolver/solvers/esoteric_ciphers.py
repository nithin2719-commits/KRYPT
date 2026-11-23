"""Esoteric and classical ciphers engine: DNA, T9 phone keypad, NATO phonetic, Polybius, Rail Fence, and COW."""
from __future__ import annotations

import re
from typing import Any

from ..flags import scan_text


# Standard genetic code (DNA -> Amino Acid 1-letter code)
DNA_CODON_TABLE = {
    "ATA": "I", "ATC": "I", "ATT": "I", "ATG": "M",
    "ACA": "T", "ACC": "T", "ACG": "T", "ACT": "T",
    "AAC": "N", "AAT": "N", "AAA": "K", "AAG": "K",
    "AGC": "S", "AGT": "S", "AGA": "R", "AGG": "R",
    "CTA": "L", "CTC": "L", "CTG": "L", "CTT": "L",
    "CCA": "P", "CCC": "P", "CCG": "P", "CCT": "P",
    "CAC": "H", "CAT": "H", "CAA": "Q", "CAG": "Q",
    "CGA": "R", "CGC": "R", "CGG": "R", "CGT": "R",
    "GTA": "V", "GTC": "V", "GTG": "V", "GTT": "V",
    "GCA": "A", "GCC": "A", "GCG": "A", "GCT": "A",
    "GAC": "D", "GAT": "D", "GAA": "E", "GAG": "E",
    "GGA": "G", "GGC": "G", "GGG": "G", "GGT": "G",
    "TCA": "S", "TCC": "S", "TCG": "S", "TCT": "S",
    "TTC": "F", "TTT": "F", "TTA": "L", "TTG": "L",
    "TAC": "Y", "TAT": "Y", "TAA": "*", "TAG": "*",
    "TGC": "C", "TGT": "C", "TGA": "*", "TGG": "W",
}

# T9 Keypad mapping
T9_KEYPAD = {
    "2": "A", "22": "B", "222": "C",
    "3": "D", "33": "E", "333": "F",
    "4": "G", "44": "H", "444": "I",
    "5": "J", "55": "K", "555": "L",
    "6": "M", "66": "N", "666": "O",
    "7": "P", "77": "Q", "777": "R", "7777": "S",
    "8": "T", "88": "U", "888": "V",
    "9": "W", "99": "X", "999": "Y", "9999": "Z",
    "0": " ",
}

# NATO Phonetic table
NATO_ALPHABET = {
    "alfa": "A", "alpha": "A", "bravo": "B", "charlie": "C", "delta": "D",
    "echo": "E", "foxtrot": "F", "golf": "G", "hotel": "H", "india": "I",
    "juliett": "J", "juliet": "J", "kilo": "K", "lima": "L", "mike": "M",
    "november": "N", "oscar": "O", "papa": "P", "quebec": "Q", "romeo": "R",
    "sierra": "S", "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W",
    "x-ray": "X", "xray": "X", "yankee": "Y", "zulu": "Z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"
}

# Polybius square 5x5 (I/J combined)
POLYBIUS_SQUARE = {
    (1, 1): "A", (1, 2): "B", (1, 3): "C", (1, 4): "D", (1, 5): "E",
    (2, 1): "F", (2, 2): "G", (2, 3): "H", (2, 4): "I", (2, 5): "K",
    (3, 1): "L", (3, 2): "M", (3, 3): "N", (3, 4): "O", (3, 5): "P",
    (4, 1): "Q", (4, 2): "R", (4, 3): "S", (4, 4): "T", (4, 5): "U",
    (5, 1): "V", (5, 2): "W", (5, 3): "X", (5, 4): "Y", (5, 5): "Z"
}


def decode_dna(text: str) -> list[tuple[str, str]]:
    """Decode DNA sequence via Codon amino acid mapping or 2-bit binary packing."""
    results: list[tuple[str, str]] = []
    clean = re.sub(r"[^ACGTUacgtu]", "", text).upper().replace("U", "T")
    if len(clean) < 6:
        return results

    # 1. Codon mapping (triplets)
    if len(clean) % 3 == 0:
        aa = "".join(DNA_CODON_TABLE.get(clean[i : i + 3], "?") for i in range(0, len(clean), 3))
        if "?" not in aa:
            results.append(("dna-codon", aa))

    # 2. 2-bit binary mapping (A=00, C=01, G=10, T=11)
    mapping = {"A": "00", "C": "01", "G": "10", "T": "11"}
    bits = "".join(mapping.get(c, "") for c in clean)
    if len(bits) >= 8:
        byte_list = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte_list.append(int(bits[i : i + 8], 2))
        try:
            ascii_text = byte_list.decode("ascii")
            if any(c.isalnum() for c in ascii_text):
                results.append(("dna-2bit", ascii_text))
        except Exception:
            pass

    return results


def decode_t9(text: str) -> str:
    """Decode space-separated T9 phone keypad multi-tap digits (e.g. 222 8 333)."""
    tokens = text.strip().split()
    chars = []
    for tok in tokens:
        if tok in T9_KEYPAD:
            chars.append(T9_KEYPAD[tok])
        elif re.fullmatch(r"[02-9]+", tok):
            # Sequence of repeated digits without spaces: e.g. 4433555555666 -> HELLO
            i = 0
            while i < len(tok):
                ch = tok[i]
                run_len = 1
                while i + run_len < len(tok) and tok[i + run_len] == ch and run_len < 4:
                    run_len += 1
                chars.append(T9_KEYPAD.get(ch * run_len, "?"))
                i += run_len
        else:
            return ""
    return "".join(chars)


def decode_nato(text: str) -> str:
    """Decode NATO phonetic words (e.g. 'Sierra Tango Echo Golf')."""
    raw_words = [re.sub(r"[^a-zA-Z0-9]", "", w).lower() for w in text.split()]
    words = [w for w in raw_words if w]
    if len(words) < 3:
        return ""
    matched = 0
    letters = []
    for w in words:
        if w in NATO_ALPHABET:
            letters.append(NATO_ALPHABET[w])
            matched += 1
        else:
            letters.append(" ")

    if matched >= 3 and (matched / len(words)) >= 0.5:
        return "".join(letters).strip()
    return ""


def decode_polybius(text: str) -> str:
    """Decode Polybius square coordinate pairs (e.g. '21 31 11 22')."""
    digits = re.sub(r"[^1-5]", "", text)
    if len(digits) < 6 or len(digits) % 2 != 0:
        return ""
    chars = []
    for i in range(0, len(digits), 2):
        row = int(digits[i])
        col = int(digits[i + 1])
        chars.append(POLYBIUS_SQUARE.get((row, col), "?"))
    return "".join(chars)


def decode_rail_fence(cipher: str, rails: int) -> str:
    """Decrypt Rail Fence (zigzag transposition) cipher for given rail depth."""
    if rails < 2 or rails >= len(cipher):
        return cipher

    fence = [["\n" for _ in range(len(cipher))] for _ in range(rails)]
    down = None
    row, col = 0, 0

    for i in range(len(cipher)):
        if row == 0:
            down = True
        elif row == rails - 1:
            down = False
        fence[row][col] = "*"
        col += 1
        row += 1 if down else -1

    idx = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] == "*" and idx < len(cipher):
                fence[r][c] = cipher[idx]
                idx += 1

    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            down = True
        elif row == rails - 1:
            down = False
        if fence[row][col] != "*":
            result.append(fence[row][col])
            col += 1
        row += 1 if down else -1

    return "".join(result)


def run_cow(code: str) -> str:
    """Execute COW esoteric programming language (moo, MoO, mOo, etc.)."""
    commands = re.findall(r"\b[mM][oO]{2}\b", code)
    if len(commands) < 4:
        return ""

    memory = [0] * 1000
    ptr = 0
    register: int | None = None
    pc = 0
    output: list[str] = []
    steps = 0
    max_steps = 100000

    # Build loop map for [MoO, moO]
    loop_stack = []
    loop_map = {}
    for i, cmd in enumerate(commands):
        if cmd == "MoO":
            loop_stack.append(i)
        elif cmd == "moO":
            if loop_stack:
                start = loop_stack.pop()
                loop_map[start] = i
                loop_map[i] = start

    while pc < len(commands) and steps < max_steps:
        steps += 1
        cmd = commands[pc]
        if cmd == "moo":
            pc -= 2  # Execute command before previous
            continue
        elif cmd == "mOo":
            ptr = max(0, (ptr - 1) % 1000)
        elif cmd == "moO":
            if memory[ptr] != 0:
                pc = loop_map.get(pc, pc)
        elif cmd == "mOO":
            # Execute command code in current memory block
            pass
        elif cmd == "Moo":
            if memory[ptr] == 0:
                pass
            else:
                output.append(chr(memory[ptr] % 256))
        elif cmd == "MOo":
            memory[ptr] = (memory[ptr] - 1) % 256
        elif cmd == "MoO":
            if memory[ptr] == 0:
                pc = loop_map.get(pc, pc)
        elif cmd == "MOO":
            register = memory[ptr]
        elif cmd == "OOO":
            memory[ptr] = 0
        elif cmd == "MMM":
            if register is not None:
                memory[ptr] = register
        elif cmd == "OOM":
            output.append(str(memory[ptr]))
        pc += 1

    return "".join(output)


def solve(text: str) -> list[dict[str, Any]]:
    """Scan and attempt all esoteric and classical ciphers."""
    results: list[dict[str, Any]] = []

    # 1. DNA check
    dna_decodes = decode_dna(text)
    for method, dec in dna_decodes:
        flags = scan_text(dec)
        if flags or "flag" in dec.lower():
            results.append({"method": method, "text": dec, "flags": flags})

    # 2. T9 keypad check
    if re.search(r"\b[02-9]{1,4}\b", text):
        t9_dec = decode_t9(text)
        if t9_dec:
            flags = scan_text(t9_dec)
            if flags or "flag" in t9_dec.lower():
                results.append({"method": "t9-keypad", "text": t9_dec, "flags": flags})

    # 3. NATO phonetic check
    nato_dec = decode_nato(text)
    if nato_dec:
        flags = scan_text(nato_dec)
        if flags or "flag" in nato_dec.lower():
            results.append({"method": "nato-phonetic", "text": nato_dec, "flags": flags})

    # 4. Polybius coordinates
    poly_dec = decode_polybius(text)
    if poly_dec:
        flags = scan_text(poly_dec)
        if flags or "flag" in poly_dec.lower():
            results.append({"method": "polybius-square", "text": poly_dec, "flags": flags})

    # 5. Rail fence brute force (depth 2 to 10)
    clean_text = text.strip()
    if 10 <= len(clean_text) <= 500:
        for depth in range(2, min(10, len(clean_text) // 2)):
            rf_dec = decode_rail_fence(clean_text, depth)
            rf_flags = scan_text(rf_dec)
            if rf_flags:
                results.append({"method": f"rail-fence-{depth}", "text": rf_dec, "flags": rf_flags})
                break

    # 6. COW esoteric language check
    if "moo" in text.lower() and len(re.findall(r"\b[mM][oO]{2}\b", text)) >= 4:
        cow_out = run_cow(text)
        if cow_out:
            cow_flags = scan_text(cow_out)
            results.append({"method": "cow-esoteric", "text": cow_out, "flags": cow_flags})

    return results
