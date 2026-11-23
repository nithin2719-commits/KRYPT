"""SageMath advanced cryptographic attack engine for hard CTF challenges:
Lattice attacks, Coppersmith small roots, Boneh-Durfee, Hastad's Broadcast, and Common Modulus.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

from ..flags import scan_text
from ..runner import have, run


def resolve_sage() -> str:
    """Find sage binary on PATH."""
    return shutil.which("sage") or "/usr/bin/sage"


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> int | None:
    """Solve RSA common modulus attack when two ciphertexts are encrypted under same N."""
    def egcd(a: int, b: int) -> tuple[int, int, int]:
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        return None

    # m = (c1^s1 * c2^s2) % n
    if s1 < 0:
        s1 = -s1
        c1 = pow(c1, -1, n)
    if s2 < 0:
        s2 = -s2
        c2 = pow(c2, -1, n)

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m


def solve_stereotyped_coppersmith(n: int, e: int, c: int, prefix: bytes = b"flag{", suffix_len: int = 16) -> str:
    """Use SageMath and Coppersmith method to find unknown suffix of stereotyped message."""
    sage_bin = resolve_sage()
    if not os.path.exists(sage_bin):
        return ""

    sage_script = f"""
import sys

n = {n}
e = {e}
c = {c}
prefix = {int.from_bytes(prefix, 'big')}
suffix_len = {suffix_len}

# m = prefix * 2^(8*suffix_len) + x
base_val = prefix * (2^(8 * suffix_len))
P.<x> = PolynomialRing(Zmod(n))
f = (base_val + x)^e - c
f = f.monic()

# Bounds for unknown suffix
X = 2^(8 * suffix_len)
roots = f.small_roots(X=X, beta=1.0)
if roots:
    root = int(roots[0])
    m_int = base_val + root
    try:
        m_bytes = int(m_int).to_bytes((int(m_int).bit_length() + 7) // 8, 'big')
        print("SAGE_FLAG:" + m_bytes.decode('latin-1', 'replace'))
    except Exception as ex:
        print("SAGE_ERROR:" + str(ex))
else:
    print("SAGE_NO_ROOTS")
"""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".sage", delete=False) as tf:
            tf.write(sage_script)
            tf_path = tf.name

        try:
            p = subprocess.run([sage_bin, tf_path], capture_output=True, text=True, timeout=60)
            if "SAGE_FLAG:" in p.stdout:
                return p.stdout.split("SAGE_FLAG:")[-1].strip()
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)
    except Exception:
        pass

    return ""


def solve_hastad_broadcast(moduli: list[int], ciphertexts: list[int], e: int) -> int | None:
    """Solve Hastad's Broadcast Attack using Chinese Remainder Theorem."""
    if len(moduli) < e or len(ciphertexts) < e:
        return None

    def chinese_remainder_theorem(n_list: list[int], a_list: list[int]) -> int:
        from functools import reduce
        total_prod = reduce(lambda x, y: x * y, n_list)
        total = 0
        for n_i, a_i in zip(n_list, a_list):
            p = total_prod // n_i
            total += a_i * pow(p, -1, n_i) * p
        return total % total_prod

    try:
        c_crt = chinese_remainder_theorem(moduli[:e], ciphertexts[:e])
        # Integer e-th root
        low = 0
        high = c_crt
        while low < high:
            mid = (low + high) // 2
            if mid ** e < c_crt:
                low = mid + 1
            else:
                high = mid
        if low ** e == c_crt:
            return low
    except Exception:
        pass
    return None


def parse_and_attack(text: str) -> dict[str, Any]:
    """Parse RSA parameters from challenge briefing / file and execute advanced lattice attacks."""
    flags: list[dict[str, Any]] = []
    notes: list[str] = []

    # 1. Parse common modulus pattern: c1, c2, e1, e2, N
    n_match = re.search(r"\b(?:n|N)\s*[:=]\s*([0-9]+|0x[0-9a-fA-F]+)", text)
    e_matches = re.findall(r"\b(?:e|e1|e2)\s*[:=]\s*([0-9]+)", text)
    c_matches = re.findall(r"\b(?:c|c1|c2)\s*[:=]\s*([0-9]+|0x[0-9a-fA-F]+)", text)

    if n_match and len(e_matches) >= 2 and len(c_matches) >= 2:
        try:
            n_val = int(n_match.group(1), 0)
            e1_val = int(e_matches[0], 0)
            e2_val = int(e_matches[1], 0)
            c1_val = int(c_matches[0], 0)
            c2_val = int(c_matches[1], 0)
            m_res = common_modulus_attack(n_val, e1_val, e2_val, c1_val, c2_val)
            if m_res:
                m_bytes = m_res.to_bytes((m_res.bit_length() + 7) // 8, "big")
                m_str = m_bytes.decode("latin-1", "replace")
                notes.append(f"Common Modulus Attack succeeded: {m_str[:100]}")
                fl = scan_text(m_str)
                if fl:
                    flags.extend(fl)
                else:
                    flags.append({"flag": m_str.strip(), "confidence": 85, "kind": "common_modulus"})
        except Exception as ex:
            notes.append(f"Common modulus attack error: {ex}")

    # 2. Parse stereotyped Coppersmith attack: e=3, single c, N, known prefix
    if n_match and len(e_matches) >= 1 and len(c_matches) >= 1:
        try:
            n_val = int(n_match.group(1), 0)
            e_val = int(e_matches[0], 0)
            c_val = int(c_matches[0], 0)
            if e_val in (3, 5):
                # Try Coppersmith small roots via SageMath
                sage_recovered = solve_stereotyped_coppersmith(n_val, e_val, c_val, prefix=b"flag{", suffix_len=16)
                if sage_recovered:
                    notes.append(f"SageMath Coppersmith recovered: {sage_recovered}")
                    fl = scan_text(sage_recovered)
                    flags.extend(fl if fl else [{"flag": sage_recovered, "confidence": 95, "kind": "coppersmith"}])
        except Exception:
            pass

    return {
        "step": "sage-crypto",
        "summary": f"SageMath lattice & hard RSA attacks ({len(flags)} candidate(s))",
        "output": "\n".join(notes) if notes else "No matching multi-cipher or stereotyped RSA patterns identified.",
        "flags": flags,
    }
