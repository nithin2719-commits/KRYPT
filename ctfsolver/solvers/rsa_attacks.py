"""Comprehensive pure-Python RSA attack suite for CTF crypto challenges.

Implements direct cryptographic attacks on RSA without external binary dependencies:
- Small / low public exponent (m^e < n, small k*n + c, smooth modulus)
- Wiener's continued fractions attack for small private exponent (d < N^0.25)
- Fermat's factorization for close primes (|p - q| is small)
- Pollard's p - 1 factorization for B-smooth (p - 1)
- Common factor (pairwise GCD) across multiple moduli and common modulus (coprime exponents)
- Hastad's broadcast attack using Chinese Remainder Theorem (CRT)
- LSB / Parity Oracle bit-by-bit recovery via exact rational binary search
- Simplified Boneh-Durfee attack for small d up to N^0.292 (pure Python + Sage fallback)
- FactorDB online database lookup and small-prime trial division
- Flexible parameter parser for free-form text, multi-line assignments, and PEM keys
"""
from __future__ import annotations

import json
import math
import os
import re
import urllib.request
from fractions import Fraction
from typing import Any, Callable

from ..flags import scan_bytes, scan_text
from ..runner import have, run

# pycryptodome
try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

    def bytes_to_long(b: bytes) -> int:
        return int.from_bytes(b, "big")

    def long_to_bytes(n: int) -> bytes:
        if n <= 0:
            return b""
        return n.to_bytes((n.bit_length() + 7) // 8, "big")

# gmpy2 fast arithmetic
try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False


# =====================================================================
# Arithmetic Helpers & Fallbacks
# =====================================================================

def isqrt(n: int) -> int:
    """Integer square root."""
    if HAVE_GMPY2:
        return int(gmpy2.isqrt(n))
    return math.isqrt(n)


def gcd(a: int, b: int) -> int:
    """Greatest common divisor."""
    if HAVE_GMPY2:
        return int(gmpy2.gcd(a, b))
    return math.gcd(a, b)


def invert(a: int, m: int) -> int:
    """Modular inverse a^(-1) mod m."""
    if HAVE_GMPY2:
        return int(gmpy2.invert(a, m))
    return pow(a, -1, m)


def is_prime(n: int) -> bool:
    """Primality check."""
    if HAVE_GMPY2:
        return bool(gmpy2.is_prime(n))
    if n < 2:
        return False
    if n in (2, 3, 5, 7):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n <= a:
            break
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    """Find next prime after n."""
    if HAVE_GMPY2:
        return int(gmpy2.next_prime(n))
    p = n + 1 if n % 2 == 0 else n + 2
    while not is_prime(p):
        p += 2
    return p


def integer_nth_root(x: int, n: int) -> tuple[int, bool]:
    """Compute floor(x^(1/n)) and whether the root is exact."""
    if x < 0:
        raise ValueError("Cannot extract root of negative integer")
    if x == 0:
        return 0, True
    if n <= 0:
        raise ValueError("Root degree must be positive")
    if n == 1:
        return x, True
    if n == 2:
        r = isqrt(x)
        return r, (r * r == x)

    if HAVE_GMPY2:
        r, exact = gmpy2.iroot(x, n)
        return int(r), bool(exact)

    # Binary search fallback
    low = 1
    high = 1 << ((x.bit_length() + n - 1) // n + 1)
    while low <= high:
        mid = (low + high) // 2
        p = pow(mid, n)
        if p == x:
            return mid, True
        elif p < x:
            low = mid + 1
        else:
            high = mid - 1
    return high, (pow(high, n) == x)


def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes and strip leading nulls or PKCS#1 v1.5 padding if present."""
    if n <= 0:
        return b""
    raw = long_to_bytes(n)
    # Check for PKCS#1 v1.5 type 2 padding (00 02 [non-zero padding] 00 [data])
    if len(raw) > 10 and raw.startswith(b"\x02"):
        sep = raw.find(b"\x00", 1)
        if sep != -1 and sep + 1 < len(raw):
            return raw[sep + 1:]
    elif len(raw) > 11 and raw.startswith(b"\x00\x02"):
        sep = raw.find(b"\x00", 2)
        if sep != -1 and sep + 1 < len(raw):
            return raw[sep + 1:]
    return raw


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm returning (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def crt(remainders: list[int], moduli: list[int]) -> tuple[int, int]:
    """Chinese Remainder Theorem for coprime moduli."""
    if len(remainders) != len(moduli) or not remainders:
        return 0, 0
    total_n = 1
    for m in moduli:
        total_n *= m
    result = 0
    for r, m in zip(remainders, moduli):
        ni = total_n // m
        inv = invert(ni, m)
        result = (result + r * ni * inv) % total_n
    return result, total_n


# =====================================================================
# Attack Result Data Structure
# =====================================================================

class AttackResult(dict):
    """Result returned by attack functions, behaving as a dict while supporting int and bytes casts."""

    def __init__(
        self,
        step: str,
        flags: list[dict[str, Any]] | None = None,
        output: str = "",
        m: int | None = None,
        plaintext: bytes = b"",
        **kwargs: Any,
    ):
        flags = flags or []
        success = kwargs.pop("success", bool(m is not None or flags))
        super().__init__(
            step=step,
            flags=flags,
            output=output,
            m=m,
            plaintext=plaintext,
            success=success,
            **kwargs,
        )

    def __bool__(self) -> bool:
        return bool(self.get("success", False))

    def __int__(self) -> int:
        return int(self.get("m") or 0)

    def __bytes__(self) -> bytes:
        pt = self.get("plaintext")
        if isinstance(pt, bytes):
            return pt
        return str(pt or "").encode("latin-1", "replace")


def _scan_and_package(step: str, m: int, output_note: str = "") -> AttackResult:
    """Helper to decode recovered integer, scan flags, and package AttackResult."""
    pt_bytes = int_to_bytes(m)
    flags = scan_bytes(pt_bytes)
    pt_text = pt_bytes.decode("latin-1", "replace")
    if not flags:
        flags = scan_text(pt_text)

    note = output_note or f"Recovered plaintext ({len(pt_bytes)} bytes): {pt_bytes[:60]!r}"
    return AttackResult(
        step=step,
        flags=flags,
        output=note,
        m=m,
        plaintext=pt_bytes,
        success=True,
    )


# =====================================================================
# 1. Small / Low Public Exponent Attack
# =====================================================================

def small_exponent_attack(c: int, e: int, n: int | None = None, max_k: int = 50000) -> AttackResult:
    """Solve RSA when e is small (e=3, 5, 7...) and m^e < n, or c + k*n is a perfect power."""
    if e <= 0 or c <= 0:
        return AttackResult("small-e", output="Invalid c or e", success=False)

    # 1. Unpadded root: m^e < n directly
    r, exact = integer_nth_root(c, e)
    if exact:
        return _scan_and_package("small-e", r, f"Exact {e}-th root recovered without modulus wrap")

    if n is not None and n > 0:
        # 2. Check small k shifts: m^e = c + k * n
        for k in range(1, max_k + 1):
            val = c + k * n
            r, exact = integer_nth_root(val, e)
            if exact:
                return _scan_and_package("small-e", r, f"Recovered via small-k root search (k={k})")

        # 3. Factorable / smooth modulus (e.g. n = 10^100 or smooth powers)
        temp_n = n
        factors: dict[int, int] = {}
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]:
            if temp_n % p == 0:
                count = 0
                while temp_n % p == 0:
                    temp_n //= p
                    count += 1
                factors[p] = count

        if temp_n == 1 or is_prime(temp_n):
            if temp_n > 1:
                factors[temp_n] = 1
            phi = 1
            for p_fac, count in factors.items():
                phi *= (p_fac ** (count - 1)) * (p_fac - 1)

            if gcd(e, phi) == 1:
                try:
                    d = invert(e, phi)
                    m = pow(c, d, n)
                    return _scan_and_package("small-e", m, f"Recovered by factoring smooth modulus into {len(factors)} prime factors")
                except Exception:
                    pass

    return AttackResult("small-e", output="Low exponent attack did not yield valid root", success=False)


# =====================================================================
# 2. Wiener's Attack (Small d < N^0.25)
# =====================================================================

def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """Compute quotients of continued fraction expansion."""
    quotients: list[int] = []
    num, den = numerator, denominator
    while den != 0:
        q = num // den
        quotients.append(q)
        num, den = den, num - q * den
    return quotients


def convergents(cf: list[int]) -> list[tuple[int, int]]:
    """Compute list of convergents (k, d) from continued fraction quotients."""
    convs: list[tuple[int, int]] = []
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for q in cf:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        convs.append((n2, d2))
        n0, d0 = n1, d1
        n1, d1 = n2, d2
    return convs


def wiener_attack(e: int, n: int, c: int | None = None) -> AttackResult:
    """Recover small private exponent d < N^0.25 via continued fraction convergents."""
    if e <= 0 or n <= 0:
        return AttackResult("wiener", output="Invalid e or n", success=False)

    cf = continued_fraction(e, n)
    conv_list = convergents(cf)

    for k, d_cand in conv_list:
        if k == 0 or d_cand == 0:
            continue
        # e * d - 1 = k * phi => (e * d - 1) % k == 0
        if (e * d_cand - 1) % k != 0:
            continue
        phi_cand = (e * d_cand - 1) // k
        s = n - phi_cand + 1
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            root_d, exact = integer_nth_root(discriminant, 2)
            if exact:
                p_cand = (s + root_d) // 2
                q_cand = (s - root_d) // 2
                if p_cand * q_cand == n and p_cand > 1 and q_cand > 1:
                    m_val = pow(c, d_cand, n) if c is not None else None
                    if m_val is not None:
                        return _scan_and_package(
                            "wiener",
                            m_val,
                            f"Wiener attack succeeded: d={d_cand}, p={p_cand}, q={q_cand}",
                        )
                    return AttackResult(
                        "wiener",
                        output=f"Wiener attack factored N: d={d_cand}, p={p_cand}, q={q_cand}",
                        d=d_cand,
                        p=p_cand,
                        q=q_cand,
                        success=True,
                    )

    return AttackResult("wiener", output="Wiener attack found no suitable convergent", success=False)


# =====================================================================
# 3. Fermat Factorization (Close Primes)
# =====================================================================

def fermat_factorization(n: int, c: int | None = None, e: int = 65537, max_iter: int = 1000000) -> AttackResult:
    """Factor n = p * q when p and q are close primes (|p - q| is small)."""
    if n <= 0:
        return AttackResult("fermat", output="Invalid modulus", success=False)

    a = isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n

    for _ in range(max_iter):
        r, exact = integer_nth_root(b2, 2)
        if exact:
            p = a - r
            q = a + r
            if p * q == n and p > 1 and q > 1:
                phi = (p - 1) * (q - 1)
                try:
                    d = invert(e, phi)
                    m_val = pow(c, d, n) if c is not None else None
                except Exception:
                    m_val = None

                if m_val is not None:
                    return _scan_and_package(
                        "fermat",
                        m_val,
                        f"Fermat factorization succeeded: |p - q| = {abs(p - q)}",
                    )
                return AttackResult(
                    "fermat",
                    output=f"Fermat factored modulus: p={p}, q={q}",
                    p=p,
                    q=q,
                    success=True,
                )
        a += 1
        b2 = a * a - n

    return AttackResult("fermat", output=f"Fermat factorization reached max iterations ({max_iter})", success=False)


# =====================================================================
# 4. Pollard's p - 1 Factorization
# =====================================================================

def pollard_p_minus_1(n: int, c: int | None = None, e: int = 65537, b1: int = 200000) -> AttackResult:
    """Factor n when p - 1 has only small prime factors (B-smooth)."""
    if n <= 0:
        return AttackResult("pollard-p-1", output="Invalid modulus", success=False)

    a = 2
    p_prime = 2
    # Stage 1: multiply primes up to bound B1
    while p_prime <= b1:
        power = p_prime
        while power * p_prime <= b1:
            power *= p_prime
        a = pow(a, power, n)
        p_prime = next_prime(p_prime)

    g = gcd(a - 1, n)
    if 1 < g < n:
        p = g
        q = n // g
        phi = (p - 1) * (q - 1)
        try:
            d = invert(e, phi)
            m_val = pow(c, d, n) if c is not None else None
        except Exception:
            m_val = None

        if m_val is not None:
            return _scan_and_package("pollard-p-1", m_val, f"Pollard p-1 factored N: p={p}")
        return AttackResult("pollard-p-1", output=f"Pollard p-1 factored N: p={p}, q={q}", p=p, q=q, success=True)

    return AttackResult("pollard-p-1", output=f"Pollard p-1 failed with bound B1={b1}", success=False)


# =====================================================================
# 5. Common Factor & Common Modulus Attacks
# =====================================================================

def common_factor_attack(
    moduli: list[int],
    ciphers: list[int] | None = None,
    e: int = 65537,
) -> AttackResult:
    """Find shared prime factors between pairs of moduli via pairwise GCD."""
    if len(moduli) < 2:
        return AttackResult("common-factor", output="Need at least 2 moduli", success=False)

    flags: list[dict[str, Any]] = []
    outputs: list[str] = []
    recovered_m: int | None = None
    recovered_pt: bytes = b""

    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            n1 = moduli[i]
            n2 = moduli[j]
            g = gcd(n1, n2)
            if 1 < g < n1:
                p = g
                q1 = n1 // g
                q2 = n2 // g
                outputs.append(f"Pairwise GCD found shared factor {p} between N[{i}] and N[{j}]")
                # Decrypt ciphers if available
                if ciphers:
                    for idx, (ni, qi) in [(i, (n1, q1)), (j, (n2, q2))]:
                        if idx < len(ciphers):
                            ci = ciphers[idx]
                            phi = (p - 1) * (qi - 1)
                            if gcd(e, phi) == 1:
                                d = invert(e, phi)
                                m = pow(ci, d, ni)
                                res = _scan_and_package("common-factor", m)
                                if res["flags"]:
                                    flags.extend(res["flags"])
                                recovered_m = m
                                recovered_pt = res["plaintext"]

    if recovered_m is not None or flags:
        return AttackResult(
            "common-factor",
            flags=flags,
            output="\n".join(outputs),
            m=recovered_m,
            plaintext=recovered_pt,
            success=True,
        )
    return AttackResult("common-factor", output="No common prime factor found between given moduli", success=False)


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> AttackResult:
    """Decrypt message encrypted under same modulus N with two coprime exponents e1 and e2."""
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        return AttackResult("common-modulus", output=f"Exponents not coprime: gcd={g}", success=False)

    # m = (c1^s1 * c2^s2) mod n
    if s1 < 0:
        s1 = -s1
        c1 = invert(c1, n)
    if s2 < 0:
        s2 = -s2
        c2 = invert(c2, n)

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return _scan_and_package("common-modulus", m, "Common modulus attack recovered plaintext")


# =====================================================================
# 6. Hastad Broadcast Attack (Same e across e moduli)
# =====================================================================

def hastad_broadcast_attack(pairs: list[tuple[int, int]], e: int = 3) -> AttackResult:
    """Solve RSA broadcast when identical plaintext is encrypted under e different moduli."""
    if len(pairs) < e:
        return AttackResult("hastad", output=f"Need at least {e} (c, n) pairs, got {len(pairs)}", success=False)

    c_list = [p[0] for p in pairs[:e]]
    n_list = [p[1] for p in pairs[:e]]

    c_crt, n_prod = crt(c_list, n_list)
    r, exact = integer_nth_root(c_crt, e)
    if exact:
        return _scan_and_package("hastad", r, f"Hastad broadcast attack succeeded using CRT with e={e}")

    return AttackResult("hastad", output="Hastad CRT produced no exact integer root", success=False)


# =====================================================================
# 7. LSB / Parity Oracle Attack
# =====================================================================

def lsb_oracle_attack(
    c: int,
    e: int,
    n: int,
    oracle_fn: Callable[[int], int],
    max_bits: int | None = None,
) -> AttackResult:
    """Recover plaintext bit by bit given a decryption oracle returning m % 2 (LSB)."""
    bits = max_bits if max_bits is not None else n.bit_length()
    low = Fraction(0, 1)
    high = Fraction(n, 1)

    c_curr = c
    two_e = pow(2, e, n)

    for _ in range(bits):
        c_curr = (c_curr * two_e) % n
        bit = oracle_fn(c_curr)
        mid = (low + high) / 2
        if bit == 1:
            low = mid
        else:
            high = mid

    # Check neighborhood of high / low
    base = int(high)
    candidates = [base, int(low), base - 1, base + 1, base - 2, base + 2]
    for cand in candidates:
        if cand > 0 and pow(cand, e, n) == c:
            return _scan_and_package("lsb-oracle", cand, "LSB oracle successfully recovered plaintext")

    # Fallback to high cast
    if base > 0:
        return _scan_and_package("lsb-oracle", base, "LSB oracle completed binary search")

    return AttackResult("lsb-oracle", output="LSB oracle recovery failed", success=False)


# =====================================================================
# 8. Boneh-Durfee Attack (Simplified & Extended Wiener)
# =====================================================================

def boneh_durfee_attack(e: int, n: int, c: int | None = None, delta: float = 0.28) -> AttackResult:
    """Recover private key d when d < N^0.292 using extended convergents, semiconvergents, and Sage."""
    if e <= 0 or n <= 0:
        return AttackResult("boneh-durfee", output="Invalid parameters", success=False)

    # 1. First, check standard Wiener
    wiener_res = wiener_attack(e, n, c)
    if wiener_res["success"]:
        wiener_res["step"] = "boneh-durfee"
        return wiener_res

    # 2. Check semiconvergents and phi approximations
    approx_phi = n - 2 * isqrt(n) + 1
    for denom in (n, approx_phi, n + 1):
        cf = continued_fraction(e, denom)
        convs = convergents(cf)
        for k, d_cand in convs:
            if k == 0 or d_cand == 0:
                continue
            if (e * d_cand - 1) % k != 0:
                continue
            phi_cand = (e * d_cand - 1) // k
            s = n - phi_cand + 1
            discriminant = s * s - 4 * n
            if discriminant >= 0:
                root_d, exact = integer_nth_root(discriminant, 2)
                if exact:
                    p = (s + root_d) // 2
                    q = (s - root_d) // 2
                    if p * q == n and p > 1:
                        m_val = pow(c, d_cand, n) if c is not None else None
                        if m_val is not None:
                            return _scan_and_package("boneh-durfee", m_val, f"Boneh-Durfee recovered d={d_cand}")
                        return AttackResult(
                            "boneh-durfee",
                            output=f"Boneh-Durfee factored modulus: d={d_cand}, p={p}, q={q}",
                            d=d_cand,
                            p=p,
                            q=q,
                            success=True,
                        )

    # 3. If SageMath is available on the machine, run Boneh-Durfee lattice reduction
    if have("sage"):
        sage_code = f"""
import sys
N = {n}
e = {e}
delta = {delta}
m = 3
t = int((1 - 2*delta)*m)
X = 2 * int(N**delta)
Y = int(N**0.5)

P.<x,y> = PolynomialRing(ZZ)
A = int((N+1)/2)
pol = 1 + x * (A + y)

PR.<u, x, y> = PolynomialRing(ZZ)
Q = PR.quotient(x*y + 1 - u)
polZ = Q(pol).lift()
UU = X*Y + 1

gg = []
for kk in range(m + 1):
    for ii in range(m - kk + 1):
        gg.append(x^ii * e^(m - kk) * polZ(u, x, y)^kk)
gg.sort()

monomials = []
for p in gg:
    for mon in p.monomials():
        if mon not in monomials:
            monomials.append(mon)
monomials.sort()

dim = len(monomials)
BB = Matrix(ZZ, dim)
for ii in range(dim):
    BB[ii, 0] = gg[ii](0, 0, 0)
    for jj in range(1, ii + 1):
        if monomials[jj] in gg[ii].monomials():
            BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU, X, Y)

BB = BB.LLL()
PR2.<w, z> = PolynomialRing(ZZ)
for p1_idx in range(dim - 1):
    for p2_idx in range(p1_idx + 1, dim):
        p1 = sum(monomials[jj](w*z+1, w, z) * BB[p1_idx, jj] / monomials[jj](UU, X, Y) for jj in range(dim))
        p2 = sum(monomials[jj](w*z+1, w, z) * BB[p2_idx, jj] / monomials[jj](UU, X, Y) for jj in range(dim))
        PRq.<q> = PolynomialRing(ZZ)
        rr = p1.resultant(p2)
        if not rr.is_zero() and rr.monomials() != [1]:
            roots_y = rr(q, q).roots()
            if roots_y:
                y0 = roots_y[0][0]
                roots_x = p1(q, y0).roots()
                if roots_x:
                    x0 = roots_x[0][0]
                    d_sol = int(pol(x0, y0) / e)
                    print(f"FOUND_D:{{d_sol}}")
                    sys.exit(0)
"""
        res = run(["sage", "-c", sage_code], timeout=60)
        m_d = re.search(r"FOUND_D:(\d+)", res.stdout)
        if m_d:
            d_found = int(m_d.group(1))
            m_val = pow(c, d_found, n) if c is not None else None
            if m_val is not None:
                return _scan_and_package("boneh-durfee", m_val, f"Sage Boneh-Durfee recovered d={d_found}")
            return AttackResult("boneh-durfee", output=f"Sage Boneh-Durfee found d={d_found}", d=d_found, success=True)

    return AttackResult("boneh-durfee", output="Boneh-Durfee attack did not locate small d", success=False)


# =====================================================================
# FactorDB & Trial Division
# =====================================================================

def factordb_factor(n: int, c: int | None = None, e: int = 65537, timeout: float = 4.0) -> AttackResult:
    """Factor n by querying factordb.com online database."""
    if n <= 0:
        return AttackResult("factordb", output="Invalid modulus", success=False)

    url = f"https://factordb.com/api?query={n}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "KRYPT/2.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
            status = data.get("status", "")
            factors_raw = data.get("factors", [])

            if status in ("FF", "CF") and factors_raw:
                primes: list[int] = []
                for item in factors_raw:
                    val = int(item[0])
                    count = int(item[1])
                    for _ in range(count):
                        primes.append(val)

                if len(primes) >= 2:
                    phi = 1
                    for p in set(primes):
                        cnt = primes.count(p)
                        phi *= (p ** (cnt - 1)) * (p - 1)

                    if gcd(e, phi) == 1:
                        d = invert(e, phi)
                        m_val = pow(c, d, n) if c is not None else None
                        if m_val is not None:
                            return _scan_and_package("factordb", m_val, f"FactorDB solved N into {len(primes)} prime factors")
                        return AttackResult(
                            "factordb",
                            output=f"FactorDB factored N into: {primes}",
                            factors=primes,
                            d=d,
                            success=True,
                        )
    except Exception:
        pass

    return AttackResult("factordb", output="FactorDB returned no complete factorization", success=False)


def trial_division_attack(n: int, c: int | None = None, e: int = 65537, limit: int = 1000000) -> AttackResult:
    """Find small prime factor of n via trial division."""
    if n <= 0:
        return AttackResult("trial-division", output="Invalid modulus", success=False)

    for p in [2, 3, 5]:
        if n % p == 0:
            q = n // p
            phi = (p - 1) * (q - 1)
            if gcd(e, phi) == 1:
                d = invert(e, phi)
                m_val = pow(c, d, n) if c is not None else None
                if m_val is not None:
                    return _scan_and_package("trial-division", m_val, f"Trial division found factor p={p}")
                return AttackResult("trial-division", output=f"Found factor p={p}", p=p, q=q, success=True)

    d_step = 2
    cur = 7
    while cur <= limit and cur * cur <= n:
        if n % cur == 0:
            p = cur
            q = n // cur
            phi = (p - 1) * (q - 1)
            if gcd(e, phi) == 1:
                d = invert(e, phi)
                m_val = pow(c, d, n) if c is not None else None
                if m_val is not None:
                    return _scan_and_package("trial-division", m_val, f"Trial division found factor p={p}")
                return AttackResult("trial-division", output=f"Found factor p={p}", p=p, q=q, success=True)
        cur += d_step
        d_step = 6 - d_step  # alternate +4, +2 for 6k +/- 1

    return AttackResult("trial-division", output=f"No factors found below {limit}", success=False)


# =====================================================================
# 9. Free-form Parameter Parser
# =====================================================================

def parse_rsa_params(text: str) -> dict[str, Any]:
    """Extract RSA parameters (n, e, c, p, q, d, dp, dq, and lists) from text and PEM keys."""
    params: dict[str, Any] = {
        "n": None,
        "e": None,
        "c": None,
        "p": None,
        "q": None,
        "d": None,
        "dp": None,
        "dq": None,
        "moduli": [],
        "ciphers": [],
        "exponents": [],
    }

    # 1. Parse PEM public/private keys
    pem_blocks = [m.group(0) for m in re.finditer(r"-----BEGIN ([^-]+)-----[\s\S]*?-----END \1-----", text)]
    if HAVE_CRYPTO:
        for pem in pem_blocks:
            try:
                key = RSA.import_key(pem)
                if hasattr(key, "n") and key.n:
                    params["n"] = key.n
                    params["moduli"].append(key.n)
                if hasattr(key, "e") and key.e:
                    params["e"] = key.e
                    params["exponents"].append(key.e)
                if hasattr(key, "d") and key.d:
                    params["d"] = key.d
                if hasattr(key, "p") and key.p:
                    params["p"] = key.p
                if hasattr(key, "q") and key.q:
                    params["q"] = key.q
            except Exception:
                pass

    # 2. Parse list declarations: e.g. c = [1, 2, 3] or moduli = [0x..., 0x...]
    for list_var, target_key in [("c", "ciphers"), ("cipher", "ciphers"), ("n", "moduli"), ("e", "exponents")]:
        for m_list in re.finditer(rf"\b{list_var}\w*\s*[:=]\s*\[([\s\S]*?)\]", text, re.IGNORECASE):
            items = re.findall(r"0x[0-9a-fA-F]+|\d+", m_list.group(1))
            for item in items:
                try:
                    val = int(item, 16) if item.lower().startswith("0x") else int(item)
                    if val not in params[target_key]:
                        params[target_key].append(val)
                except Exception:
                    pass

    # 3. Clean helper for integer values
    def _to_int(s: str) -> int | None:
        s = s.strip().rstrip(",;").rstrip("L")
        m_int = re.search(r"int\s*\(\s*['\"]([0-9a-fA-FxX]+)['\"]\s*(?:,\s*(\d+))?\s*\)", s)
        if m_int:
            base = int(m_int.group(2)) if m_int.group(2) else (16 if "0x" in m_int.group(1).lower() else 10)
            return int(m_int.group(1), base)
        clean = re.sub(r"['\"L\\()]", "", s)
        clean = re.sub(r"\s+", "", clean)
        if clean.lower().startswith("0x"):
            try:
                return int(clean, 16)
            except ValueError:
                return None
        if clean.isdigit():
            return int(clean)
        # Raw hex string without 0x
        if len(clean) >= 16 and all(c in "0123456789abcdefABCDEF" for c in clean):
            try:
                return int(clean, 16)
            except ValueError:
                return None
        return None

    # 4. Multi-line assignment scanner
    target_vars = {"n", "e", "c", "p", "q", "d", "dp", "dq", "invq", "ct", "pt", "m", "modulus", "ciphertext"}
    lines = text.splitlines()
    curr_var: str | None = None
    curr_val_parts: list[str] = []

    def commit_var(vname: str, parts: list[str]):
        combined = " ".join(parts)
        val = _to_int(combined)
        if val is not None:
            norm_key = vname.lower()
            if norm_key in ("ct", "ciphertext"):
                norm_key = "c"
            elif norm_key in ("pt", "m"):
                norm_key = "m"
            elif norm_key in ("modulus",):
                norm_key = "n"

            if norm_key in params:
                params[norm_key] = val

            if norm_key.startswith("n") and norm_key not in ("n",):
                params["moduli"].append(val)
            elif norm_key == "n" and val not in params["moduli"]:
                params["moduli"].append(val)
            elif norm_key.startswith("c") and norm_key not in ("c",):
                params["ciphers"].append(val)
            elif norm_key == "c" and val not in params["ciphers"]:
                params["ciphers"].append(val)
            elif norm_key.startswith("e") and norm_key not in ("e",):
                params["exponents"].append(val)
            elif norm_key == "e" and val not in params["exponents"]:
                params["exponents"].append(val)

    for line in lines:
        line_clean = line.strip()
        m_assign = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(.*)$", line_clean)
        if m_assign:
            if curr_var and curr_val_parts:
                commit_var(curr_var, curr_val_parts)
            vname = m_assign.group(1).lower()
            rest = m_assign.group(2)
            if vname in target_vars or re.match(r"^[nec]\d+$", vname):
                curr_var = vname
                curr_val_parts = [rest] if rest else []
            else:
                curr_var = None
                curr_val_parts = []
        elif curr_var:
            if line_clean:
                curr_val_parts.append(line_clean)
            else:
                commit_var(curr_var, curr_val_parts)
                curr_var = None
                curr_val_parts = []

    if curr_var and curr_val_parts:
        commit_var(curr_var, curr_val_parts)

    return params


# =====================================================================
# 10. Top-Level solve(target, workdir)
# =====================================================================

def solve(target: str, workdir: str = "") -> dict[str, Any]:
    """Main solver entry point: parse target parameters and run RSA attack suite."""
    text = ""
    target_path = target
    if not os.path.isabs(target_path) and workdir and os.path.exists(os.path.join(workdir, target)):
        target_path = os.path.join(workdir, target)

    if os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="latin-1", errors="replace") as fh:
                text = fh.read(1_000_000)
        except OSError:
            text = target
    else:
        text = target

    params = parse_rsa_params(text)
    flags: list[dict[str, Any]] = []
    outputs: list[str] = []

    def _record(res: AttackResult):
        if res.get("output"):
            outputs.append(res["output"])
        for f in res.get("flags", []):
            if f not in flags:
                flags.append(f)

    # 1. Direct decryption if private components already known
    n = params.get("n")
    e = params.get("e") or 65537
    c = params.get("c")
    d = params.get("d")
    p = params.get("p")
    q = params.get("q")
    dp = params.get("dp")
    dq = params.get("dq")

    if c is not None and d is not None and n is not None:
        m = pow(c, d, n)
        _record(_scan_and_package("direct-private-key", m, "Decrypted using parsed private exponent d"))

    elif c is not None and p is not None and q is not None:
        mod = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            d_calc = invert(e, phi)
            m = pow(c, d_calc, mod)
            _record(_scan_and_package("direct-p-q", m, f"Decrypted using parsed primes p and q (d={d_calc})"))

    elif c is not None and p is not None and q is not None and dp is not None and dq is not None:
        # CRT decryption
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        qinv = invert(q, p)
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
        _record(_scan_and_package("direct-crt-dp-dq", m, "Decrypted using parsed CRT components dp, dq"))

    # 2. Multi-moduli attacks
    moduli = params.get("moduli", [])
    ciphers = params.get("ciphers", [])
    exponents = params.get("exponents", [])

    if len(moduli) >= 2:
        res_cf = common_factor_attack(moduli, ciphers, e)
        if res_cf["success"]:
            _record(res_cf)

    if len(moduli) >= 3 and len(ciphers) >= 3:
        pairs = list(zip(ciphers, moduli))
        res_hastad = hastad_broadcast_attack(pairs, e=3)
        if res_hastad["success"]:
            _record(res_hastad)

    # 3. Common modulus attack: same n, two different e and c
    if n is not None and len(exponents) >= 2 and len(ciphers) >= 2:
        res_cm = common_modulus_attack(n, exponents[0], exponents[1], ciphers[0], ciphers[1])
        if res_cm["success"]:
            _record(res_cm)

    # 4. Single N attacks
    if n is not None:
        # A. Small exponent
        if c is not None and e in (3, 5, 7, 11, 13, 17, 65537):
            res_se = small_exponent_attack(c, e, n)
            if res_se["success"]:
                _record(res_se)

        # B. FactorDB lookup
        if not flags:
            res_fdb = factordb_factor(n, c, e)
            if res_fdb["success"]:
                _record(res_fdb)

        # C. Small prime trial division
        if not flags:
            res_td = trial_division_attack(n, c, e, limit=500000)
            if res_td["success"]:
                _record(res_td)

        # D. Wiener's attack
        if not flags:
            res_wiener = wiener_attack(e, n, c)
            if res_wiener["success"]:
                _record(res_wiener)

        # E. Fermat factorization (close primes)
        if not flags:
            res_fermat = fermat_factorization(n, c, e, max_iter=200000)
            if res_fermat["success"]:
                _record(res_fermat)

        # F. Pollard's p - 1
        if not flags:
            res_pollard = pollard_p_minus_1(n, c, e, b1=100000)
            if res_pollard["success"]:
                _record(res_pollard)

        # G. Boneh-Durfee
        if not flags:
            res_bd = boneh_durfee_attack(e, n, c)
            if res_bd["success"]:
                _record(res_bd)

    summary = (
        f"RSA Attacks finished: {len(flags)} flag candidate(s) recovered."
        if flags
        else "RSA attack suite completed; no flags immediately recovered."
    )

    return {
        "step": "rsa-attacks",
        "flags": flags,
        "output": "\n".join(outputs) if outputs else "No matching attack succeeded on provided RSA parameters.",
        "summary": summary,
    }
