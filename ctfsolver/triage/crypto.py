"""Triage for text/data blobs: encoding detection and quick decode attempts.

Handles the frequent CTF case where a challenge is a string that has been
base64/hex/rot-encoded one or more times, or a hash to identify.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import os
import re
import sys

from ..flags import scan_text
from ..runner import have, run

_SOLVERS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "solvers")

_B64 = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
_HEX = re.compile(rb"^[0-9a-fA-F\s]+$")


def _try_decodes(data: bytes) -> list[tuple[str, str]]:
    """Return (method, decoded-text) for decodings that yield printable text."""
    out: list[tuple[str, str]] = []
    s = data.strip()

    def printable(b: bytes) -> bool:
        if not b:
            return False
        good = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)
        return good / len(b) > 0.85

    if _B64.match(s) and len(s) >= 8:
        try:
            d = base64.b64decode(s + b"===", validate=False)
            if printable(d):
                out.append(("base64", d.decode("latin-1")))
        except (binascii.Error, ValueError):
            pass
    if _HEX.match(s) and len(s.replace(b" ", b"")) % 2 == 0:
        try:
            d = binascii.unhexlify(re.sub(rb"\s", b"", s))
            if printable(d):
                out.append(("hex", d.decode("latin-1")))
        except (binascii.Error, ValueError):
            pass
    # ROT13 / all rotations of ascii text
    try:
        txt = data.decode("ascii")
        out.append(("rot13", codecs.decode(txt, "rot_13")))
    except UnicodeDecodeError:
        pass
    return out


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read(1 << 20)
    except OSError as e:
        return [{"step": "read", "summary": f"error: {e}", "output": "",
                 "flags": []}]

    preview = data[:500].decode("latin-1", "replace")
    steps.append({"step": "preview", "summary": f"{len(data)} bytes",
                  "output": preview, "flags": scan_text(preview)})

    # Esolang: Brainfuck (incl. reversed / "turnedaround" variants)
    src = data.decode("latin-1", "replace")
    bf = sum(1 for c in src if c in "><+-.,[]")
    if bf >= 8 and bf / max(1, len(src.strip())) > 0.5:
        py = sys.executable or "python3"
        r = run([py, os.path.join(_SOLVERS, "brainfuck.py"), path], timeout=60)
        if r.found and ("FORWARD" in r.stdout or "REVERSED" in r.stdout):
            flags = scan_text(r.stdout)
            # if the event's flag format is known, wrap the decoded output
            fmt = os.environ.get("CTF_FLAG_FORMAT", "")
            prefix = re.split(r"\\?\{", fmt)[0].replace("\\", "") if "{" in fmt else ""
            for line in r.stdout.splitlines():
                for tag in ("FORWARD:", "REVERSED:"):
                    if line.startswith(tag):
                        val = line[len(tag):].strip()
                        if prefix and val and "{" not in val and 1 <= len(val) <= 120:
                            flags.append({"flag": f"{prefix}{{{val}}}",
                                          "kind": "custom", "confidence": 95})
            steps.append({"step": "brainfuck",
                          "summary": "executed Brainfuck (forward + reversed)",
                          "output": r.stdout[:2000], "flags": flags})

    # Magic engine: BFS across all decoders + single-byte XOR brute.
    from ..decoders import magic
    m = magic(data)
    if m["found"]:
        steps.append({"step": "magic-decode",
                      "summary": "flag via decode chain: " + " -> ".join(m["path"]),
                      "output": m["sample"], "flags": m["flags"]})
    else:
        # Fall back to the simple single-branch decode for visibility.
        layer, cur = 0, data
        while layer < 4:
            decs = _try_decodes(cur)
            if not decs:
                break
            method, text = decs[0]
            fl = scan_text(text)
            steps.append({"step": f"decode-L{layer + 1}({method})",
                          "summary": f"decoded {len(text)} chars",
                          "output": text[:1000], "flags": fl})
            if fl:
                break
            cur = text.encode("latin-1", "replace")
            layer += 1
        if m["path"]:
            steps.append({"step": "magic-decode",
                          "summary": "no flag; deepest chain tried: "
                                     + " -> ".join(m["path"]),
                          "output": "", "flags": []})

    # Hash identification + auto-crack when the blob is a single hash token.
    toks = data.strip().split()
    if len(toks) == 1:
        tok = toks[0].decode("latin-1", "replace")
        is_hash = bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|"
                                    r"[0-9a-fA-F]{64}", tok)) or tok.startswith("$")
        if have("hashid"):
            r = run(["hashid", "-m", tok], timeout=15)
            if r.ok():
                steps.append({"step": "hashid", "summary": "possible hash types",
                              "output": r.stdout[:1500], "flags": []})
        if is_hash:
            from ..crack import crack_hash
            steps.append(crack_hash(tok, workdir))

    # RSA auto-attack when the blob looks like RSA (n/e/c or a PEM public key)
    txt = data.decode("latin-1", "replace")
    if re.search(r"\bn\s*[:=]\s*[0-9]", txt) and re.search(r"\be\s*[:=]\s*[0-9]", txt) \
            or ("-----BEGIN" in txt and "KEY-----" in txt):
        py = sys.executable or "python3"
        r = run([py, os.path.join(_SOLVERS, "rsa_solve.py"), path], timeout=300)
        if r.found:
            body = r.stdout or r.stderr
            steps.append({"step": "rsa-attack",
                          "summary": "RsaCtfTool attack suite",
                          "output": body[:3000], "flags": scan_text(body)})

    steps.append({"step": "next",
                  "summary": "If this is classical/again encoded, try CyberChef-"
                             "style chains; for RSA use ~/tools/RsaCtfTool; for "
                             "hashes crack with john/hashcat.",
                  "output": "", "flags": []})
    return steps
