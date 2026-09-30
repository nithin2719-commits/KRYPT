#!/usr/bin/env python3
"""Standalone RSA auto-attack for crypto challenges.

Parses RSA parameters (n, e, c) or a public-key file out of the given input and
runs RsaCtfTool's attack suite to recover the plaintext / flag. Weak-RSA CTF
staple (small e, close primes, factorable n, common modulus, Wiener, etc.).

    python3 rsa_solve.py <file-or-text-file>
"""
import re
import shutil
import subprocess
import sys
import tempfile


def _find_ints(text):
    vals = {}
    for key in ("n", "e", "c"):
        m = re.search(rf"\b{key}\s*[:=]\s*([0-9]+)", text)
        if not m:
            m = re.search(rf"\b{key}\s*[:=]\s*0x([0-9a-fA-F]+)", text)
            if m:
                vals[key] = int(m.group(1), 16)
                continue
        if m:
            vals[key] = int(m.group(1))
    return vals


def main():
    if len(sys.argv) < 2:
        print("USAGE: rsa_solve.py <file>")
        return 2
    tool = shutil.which("rsactftool") or shutil.which("RsaCtfTool")
    if not tool:
        print("RSACTFTOOL_MISSING")
        return 2
    path = sys.argv[1]
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read(200000)
    except OSError as e:
        print(f"READ_FAILED {e}")
        return 2

    # PEM public key present? attack it directly.
    if "-----BEGIN" in text and "KEY-----" in text:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as t:
            t.write(text[text.index("-----BEGIN"):])
            pub = t.name
        cmd = [tool, "--publickey", pub, "--private", "--attack", "all"]
        r = subprocess.run(cmd, capture_output=True, timeout=280)
        print(r.stdout.decode("latin-1", "replace")[-4000:])
        return 0

    v = _find_ints(text)
    if "n" not in v or "e" not in v:
        print("NO_RSA_PARAMS")
        return 1
    cmd = [tool, "-n", str(v["n"]), "-e", str(v["e"]), "--attack", "all"]
    if "c" in v:
        cmd += ["--uncipher", str(v["c"])]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=280)
    except subprocess.TimeoutExpired:
        print("RSA_TIMEOUT")
        return 1
    out = (r.stdout + r.stderr).decode("latin-1", "replace")
    print(out[-4000:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
