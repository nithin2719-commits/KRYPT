"""Automated credential/hash cracking for CTF artifacts, backed by rockyou.

Only invoked when triage hits a locked artifact (password archive, steghide
container, or an isolated hash), so it never slows an ordinary run. Every call
is time-boxed.
"""
from __future__ import annotations

import os
import re

from .runner import have, run

ROCKYOU = next((w for w in (
    "/usr/share/wordlists/rockyou.txt",
    os.path.expanduser("~/rockyou.txt"),
) if os.path.exists(w)), None)


def _john(hash_file: str, fmt: str | None = None, timeout: int = 150) -> dict:
    if not have("john") or not ROCKYOU:
        return {"ok": False, "note": "john or rockyou missing"}
    argv = ["john", f"--wordlist={ROCKYOU}", hash_file]
    if fmt:
        argv.insert(1, f"--format={fmt}")
    run(argv, timeout=timeout)
    show = run(["john", "--show", hash_file] + ([f"--format={fmt}"] if fmt else []),
               timeout=20)
    return {"ok": show.ok(), "output": show.stdout}


def _extract_password(show_output: str) -> str:
    """Pull the password out of `john --show` output.

    Lines look like ``<name>:<password>`` or, with trailing metadata,
    ``<name>:<password>:::::<name>``. The password itself may contain ':', so
    drop the leading name field and strip the trailing ``:::...`` metadata
    rather than taking a fixed column (the old ``split(':')[1]`` truncated any
    password with a colon in it).
    """
    for line in show_output.splitlines():
        line = line.rstrip("\n")
        if ":" not in line:
            continue
        low = line.lower()
        if low.startswith(("0 ", "no ")) or " password hash" in low:
            continue  # summary lines ("1 password hash cracked, 0 left")
        _name, _, rest = line.partition(":")
        # strip a trailing run of colons + optional non-colon field (the
        # repeated filename / empty metadata john appends)
        pw = re.sub(r":+[^:]*$", "", rest) if ":" in rest else rest
        if pw:
            return pw
    return ""


def crack_zip(path: str, workdir: str) -> dict:
    """zip2john -> john; on success, extract with the recovered password."""
    if not have("zip2john"):
        return {"step": "crack-zip", "summary": "zip2john missing",
                "output": "", "flags": []}
    hf = os.path.join(workdir, "zip.hash")
    h = run(["zip2john", path], timeout=30)
    with open(hf, "w") as fh:
        fh.write(h.stdout)
    res = _john(hf)
    pw = _extract_password(res.get("output", ""))
    out = f"recovered password: {pw!r}" if pw else "no password found in rockyou"
    artifacts = []
    if pw and have("7z"):
        ex = os.path.join(workdir, "cracked_extract")
        run(["7z", "x", "-y", f"-p{pw}", f"-o{ex}", path], timeout=60)
        if os.path.isdir(ex):
            for r, _d, files in os.walk(ex):
                artifacts += [os.path.join(r, f) for f in files]
    return {"step": "crack-zip", "summary": out,
            "output": res.get("output", "")[:1000], "flags": [],
            "artifacts": artifacts}


def crack_steghide(path: str, workdir: str) -> dict:
    """stegseek wordlist attack against a steghide container."""
    if not have("stegseek") or not ROCKYOU:
        return {"step": "crack-steghide", "summary": "stegseek/rockyou missing",
                "output": "", "flags": []}
    out = os.path.join(workdir, "stegseek_cracked.bin")
    r = run(["stegseek", path, ROCKYOU, out, "-f"], timeout=180)
    got = os.path.exists(out)
    return {"step": "crack-steghide",
            "summary": "passphrase found + payload extracted" if got
                       else "no passphrase in rockyou",
            "output": (r.stdout or r.stderr)[:1200], "flags": [],
            "artifacts": [out] if got else []}


def crack_hash(hash_str: str, workdir: str, fmt: str | None = None) -> dict:
    hf = os.path.join(workdir, "target.hash")
    with open(hf, "w") as fh:
        fh.write(hash_str.strip() + "\n")
    res = _john(hf, fmt=fmt)
    return {"step": "crack-hash",
            "summary": "john --show result" if res.get("ok") else "no crack",
            "output": res.get("output", "")[:1000], "flags": []}
