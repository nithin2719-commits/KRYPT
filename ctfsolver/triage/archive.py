"""Triage for archives: detect encryption, extract (or crack), list members.

The caller (__main__) recurses the full pipeline into every extracted member,
so nested challenges unravel automatically.
"""
from __future__ import annotations

import os

from ..runner import have, run


def _encrypted(path: str) -> bool:
    """True if any archive member is encrypted (7z: 'Encrypted = +')."""
    r = run(["7z", "l", "-slt", path], timeout=30)
    return r.ok() and "Encrypted = +" in r.stdout


def _members(out_dir: str) -> list[str]:
    out = []
    if os.path.isdir(out_dir):
        for root, _d, files in os.walk(out_dir):
            for fn in files:
                p = os.path.join(root, fn)
                if os.path.getsize(p) > 0:   # ignore 0-byte extraction stubs
                    out.append(p)
    return out


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []
    out_dir = os.path.join(workdir, "archive_extract")
    os.makedirs(out_dir, exist_ok=True)
    lower = path.lower()

    listed = run(["7z", "l", path], timeout=30)
    if listed.ok():
        steps.append({"step": "7z-list", "summary": "archive contents",
                      "output": listed.stdout[:2000], "flags": []})

    # Encrypted archive -> go straight to cracking (an empty-password extract
    # would otherwise write 0-byte stubs and masquerade as success).
    if _encrypted(path):
        steps.append({"step": "extract",
                      "summary": "archive is ENCRYPTED — cracking passphrase",
                      "output": "", "flags": []})
        if lower.endswith(".zip"):
            from ..crack import crack_zip
            steps.append(crack_zip(path, workdir))
        else:
            steps.append({"step": "next",
                          "summary": "Locked non-zip archive. Extract the hash "
                                     "with the matching *2john tool and crack "
                                     "with john/hashcat.", "output": "",
                          "flags": []})
        return steps

    # Not encrypted -> extract normally.
    run(["7z", "x", "-y", "-o" + out_dir, path], timeout=120)
    members = _members(out_dir)
    if not members and lower.endswith(".zip") and have("unzip"):
        run(["unzip", "-o", path, "-d", out_dir], timeout=120)
        members = _members(out_dir)

    steps.append({
        "step": "extract",
        "summary": (f"extracted {len(members)} file(s)" if members
                    else "extraction produced no files"),
        "output": "\n".join(members[:50]),
        "flags": [], "artifacts": members,
    })
    return steps
