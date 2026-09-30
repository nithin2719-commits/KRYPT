"""Triage for images: LSB/stego, appended data, and metadata."""
from __future__ import annotations

import os

from ..flags import scan_text
from ..runner import have, run


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []
    lower = path.lower()

    # zsteg for PNG/BMP LSB channels
    if have("zsteg") and lower.endswith((".png", ".bmp")):
        r = run(["zsteg", "-a", path], timeout=90)
        if r.found:
            steps.append({"step": "zsteg",
                          "summary": "LSB / channel analysis",
                          "output": (r.stdout or r.stderr)[:4000],
                          "flags": scan_text(r.stdout)})

    # steghide (JPEG/BMP/WAV) — try empty passphrase automatically
    if have("steghide") and lower.endswith((".jpg", ".jpeg", ".bmp", ".wav")):
        out = os.path.join(workdir, "steghide_out.bin")
        r = run(["steghide", "extract", "-sf", path, "-p", "",
                 "-xf", out, "-f"], timeout=30)
        note = "empty-passphrase extract " + (
            "succeeded" if os.path.exists(out) else "failed (may need password)")
        steps.append({"step": "steghide",
                      "summary": note,
                      "output": (r.stdout or r.stderr)[:1500],
                      "flags": [],
                      "artifacts": [out] if os.path.exists(out) else []})

    # steghide passphrase bruteforce with rockyou (time-boxed).
    if have("stegseek") and lower.endswith((".jpg", ".jpeg", ".bmp", ".wav")):
        from ..crack import crack_steghide
        steps.append(crack_steghide(path, workdir))

    steps.append({"step": "next",
                  "summary": "If nothing yet: check colour planes / palette by "
                             "eye, try zsteg on flipped bit-orders, or "
                             "stegsolve. Also run the generic sweep output above.",
                  "output": "", "flags": []})
    return steps
