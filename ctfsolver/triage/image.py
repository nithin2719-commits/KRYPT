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

    # Appended/overlay data after EOF marker (classic cat secret >> image trick)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        overlay = None
        if lower.endswith(".png"):
            idx = data.find(b"IEND\xae\x42\x60\x82")
            if idx != -1 and idx + 8 < len(data):
                overlay = data[idx + 8:]
        elif lower.endswith((".jpg", ".jpeg")):
            idx = data.rfind(b"\xff\xd9")
            if idx != -1 and idx + 2 < len(data):
                overlay = data[idx + 2:]
        elif lower.endswith(".gif"):
            idx = data.rfind(b"\x3b")
            if idx != -1 and idx + 1 < len(data):
                overlay = data[idx + 1:]

        if overlay and len(overlay) > 0:
            out_overlay = os.path.join(workdir, "trailing_overlay.bin")
            with open(out_overlay, "wb") as ofh:
                ofh.write(overlay)
            from ..flags import scan_bytes, scan_encoded
            ov_flags = scan_bytes(overlay) + scan_encoded(overlay)
            steps.append({"step": "image-overlay",
                          "summary": f"carved {len(overlay)} bytes of trailing data after EOF marker",
                          "output": overlay[:500].decode("latin-1", "replace"),
                          "flags": ov_flags,
                          "artifacts": [out_overlay]})
    except OSError:
        pass

    steps.append({"step": "next",
                  "summary": "If nothing yet: check colour planes / palette by "
                             "eye, try zsteg on flipped bit-orders, or "
                             "stegsolve. Also run the generic sweep output above.",
                  "output": "", "flags": []})

    return steps
