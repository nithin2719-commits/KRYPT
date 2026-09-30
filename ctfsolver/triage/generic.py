"""Generic triage that applies to any file: metadata, strings, embedded data,
entropy, and a full flag sweep. These are the cheap wins run first."""
from __future__ import annotations

import math
import os

from ..flags import scan_file, scan_text
from ..runner import run


def _entropy(path: str, sample: int = 1 << 20) -> float:
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []

    # 1. file identification
    r = run(["file", path])
    steps.append({"step": "file", "summary": r.stdout.strip(),
                  "output": r.stdout, "flags": []})

    # 2. flag sweep over raw bytes (catches plaintext flags instantly)
    flags = scan_file(path)
    steps.append({"step": "flag-sweep(raw)",
                  "summary": f"{len(flags)} candidate(s) in raw bytes",
                  "output": "\n".join(f["flag"] for f in flags[:20]),
                  "flags": flags})

    # 3. printable strings (ascii + 16-bit LE), swept for flags too
    s = run(["strings", "-n", "6", path], timeout=90)
    sl = run(["strings", "-n", "6", "-el", path], timeout=90)
    all_strings = s.stdout + "\n" + sl.stdout
    str_flags = scan_text(all_strings)
    interesting = [ln for ln in all_strings.splitlines()
                   if any(k in ln.lower() for k in
                          ("flag", "pass", "key", "secret", "ctf", "http",
                           "base64", "xor", "token"))][:60]
    steps.append({"step": "strings",
                  "summary": f"{len(all_strings.splitlines())} strings; "
                             f"{len(interesting)} interesting; "
                             f"{len(str_flags)} flag candidate(s)",
                  "output": "\n".join(interesting),
                  "flags": str_flags})

    # 4. exif / metadata
    r = run(["exiftool", path], timeout=30)
    if r.ok():
        meta_flags = scan_text(r.stdout)
        steps.append({"step": "exiftool",
                      "summary": "metadata extracted",
                      "output": r.stdout[:4000], "flags": meta_flags})

    # 5. embedded-file scan + entropy (points at stego / appended archives)
    ent = _entropy(path)
    bw = run(["binwalk", path], timeout=60)
    steps.append({"step": "binwalk+entropy",
                  "summary": f"entropy={ent:.2f} "
                             f"({'high/packed-or-encrypted' if ent > 7.5 else 'normal'})",
                  "output": bw.stdout[:4000] if bw.ok() else bw.note,
                  "flags": []})

    # 6. auto-extract embedded files (non-destructive, into workdir)
    ex_dir = os.path.join(workdir, "binwalk_extract")
    ex = run(["binwalk", "--dd=.*", "-e", "-C", ex_dir, path], timeout=120)
    if ex.ok() and os.path.isdir(ex_dir):
        carved = []
        for root, _dirs, files in os.walk(ex_dir):
            for fn in files:
                carved.append(os.path.join(root, fn))
        if carved:
            steps.append({"step": "binwalk-extract",
                          "summary": f"carved {len(carved)} embedded file(s)",
                          "output": "\n".join(carved[:40]),
                          "flags": [], "artifacts": carved})
    return steps
