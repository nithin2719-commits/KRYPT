"""Triage for PDFs.

The generic sweep (strings + raw flag scan) misses the common case: a flag that
lives in a FlateDecode-compressed text stream — i.e. ordinary PDF body text. So
here we pull the text out properly (pdftotext), decompress the whole file
(qpdf --qdf) so compressed objects become greppable, and detach any embedded
files and images so the recursive hunt can process them (stego, nested archives,
etc.). Extracted text is also run through the magic decoder for encoded flags.
"""
from __future__ import annotations

import os

from ..flags import scan_text
from ..runner import have, run


def _decode_sweep(text: str) -> list[dict]:
    """Flag scan + a magic-decode pass over extracted text (encoded-in-doc)."""
    flags = list(scan_text(text))
    try:
        from ..decoders import magic
        m = magic(text.encode("utf-8", "replace"))
        if m["found"]:
            flags += m["flags"]
    except Exception:
        pass
    return flags


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []

    # 1. extract rendered text (handles compressed content streams)
    if have("pdftotext"):
        r = run(["pdftotext", "-layout", path, "-"], timeout=60)
        text = r.stdout or ""
        if text.strip():
            txt_art = os.path.join(workdir, "pdf_text.txt")
            try:
                with open(txt_art, "w") as fh:
                    fh.write(text)
            except OSError:
                txt_art = None
            steps.append({"step": "pdftotext",
                          "summary": f"extracted {len(text)} chars of text",
                          "output": text[:4000],
                          "flags": _decode_sweep(text),
                          "artifacts": [txt_art] if txt_art else []})

    # 2. document metadata (title/author/keywords often hide the flag)
    if have("pdfinfo"):
        r = run(["pdfinfo", "-meta", path], timeout=30)
        if r.found and (r.stdout or "").strip():
            steps.append({"step": "pdfinfo",
                          "summary": "document metadata",
                          "output": r.stdout[:3000],
                          "flags": scan_text(r.stdout)})

    # 3. decompress every object so hidden/compressed streams become greppable
    if have("qpdf"):
        qdf = os.path.join(workdir, "pdf_decompressed.qdf")
        r = run(["qpdf", "--qdf", "--object-streams=disable",
                 "--decode-level=all", path, qdf], timeout=60)
        # qpdf returns rc 3 on warnings but still writes the file — accept it.
        if os.path.isfile(qdf) and os.path.getsize(qdf) > 0:
            fl = scan_text(open(qdf, "r", errors="replace").read(1 << 20))
            steps.append({"step": "qpdf-decompress",
                          "summary": "decompressed all streams (qdf)",
                          "output": (r.stderr or "")[:600],
                          "flags": fl, "artifacts": [qdf]})

    # 4. detach embedded/attached files -> recursive hunt handles them
    if have("pdfdetach"):
        att_dir = os.path.join(workdir, "pdf_attachments")
        os.makedirs(att_dir, exist_ok=True)
        run(["pdfdetach", "-saveall", "-o", att_dir, path], timeout=60)
        carved = [os.path.join(att_dir, fn) for fn in os.listdir(att_dir)
                  if os.path.isfile(os.path.join(att_dir, fn))]
        if carved:
            steps.append({"step": "pdfdetach",
                          "summary": f"{len(carved)} embedded file(s)",
                          "output": "\n".join(carved),
                          "flags": [], "artifacts": carved})

    # 5. extract embedded images -> recursive hunt -> image/stego triage
    if have("pdfimages"):
        prefix = os.path.join(workdir, "pdfimg")
        r = run(["pdfimages", "-all", path, prefix], timeout=60)
        imgs = [os.path.join(workdir, fn) for fn in os.listdir(workdir)
                if fn.startswith("pdfimg") and
                os.path.isfile(os.path.join(workdir, fn))]
        if imgs:
            steps.append({"step": "pdfimages",
                          "summary": f"extracted {len(imgs)} image(s)",
                          "output": "\n".join(imgs[:40]),
                          "flags": [], "artifacts": imgs})

    steps.append({"step": "next",
                  "summary": "If still nothing: inspect objects with pdf-parser "
                             "(JS, /OpenAction), check for text drawn as vector "
                             "paths, and eyeball extracted images for stego.",
                  "output": "", "flags": []})
    return steps
