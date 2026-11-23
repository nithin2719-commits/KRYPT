"""Document and PDF deep forensics: stream extraction, incremental revision recovery, and XML comment sweeping."""
from __future__ import annotations

import os
import re
import zipfile
from typing import Any

from ..flags import scan_bytes, scan_text, scan_encoded
from ..runner import have, run


def carve_pdf(path: str, workdir: str = "") -> dict[str, Any]:
    """Extract hidden PDF streams, metadata, and uncompressed revisions."""
    flags: list[dict[str, Any]] = []
    artifacts: list[str] = []
    notes: list[str] = []

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return {"flags": [], "artifacts": [], "notes": []}

    # 1. Plain byte sweep over raw PDF
    flags.extend(scan_bytes(data) + scan_encoded(data))

    # 2. Decompress PDF streams with qpdf
    if have("qpdf"):
        decomp_pdf = os.path.join(workdir, "decompressed.pdf")
        r = run(["qpdf", "--qdf", "--object-streams=disable", path, decomp_pdf], timeout=30)
        if os.path.exists(decomp_pdf):
            artifacts.append(decomp_pdf)
            with open(decomp_pdf, "rb") as dfh:
                decomp_data = dfh.read()
            d_flags = scan_bytes(decomp_data) + scan_encoded(decomp_data)
            for f in d_flags:
                f["method"] = "qpdf-stream"
            flags.extend(d_flags)
            notes.append(f"Decompressed PDF streams with qpdf -> {len(d_flags)} flag(s)")

    # 3. Extract embedded attachments with pdfdetach
    if have("pdfdetach"):
        save_dir = os.path.join(workdir, "pdf_attachments")
        os.makedirs(save_dir, exist_ok=True)
        r = run(["pdfdetach", "-saveall", "-o", save_dir, path], timeout=30)
        attached_files = [os.path.join(save_dir, f) for f in os.listdir(save_dir)] if os.path.isdir(save_dir) else []
        if attached_files:
            artifacts.extend(attached_files)
            notes.append(f"Extracted {len(attached_files)} PDF attachment(s)")
            for af in attached_files:
                try:
                    with open(af, "rb") as afh:
                        ab = afh.read()
                    flags.extend(scan_bytes(ab) + scan_encoded(ab))
                except OSError:
                    pass

    # 4. Search for white-on-white text using pdftotext
    if have("pdftotext"):
        r_txt = run(["pdftotext", path, "-"], timeout=30)
        if r_txt.ok() and r_txt.stdout.strip():
            txt_flags = scan_text(r_txt.stdout)
            flags.extend(txt_flags)

    return {"flags": flags, "artifacts": artifacts, "notes": notes}


def carve_office_xml(path: str, workdir: str = "") -> dict[str, Any]:
    """Inspect DOCX, PPTX, XLSX for hidden slides, white text, and XML comments."""
    flags: list[dict[str, Any]] = []
    notes: list[str] = []

    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.endswith((".xml", ".rels", ".txt")):
                    content = zf.read(name).decode("utf-8", "replace")
                    # Check comments <!-- ... -->
                    comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)
                    for cm in comments:
                        c_flags = scan_text(cm)
                        if c_flags:
                            for f in c_flags:
                                f["method"] = f"office-xml-comment-{name}"
                            flags.extend(c_flags)
                    # Check text
                    t_flags = scan_text(content)
                    if t_flags:
                        for f in t_flags:
                            f["method"] = f"office-xml-{name}"
                        flags.extend(t_flags)
    except Exception:
        pass

    return {"flags": flags, "notes": notes}


def solve(path: str, workdir: str = "") -> dict[str, Any]:
    """Execute document forensics on PDF or Office files."""
    lower = path.lower()
    if lower.endswith(".pdf"):
        res = carve_pdf(path, workdir)
        return {
            "step": "doc-carve-pdf",
            "summary": f"PDF stream extraction ({len(res.get('flags', []))} flag(s))",
            "output": "\n".join(res.get("notes", [])) if res.get("notes") else "No hidden PDF streams or attachments.",
            "flags": res.get("flags", []),
            "artifacts": res.get("artifacts", []),
        }
    elif lower.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods")):
        res = carve_office_xml(path, workdir)
        return {
            "step": "doc-carve-office",
            "summary": f"Office XML comment sweep ({len(res.get('flags', []))} flag(s))",
            "output": "Extracted internal XML contents and comments.",
            "flags": res.get("flags", []),
        }
    return {"step": "doc-carve", "summary": "Not a PDF or Office document", "output": "", "flags": []}
