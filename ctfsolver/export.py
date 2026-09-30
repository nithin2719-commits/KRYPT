"""Export writeups to polished Markdown and PDF.

Markdown is produced by the vault; this module renders it to a clean, printable
HTML and then to PDF via headless Chrome (no external Python deps). Fully
deterministic — no LLM tokens are used anywhere in export.
"""
from __future__ import annotations

import html
import os
import re
import shutil
import subprocess
import tempfile

_CSS = """
*{box-sizing:border-box} body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
 color:#111;max-width:780px;margin:0 auto;padding:40px 36px;line-height:1.55;font-size:13px}
h1{font-size:24px;border-bottom:2px solid #111;padding-bottom:8px;margin:0 0 6px}
h2{font-size:16px;margin:26px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
h3{font-size:14px;margin:18px 0 6px}
blockquote{margin:10px 0;padding:8px 14px;background:#f4f4f5;border-left:3px solid #111;color:#333}
code{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;background:#f0f0f1;
 padding:1px 5px;border-radius:4px;font-size:12px}
pre{background:#0d0d0f;color:#e8e8ea;padding:12px 14px;border-radius:8px;overflow:auto;font-size:11.5px;
 font-family:"JetBrains Mono",ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
pre code{background:none;color:inherit;padding:0}
ul{margin:6px 0;padding-left:22px} li{margin:3px 0}
hr{border:0;border-top:1px solid #ddd;margin:22px 0}
a{color:#0645ad} .foot{color:#888;font-size:11px;margin-top:28px}
@page{margin:16mm}
"""


def md_to_html(md: str, title: str = "writeup") -> str:
    lines = md.split("\n")
    out, i = [], 0
    in_code, in_list = False, False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def inline(s: str) -> str:
        s = html.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
        return s

    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            if not in_code:
                close_list(); out.append("<pre><code>"); in_code = True
            else:
                out.append("</code></pre>"); in_code = False
            i += 1; continue
        if in_code:
            out.append(html.escape(ln)); i += 1; continue
        if ln.startswith("# "):
            close_list(); out.append(f"<h1>{inline(ln[2:])}</h1>")
        elif ln.startswith("## "):
            close_list(); out.append(f"<h2>{inline(ln[3:])}</h2>")
        elif ln.startswith("### "):
            close_list(); out.append(f"<h3>{inline(ln[4:])}</h3>")
        elif ln.startswith("> "):
            close_list(); out.append(f"<blockquote>{inline(ln[2:])}</blockquote>")
        elif ln.startswith("- "):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{inline(ln[2:])}</li>")
        elif ln.strip() == "---":
            close_list(); out.append("<hr>")
        elif ln.strip() == "":
            close_list()
        else:
            close_list(); out.append(f"<p>{inline(ln)}</p>")
        i += 1
    close_list()
    if in_code:
        out.append("</code></pre>")
    body = "\n".join(out)
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}"
            f"</title><style>{_CSS}</style></head><body>{body}</body></html>")


def _chrome() -> str | None:
    for c in ("google-chrome-stable", "chromium", "chromium-browser", "google-chrome"):
        p = shutil.which(c)
        if p:
            return p
    return None


def md_to_pdf(md: str, out_path: str, title: str = "writeup") -> bool:
    chrome = _chrome()
    if not chrome:
        return False
    htmls = md_to_html(md, title)
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as t:
        t.write(htmls)
        src = t.name
    try:
        subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
             f"--print-to-pdf={out_path}", "file://" + src],
            capture_output=True, timeout=60)
    except Exception:
        return False
    finally:
        try:
            os.remove(src)
        except OSError:
            pass
    return os.path.exists(out_path) and os.path.getsize(out_path) > 0
