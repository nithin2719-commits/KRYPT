"""Export writeups to polished Markdown and a KRYPT-branded PDF.

Markdown is produced by the vault; this module renders it to a themed HTML that
matches the KRYPT interface (pure-black monochrome terminal, Orbitron masthead,
JetBrains Mono body, a "FLAG CAPTURED" hero chip) and then to PDF via headless
Chrome — no external Python deps. Fully deterministic; no LLM tokens are used.
"""
from __future__ import annotations

import html
import os
import re
import shutil
import subprocess
import tempfile

# KRYPT brand — mirrors gui/index.html (monochrome dark terminal).
_CSS = """
:root{
 --bg:#060608; --surface:#0f0f12; --raise:#15151a; --fg:#f2f2f4;
 --dim:#9a9aa2; --muted:#64646c; --line:rgba(255,255,255,.14);
 --flag:#f5f5f6;
 --display:"Orbitron","Rajdhani",system-ui,sans-serif;
 --mono:"JetBrains Mono","JetBrainsMono Nerd Font","JetBrainsMono NF",ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{background:var(--bg);-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-family:var(--mono);color:var(--fg);margin:0;padding:0;
 line-height:1.62;font-size:12.5px;font-feature-settings:"liga" 0}
/* full-bleed black page (edge-to-edge, like the KRYPT GUI) with centered body */
.page{max-width:820px;margin:0 auto;padding:30px 48px 44px;min-height:100vh}

/* masthead */
.mast{display:flex;align-items:flex-end;justify-content:space-between;
 gap:16px;padding:30px 0 14px;margin:0 0 26px;border-bottom:1px solid var(--line)}
.mast .brand{font-family:var(--display);font-weight:800;font-size:26px;
 letter-spacing:7px;color:#fff;line-height:1}
.mast .brand .dia{font-size:19px;vertical-align:1px;margin-right:10px;color:#fff}
.mast .tag{font-size:9.5px;letter-spacing:3.4px;color:var(--dim);
 text-transform:uppercase;margin-top:7px}
.mast .stamp{font-size:9.5px;letter-spacing:2.6px;color:var(--muted);
 text-transform:uppercase;text-align:right;white-space:nowrap}

/* flag hero chip */
.flaghero{margin:18px 0 8px;border:1px solid var(--line);border-left:3px solid #fff;
 background:linear-gradient(90deg,var(--raise),var(--surface));
 border-radius:10px;padding:13px 18px}
.flaghero .lbl{font-size:9.5px;letter-spacing:3.4px;color:var(--dim);
 text-transform:uppercase;display:block;margin-bottom:6px}
.flaghero .val{font-family:var(--mono);font-weight:700;font-size:16.5px;
 color:var(--flag);word-break:break-all}

h1{font-family:var(--display);font-weight:700;font-size:21px;color:#fff;
 letter-spacing:.5px;margin:4px 0 4px;padding-bottom:0;border:0}
h2{font-family:var(--display);font-weight:600;font-size:12.5px;color:#ededef;
 text-transform:uppercase;letter-spacing:2.6px;margin:30px 0 11px;
 padding-bottom:7px;border-bottom:1px solid var(--line)}
h3{font-family:var(--mono);font-weight:700;font-size:12.5px;color:var(--fg);
 margin:20px 0 7px;letter-spacing:.3px}

p{margin:9px 0}
p.note{color:var(--muted);font-size:10.5px;letter-spacing:.4px;font-style:italic}
blockquote{margin:12px 0;padding:10px 16px;background:var(--surface);
 border:1px solid var(--line);border-left:3px solid #fff;border-radius:8px;
 color:var(--dim);font-size:11.5px;letter-spacing:.3px}
code{font-family:var(--mono);background:var(--raise);color:#eaeaec;
 padding:1.5px 6px;border-radius:5px;font-size:11.5px;border:1px solid var(--line)}
pre{background:#0a0a0d;color:#e6e6e8;padding:14px 16px;border-radius:9px;
 border:1px solid var(--line);overflow:auto;font-size:11px;
 font-family:var(--mono);white-space:pre-wrap;word-break:break-word;margin:11px 0}
pre code{background:none;color:inherit;padding:0;border:0}
b,strong{color:#fff;font-weight:700}
ul,ol{margin:8px 0;padding-left:24px}
li{margin:4px 0}
li::marker{color:var(--muted)}
hr{border:0;border-top:1px solid var(--line);margin:24px 0}
a{color:#fff;text-decoration:underline;text-underline-offset:2px}
.foot{display:flex;justify-content:space-between;gap:12px;color:var(--muted);
 font-size:9.5px;letter-spacing:2.4px;text-transform:uppercase;margin-top:34px;
 padding-top:12px;border-top:1px solid var(--line)}
@page{margin:0;size:A4}
/* keep a heading with its first content, and never split a card/chip/code block */
h1,h2,h3{break-after:avoid;page-break-after:avoid}
pre,blockquote,.flaghero,li{break-inside:avoid;page-break-inside:avoid}
"""

_FLAG_LINE = re.compile(r"^\*\*Flag\*\*\s*·\s*`(.+?)`\s*$")
_ORDERED = re.compile(r"^(\d+)\.\s+(.*)$")
# a whole line wrapped in underscores (e.g. the generator footer) — rendered as
# a muted note. Scoped to full lines so flag underscores (flag{a_b}) are safe.
_ITALIC_LINE = re.compile(r"^_([^_].*[^_])_$")


def _masthead(title: str) -> str:
    stamp = html.escape(title.upper()[:46])
    return ("<div class='mast'>"
            "<div><div class='brand'><span class='dia'>◆</span>KRYPT</div>"
            "<div class='tag'>CTF Triage · Flag Hunter</div></div>"
            f"<div class='stamp'>Auto-Writeup<br>{stamp}</div></div>")


def md_to_html(md: str, title: str = "writeup") -> str:
    lines = md.split("\n")
    out, i = [], 0
    in_code = False
    list_kind = None  # None | "ul" | "ol"

    def close_list():
        nonlocal list_kind
        if list_kind:
            out.append(f"</{list_kind}>")
            list_kind = None

    def open_list(kind: str):
        nonlocal list_kind
        if list_kind != kind:
            close_list()
            out.append(f"<{kind}>")
            list_kind = kind

    def inline(s: str) -> str:
        s = html.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"<a href='\2'>\1</a>", s)
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

        mflag = _FLAG_LINE.match(ln)
        mord = _ORDERED.match(ln)
        mital = _ITALIC_LINE.match(ln)
        if ln.startswith("# "):
            close_list(); out.append(f"<h1>{inline(ln[2:])}</h1>")
        elif mital:
            close_list()
            out.append(f"<p class='note'>{inline(mital.group(1))}</p>")
        elif mflag:
            close_list()
            out.append("<div class='flaghero'><span class='lbl'>🚩 Flag Captured"
                       "</span><span class='val'>"
                       f"{html.escape(mflag.group(1))}</span></div>")
        elif ln.startswith("## "):
            close_list(); out.append(f"<h2>{inline(ln[3:])}</h2>")
        elif ln.startswith("### "):
            close_list(); out.append(f"<h3>{inline(ln[4:])}</h3>")
        elif ln.startswith("> "):
            close_list(); out.append(f"<blockquote>{inline(ln[2:])}</blockquote>")
        elif mord:
            open_list("ol"); out.append(f"<li>{inline(mord.group(2))}</li>")
        elif ln.startswith("- "):
            open_list("ul"); out.append(f"<li>{inline(ln[2:])}</li>")
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

    foot = ("<div class='foot'><span>◆ KRYPT — deterministic writeup · "
            "no AI tokens</span><span>github.com/nithin2719-commits/KRYPT</span></div>")
    body = _masthead(title) + "\n".join(out) + foot
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>"
            f"{html.escape(title)}</title><style>{_CSS}</style></head>"
            f"<body><div class='page'>{body}</div></body></html>")


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
    # Isolate the HTML source and Chrome's profile in a private temp dir so a PDF
    # export never collides with an already-running Chrome ("profile in use") or
    # with a second concurrent export — the common cause of a silent empty PDF.
    workdir = tempfile.mkdtemp(prefix="krypt-pdf-")
    src = os.path.join(workdir, "writeup.html")
    profile = os.path.join(workdir, "profile")
    try:
        with open(src, "w") as fh:
            fh.write(htmls)
        subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", "--no-default-browser-check",
             f"--user-data-dir={profile}",
             "--no-pdf-header-footer", "--print-to-pdf-no-header",
             f"--print-to-pdf={out_path}", "file://" + src],
            capture_output=True, timeout=60)
    except Exception:
        return False
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return os.path.exists(out_path) and os.path.getsize(out_path) > 0
