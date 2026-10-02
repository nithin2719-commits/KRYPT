"""Triage for web URLs: headers, source, common paths, tech fingerprint.

Read-only reconnaissance intended for CTF web challenges and targets you are
authorized to test. It fetches pages and checks a small list of conventional
CTF paths; it does not brute-force or exploit anything on its own.
"""
from __future__ import annotations

import os
import re
import shutil
from urllib.parse import urljoin

from ..flags import scan_text
from ..runner import have, run


def _real_curl() -> str:
    """Resolve a genuine curl binary, skipping any `curl` shim earlier on PATH.

    ~/.local/bin (which the Alt+T launcher puts first on PATH so `claude`/`agy`
    resolve) contains a CTF practice wrapper named `curl` that fakes responses
    for a few challenge ports. KRYPT's own recon must use the real binary, or the
    web triage reports fabricated pages/flags. Prefer the real paths; fall back
    to PATH only if none exist.
    """
    for c in ("/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"):
        if os.path.exists(c):
            return c
    return shutil.which("curl") or "curl"


_CURL = _real_curl()

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/flag",
    "/flag.txt", "/admin", "/backup", "/.htaccess", "/index.php.bak",
    "/api", "/status", "/debug", "/.svn/entries", "/config.php.bak",
    "/server-status", "/.DS_Store", "/swagger.json", "/graphql",
]
_FORM = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
_ACTION = re.compile(r'action\s*=\s*["\']([^"\']*)', re.I)
_INPUT = re.compile(r'<input[^>]*name\s*=\s*["\']([^"\']+)', re.I)
_METHOD = re.compile(r'method\s*=\s*["\']?(\w+)', re.I)
_COOKIE_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}')


def _curl(url: str, args: list[str], timeout: int = 20):
    return run([_CURL, "-sS", "-k", "-L", "--max-time", str(timeout - 2),
                *args, url], timeout=timeout)


def triage(url: str, workdir: str) -> list[dict]:
    steps: list[dict] = []

    # Headers
    r = _curl(url, ["-D", "-", "-o", "/dev/null"])
    steps.append({"step": "headers", "summary": "response headers",
                  "output": (r.stdout or r.stderr)[:2000],
                  "flags": scan_text(r.stdout)})

    # Body + flag sweep + comment/hint extraction
    r = _curl(url, [])
    body = r.stdout
    hints = [ln.strip() for ln in body.splitlines()
             if any(k in ln.lower() for k in
                    ("<!--", "flag", "todo", "password", "secret", "api",
                     "hidden", "debug"))][:40]
    steps.append({"step": "body",
                  "summary": f"{len(body)} bytes; {len(hints)} hint line(s)",
                  "output": "\n".join(hints), "flags": scan_text(body)})

    # Conventional CTF paths
    hits = []
    for p in COMMON_PATHS:
        u = urljoin(url, p)
        code = run([_CURL, "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
                    "--max-time", "8", u], timeout=12).stdout.strip()
        if code and code not in ("404", "000"):
            hits.append(f"{code}  {u}")
    steps.append({"step": "common-paths",
                  "summary": f"{len(hits)} interesting path(s)",
                  "output": "\n".join(hits), "flags": []})

    # Forms & inputs — the attack surface (SQLi / XSS / SSTI / upload targets)
    forms = []
    for fm in _FORM.findall(body):
        act = (_ACTION.search(fm) or [None, "(self)"])[1]
        meth = (_METHOD.search(fm) or [None, "GET"])[1].upper()
        names = _INPUT.findall(fm)
        forms.append(f"{meth} {act}  params={names}")
    if forms:
        steps.append({"step": "forms",
                      "summary": f"{len(forms)} form(s) — test for SQLi/XSS/SSTI",
                      "output": "\n".join(forms[:20]), "flags": []})

    # JWT in body/headers?
    jwts = set(_COOKIE_JWT.findall(body)) | set(_COOKIE_JWT.findall(
        _curl(url, ["-D", "-", "-o", "/dev/null"]).stdout))
    if jwts:
        steps.append({"step": "jwt",
                      "summary": f"{len(jwts)} JWT(s) found — try alg:none / weak-secret",
                      "output": "\n".join(list(jwts)[:5]), "flags": []})

    # Tech fingerprint
    if have("whatweb"):
        r = run(["whatweb", "--color=never", url], timeout=30)
        steps.append({"step": "whatweb", "summary": "tech fingerprint",
                      "output": r.stdout[:2000], "flags": []})

    # Parameter discovery (arjun) — finds hidden GET params
    if have("arjun"):
        out = run(["arjun", "-u", url, "-oT", "/dev/stdout", "-q"], timeout=90)
        if out.ok() and out.stdout.strip():
            steps.append({"step": "arjun",
                          "summary": "hidden parameter discovery",
                          "output": out.stdout[:2000], "flags": []})

    steps.append({"step": "next",
                  "summary": "Deeper: feroxbuster/ffuf for content discovery, "
                             "nuclei for CVEs, sqlmap on the forms above, and the "
                             "exploiting-* skills for the matched bug class.",
                  "output": "", "flags": []})
    return steps
