"""Triage for web URLs: headers, source, common paths, tech fingerprint.

Read-only reconnaissance intended for CTF web challenges and targets you are
authorized to test. It fetches pages and checks a small list of conventional
CTF paths; it does not brute-force or exploit anything on its own.
"""
from __future__ import annotations

from urllib.parse import urljoin

from ..flags import scan_text
from ..runner import have, run

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/flag",
    "/flag.txt", "/admin", "/backup", "/.htaccess", "/index.php.bak",
    "/api", "/status", "/debug",
]


def _curl(url: str, args: list[str], timeout: int = 20):
    return run(["curl", "-sS", "-k", "-L", "--max-time", str(timeout - 2),
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
        code = run(["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
                    "--max-time", "8", u], timeout=12).stdout.strip()
        if code and code not in ("404", "000"):
            hits.append(f"{code}  {u}")
    steps.append({"step": "common-paths",
                  "summary": f"{len(hits)} interesting path(s)",
                  "output": "\n".join(hits), "flags": []})

    # Tech fingerprint if whatweb present
    if have("whatweb"):
        r = run(["whatweb", "--color=never", url], timeout=30)
        steps.append({"step": "whatweb", "summary": "tech fingerprint",
                      "output": r.stdout[:2000], "flags": []})

    steps.append({"step": "next",
                  "summary": "Deeper: hexstrike ffuf/gobuster for content "
                             "discovery, nuclei for known CVEs, and sqlmap / "
                             "the exploiting-* skills for the specific bug "
                             "class this looks like.",
                  "output": "", "flags": []})
    return steps
