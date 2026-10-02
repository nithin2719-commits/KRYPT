"""OSINT triage: pull entities (usernames, emails, domains, phone numbers) out of
the briefing and actually RUN the installed OSINT tools on them — sherlock/maigret
(username -> social accounts), holehe (email -> sites it's registered on),
theHarvester/subfinder (domain -> emails & subdomains), phoneinfoga (phone).

These are passive, read-only lookups against public sources — the intended use for
an authorized OSINT challenge — so they auto-run in triage. Every tool is time-boxed
and the entity count is capped so a hunt can't hang. Tool output is swept for flags
(the flag often sits in a discovered profile bio) and discovered profile URLs are
surfaced as leads for the operator / AI engine to follow.
"""
from __future__ import annotations

import re

from ..flags import scan_text
from ..runner import have, run

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HANDLE = re.compile(r"(?<![\w@])@([A-Za-z0-9_]{3,30})\b")
_KW = (r"(?:user(?:name)?|handle|account|alias|nick(?:name)?|profile|login|"
       r"twitter|github|instagram|reddit|telegram|tiktok)")
# connector optional ("username johndoe") ...
_HINT = re.compile(r"(?i)\b" + _KW + r"\b\s*(?:is|was|:|=|->|'|\")?\s*@?([A-Za-z0-9_.]{3,30})")
# ... and connector REQUIRED, which still catches the real target when a second
# keyword sits in between ("Twitter profile is johndoe" -> johndoe, not "profile")
_HINT_REQ = re.compile(r"(?i)\b" + _KW + r"\b\s*(?:is|was|:|=|->)\s*@?([A-Za-z0-9_.]{3,30})")
_DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
_PHONE = re.compile(r"\+\d[\d\s().-]{7,}\d")

# tokens the hint regex may grab that are never usernames
_HINT_STOP = {"is", "was", "the", "and", "for", "name", "this", "that", "with",
              "your", "profile", "account", "user", "username", "handle"}
# domains that are platforms/noise, not the challenge target
_DOMAIN_STOP = {"example.com", "test.com", "google.com", "gmail.com", "twitter.com",
                "x.com", "github.com", "instagram.com", "facebook.com", "reddit.com",
                "youtube.com", "linkedin.com", "t.me", "telegram.org", "tiktok.com"}
_FILE_TLDS = ("png", "jpg", "jpeg", "gif", "txt", "py", "zip", "pdf", "bin", "exe",
              "md", "json", "html", "css", "js")


def _entities(text: str):
    emails = {e.lower() for e in _EMAIL.findall(text)}
    users = set(_HANDLE.findall(text)) | set(_HINT.findall(text)) | set(_HINT_REQ.findall(text))
    users = {u for u in users if len(u) >= 3 and not u.isdigit()
             and u.lower() not in _HINT_STOP}
    # scan for domains with emails removed, so an email's local-part (e.g. "bob.smith")
    # isn't mistaken for a domain
    domains = {d.lower() for d in _DOMAIN.findall(_EMAIL.sub(" ", text))}
    domains = {d for d in domains if d not in _DOMAIN_STOP
               and d.rsplit(".", 1)[-1] not in _FILE_TLDS}
    # a bare email local-part can double as a username lead
    users |= {e.split("@", 1)[0] for e in emails if e.split("@", 1)[0].isalnum()}
    phones = {m.strip() for m in _PHONE.findall(text)}
    return (sorted(emails), sorted(users), sorted(domains), sorted(phones))


def _tool(steps, name, argv, workdir, timeout, leads=False):
    if not have(argv[0]):
        steps.append({"step": name, "summary": f"{argv[0]} not installed",
                      "output": "", "flags": []})
        return 0
    r = run(argv, timeout=timeout, cwd=workdir)
    out = (r.stdout or "").strip() or (r.stderr or "").strip()
    found_urls = []
    if leads:
        found_urls = sorted(set(re.findall(r"https?://[^\s\]\)>\"']+", out)))
    if r.timed_out:
        summary = f"timed out after {timeout}s (partial)"
    elif leads:
        summary = f"{len(found_urls)} profile/link(s) found"
    else:
        summary = "done" if out else "no results"
    body = out[:3000]
    if found_urls:
        body += "\n\nLEADS:\n" + "\n".join(found_urls[:40])
    steps.append({"step": name, "summary": summary, "output": body[:4000],
                  "flags": scan_text(out)})
    return len(found_urls)


def triage(text: str, workdir: str) -> list[dict]:
    steps: list[dict] = []
    emails, users, domains, phones = _entities(text)
    users, emails, domains, phones = users[:2], emails[:2], domains[:1], phones[:1]

    if not (users or emails or domains or phones):
        steps.append({"step": "osint-entities",
                      "summary": "no username / email / domain / phone found in the "
                      "briefing — add one, e.g. 'username: johndoe', an email, a "
                      "domain, or a +phone, then re-hunt",
                      "output": "", "flags": []})
        return steps

    steps.append({"step": "osint-entities",
                  "summary": f"users={users or '—'}  emails={emails or '—'}  "
                  f"domains={domains or '—'}  phones={phones or '—'}",
                  "output": "", "flags": []})

    for u in users:
        hits = _tool(steps, f"sherlock[{u}]",
                     ["sherlock", "--timeout", "5", "--print-found", "--no-color", u],
                     workdir, 100, leads=True)
        # maigret is slower/deeper — only fall back to it when sherlock came up empty
        if hits == 0 and have("maigret"):
            _tool(steps, f"maigret[{u}]",
                  ["maigret", "--timeout", "8", "--top-sites", "75",
                   "--no-progressbar", "--no-color", u], workdir, 120, leads=True)

    for e in emails:
        _tool(steps, f"holehe[{e}]", ["holehe", "--only-used", "--no-color", e],
              workdir, 90, leads=True)

    for d in domains:
        _tool(steps, f"theharvester[{d}]",
              ["theharvester", "-d", d, "-l", "50", "-b", "duckduckgo,bing,crtsh"],
              workdir, 120, leads=True)
        if have("subfinder"):
            _tool(steps, f"subfinder[{d}]", ["subfinder", "-silent", "-d", d],
                  workdir, 60, leads=True)

    for p in phones:
        _tool(steps, f"phoneinfoga[{p}]", ["phoneinfoga", "scan", "-n", p],
              workdir, 40, leads=True)

    return steps
