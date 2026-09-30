"""Classify an input into a challenge category so the right triage runs."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .runner import run

URL_RE = re.compile(r"^https?://", re.I)
HOSTPORT_RE = re.compile(r"^(?:nc\s+)?([\w.\-]+)[\s:]+(\d{1,5})$")


@dataclass
class Target:
    kind: str          # file | url | netcat | unknown
    raw: str
    # file-only, refined category: binary | image | archive | pcap | pdf |
    #                              audio | text | data
    subkind: str = ""
    host: str = ""
    port: int = 0
    mime: str = ""


def _file_subkind(path: str) -> tuple[str, str]:
    r = run(["file", "-b", "--mime-type", path], timeout=15)
    mime = r.stdout.strip() if r.ok() else ""
    desc = run(["file", "-b", path], timeout=15).stdout.strip().lower()

    if any(t in mime for t in ("x-executable", "x-pie-executable",
                               "x-sharedlib", "x-object", "x-dosexec")) \
            or "elf" in desc or "pe32" in desc or "mach-o" in desc:
        return "binary", mime
    if mime.startswith("image/") or "image data" in desc:
        return "image", mime
    if mime.startswith("audio/") or "audio" in desc:
        return "audio", mime
    if mime == "application/pdf" or "pdf document" in desc:
        return "pdf", mime
    if any(t in mime for t in ("zip", "x-tar", "x-7z", "gzip", "x-bzip2",
                               "x-rar", "x-xz")) or "archive" in desc \
            or "compressed" in desc:
        return "archive", mime
    if "pcap" in desc or "tcpdump" in desc or mime == "application/vnd.tcpdump.pcap":
        return "pcap", mime
    if mime.startswith("text/") or "ascii text" in desc or "unicode text" in desc:
        return "text", mime
    return "data", mime


def classify(arg: str) -> Target:
    if URL_RE.match(arg):
        return Target(kind="url", raw=arg)
    if os.path.exists(arg):
        sub, mime = _file_subkind(arg)
        return Target(kind="file", raw=arg, subkind=sub, mime=mime)
    m = HOSTPORT_RE.match(arg.strip())
    if m:
        return Target(kind="netcat", raw=arg, host=m.group(1),
                      port=int(m.group(2)))
    return Target(kind="unknown", raw=arg)
