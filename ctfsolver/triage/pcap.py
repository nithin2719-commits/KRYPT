"""Triage for packet captures: protocol summary, extracted strings, HTTP objects,
and USB HID keystroke decoding."""
from __future__ import annotations

import os
import sys

from ..flags import scan_text
from ..runner import have, run

_SOLVERS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "solvers")


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []

    if have("capinfos"):
        r = run(["capinfos", path], timeout=30)
        steps.append({"step": "capinfos", "summary": "capture summary",
                      "output": r.stdout[:1500], "flags": []})

    if have("tshark"):
        # Protocol hierarchy
        r = run(["tshark", "-r", path, "-q", "-z", "io,phs"], timeout=60)
        steps.append({"step": "protocols", "summary": "protocol hierarchy",
                      "output": r.stdout[:2000], "flags": []})
        # ASCII of all payloads, swept for flags / creds
        r = run(["tshark", "-r", path, "-T", "fields", "-e", "data.text",
                 "-e", "http.file_data"], timeout=90)
        blob = r.stdout
        steps.append({"step": "payloads",
                      "summary": "payload text swept for flags",
                      "output": blob[:2000], "flags": scan_text(blob)})

        # DNS query sweep (catches DNS exfiltration challenges)
        rdns = run(["tshark", "-r", path, "-T", "fields", "-e", "dns.qry.name"], timeout=45)
        if rdns.ok() and rdns.stdout.strip():
            queries = [q.strip() for q in rdns.stdout.splitlines() if q.strip()]
            uniq_queries = list(dict.fromkeys(queries))
            dns_flags = scan_text("\n".join(uniq_queries))
            from ..flags import scan_encoded
            dns_enc = scan_encoded("\n".join(uniq_queries).encode())
            dns_flags = sorted(dns_flags + dns_enc, key=lambda f: -f["confidence"])
            steps.append({"step": "dns-queries",
                          "summary": f"{len(uniq_queries)} unique DNS query name(s) swept",
                          "output": "\n".join(uniq_queries[:40]), "flags": dns_flags})

        # Export HTTP objects (files transferred over HTTP)
        http_dir = os.path.join(workdir, "pcap_http_objects")
        os.makedirs(http_dir, exist_ok=True)
        run(["tshark", "-r", path, "--export-objects", f"http,{http_dir}"], timeout=60)
        exported = [os.path.join(http_dir, f) for f in os.listdir(http_dir)] if os.path.isdir(http_dir) else []
        if exported:
            steps.append({"step": "pcap-http-export",
                          "summary": f"carved {len(exported)} file(s) transferred over HTTP",
                          "output": "\n".join(os.path.basename(f) for f in exported[:30]),
                          "flags": [], "artifacts": exported})
    else:
        # Fall back to strings over the raw capture
        r = run(["strings", "-n", "6", path], timeout=60)
        steps.append({"step": "strings",
                      "summary": "no tshark; raw strings",
                      "output": r.stdout[:2000], "flags": scan_text(r.stdout)})

    # USB HID keystroke decode — auto-solves keyboard-capture forensics challenges
    py = sys.executable or "python3"
    hid = run([py, os.path.join(_SOLVERS, "usb_hid.py"), path], timeout=150)
    if hid.found and "KEYSTROKES" in hid.stdout:
        steps.append({"step": "usb-hid",
                      "summary": "decoded USB keyboard keystrokes",
                      "output": hid.stdout[:3000], "flags": scan_text(hid.stdout)})

    steps.append({"step": "next",
                  "summary": "Deeper: Wireshark Follow-TCP-Stream on flagged "
                             "conversations, export HTTP objects, or use the "
                             "analyzing-network-traffic-with-wireshark skill.",
                  "output": "", "flags": []})
    return steps
