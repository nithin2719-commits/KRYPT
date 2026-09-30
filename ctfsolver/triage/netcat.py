"""Auto-probe a remote CTF service: grab the banner and try a few benign
inputs, sweeping every response for flags. Time-boxed, read-mostly recon for
services you are authorized to test.
"""
from __future__ import annotations

import socket

from ..flags import scan_text

# Harmless prompts that frequently reveal a flag on intro/misc services.
PROBES = [b"\n", b"1\n", b"y\n", b"help\n", b"flag\n", b"cat flag\n",
          b"cat flag.txt\n", b"ls\n"]


def _recv(sock: socket.socket, timeout: float = 3.0, limit: int = 65536) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
    except (socket.timeout, OSError):
        pass
    return data


def _one_shot(host: str, port: int, probe: bytes) -> bytes:
    """Fresh connection: read banner, send one probe, read reply. Robust to
    both single-shot and persistent services."""
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            pre = _recv(s, 1.5)
            s.sendall(probe)
            return pre + b"\n>>> " + probe + _recv(s, 1.5)
    except OSError:
        return b""


def triage(host: str, port: int, workdir: str) -> list[dict]:
    steps: list[dict] = []
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            banner = _recv(s, 3.0)
    except OSError as e:
        return [{"step": "netcat", "summary": f"connect failed: {e}",
                 "output": "", "flags": []}]

    btext = banner.decode("latin-1", "replace")
    steps.append({"step": "banner",
                  "summary": f"{len(banner)} bytes from {host}:{port}",
                  "output": btext[:2000], "flags": scan_text(btext)})

    # One fresh connection per probe (handles single-shot services too).
    transcript = b""
    for p in PROBES:
        resp = _one_shot(host, port, p)
        if resp:
            transcript += b"\n" + resp
    text = transcript.decode("latin-1", "replace")
    steps.append({"step": "auto-probe",
                  "summary": f"sent {len(PROBES)} benign probes (fresh conns); "
                             "swept responses",
                  "output": text[:4000], "flags": scan_text(text)})
    steps.append({"step": "next",
                  "summary": "Interactive/pwn service. For exploitation drive it "
                             "with pwntools remote() via hexstrike, guided by the "
                             "performing-binary-exploitation-analysis skill.",
                  "output": "", "flags": []})
    return steps
