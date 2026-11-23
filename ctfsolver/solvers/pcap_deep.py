"""Deep PCAP triage solver: ICMP data tunnels, plaintext credentials, and TCP stream extraction."""
from __future__ import annotations

import base64
import binascii
import os
import re
from typing import Any

from ..flags import scan_bytes, scan_text, scan_encoded
from ..runner import have, run


def extract_icmp_tunnel(pcap_path: str, workdir: str = "") -> dict[str, Any]:
    """Extract and reassemble ICMP data payloads (echo requests/replies)."""
    flags: list[dict[str, Any]] = []
    if not have("tshark"):
        return {"flags": [], "notes": []}

    # Extract hex-encoded ICMP data field
    r = run(["tshark", "-r", pcap_path, "-Y", "icmp", "-T", "fields", "-e", "data"], timeout=45)
    if not r.ok() or not r.stdout.strip():
        return {"flags": [], "notes": []}

    hex_lines = [line.strip().replace(":", "") for line in r.stdout.splitlines() if line.strip()]
    if not hex_lines:
        return {"flags": [], "notes": []}

    raw_payloads = bytearray()
    for hl in hex_lines:
        try:
            b = binascii.unhexlify(hl)
            raw_payloads.extend(b)
        except Exception:
            continue

    if not raw_payloads:
        return {"flags": [], "notes": []}

    # Scan raw and encoded payloads
    found = scan_bytes(bytes(raw_payloads)) + scan_encoded(bytes(raw_payloads))
    for f in found:
        f["method"] = "icmp-tunnel"

    notes = [f"Reassembled {len(raw_payloads)} bytes across {len(hex_lines)} ICMP packet(s)"]
    return {"flags": found, "notes": notes, "bytes_count": len(raw_payloads)}


def extract_credentials(pcap_path: str) -> dict[str, Any]:
    """Extract cleartext credentials across FTP, HTTP Basic, and SMTP."""
    flags: list[dict[str, Any]] = []
    creds: list[str] = []
    if not have("tshark"):
        return {"flags": [], "creds": []}

    # 1. FTP credentials
    r_ftp = run(["tshark", "-r", pcap_path, "-Y", "ftp.request.command in {\"USER\",\"PASS\"}",
                 "-T", "fields", "-e", "ftp.request.command", "-e", "ftp.request.arg"], timeout=30)
    if r_ftp.ok() and r_ftp.stdout.strip():
        for line in r_ftp.stdout.splitlines():
            line = line.strip()
            if line:
                creds.append(f"[FTP] {line}")
                flags.extend(scan_text(line))

    # 2. HTTP Basic Auth
    r_http = run(["tshark", "-r", pcap_path, "-T", "fields", "-e", "http.authorization"], timeout=30)
    if r_http.ok() and r_http.stdout.strip():
        for line in r_http.stdout.splitlines():
            line = line.strip()
            if "Basic " in line:
                b64 = line.split("Basic ")[-1].strip()
                try:
                    decoded = base64.b64decode(b64).decode("latin-1", "replace")
                    creds.append(f"[HTTP-AUTH] {decoded}")
                    flags.extend(scan_text(decoded))
                except Exception:
                    pass

    return {"flags": flags, "creds": creds}


def extract_tcp_streams(pcap_path: str, max_streams: int = 8) -> dict[str, Any]:
    """Extract and follow top TCP conversation streams."""
    flags: list[dict[str, Any]] = []
    stream_summaries: list[str] = []
    if not have("tshark"):
        return {"flags": [], "streams": []}

    # Get unique stream indices
    r_idx = run(["tshark", "-r", pcap_path, "-T", "fields", "-e", "tcp.stream"], timeout=30)
    if not r_idx.ok() or not r_idx.stdout.strip():
        return {"flags": [], "streams": []}

    raw_indices = [ln.strip() for ln in r_idx.stdout.splitlines() if ln.strip().isdigit()]
    unique_indices = list(dict.fromkeys(raw_indices))[:max_streams]

    for s_idx in unique_indices:
        r_stream = run(["tshark", "-r", pcap_path, "-q", "-z", f"follow,tcp,ascii,{s_idx}"], timeout=30)
        if r_stream.ok() and r_stream.stdout.strip():
            content = r_stream.stdout
            s_flags = scan_text(content)
            if s_flags:
                for f in s_flags:
                    f["method"] = f"tcp-stream-{s_idx}"
                flags.extend(s_flags)
                stream_summaries.append(f"Stream #{s_idx} captured {len(s_flags)} flag candidate(s)")
            elif len(content) > 50:
                stream_summaries.append(f"Stream #{s_idx}: {len(content)} bytes followed")

    return {"flags": flags, "streams": stream_summaries}


def solve(pcap_path: str, workdir: str = "") -> dict[str, Any]:
    """Run comprehensive deep PCAP analysis."""
    icmp_res = extract_icmp_tunnel(pcap_path, workdir)
    cred_res = extract_credentials(pcap_path)
    tcp_res = extract_tcp_streams(pcap_path)

    all_flags = icmp_res.get("flags", []) + cred_res.get("flags", []) + tcp_res.get("flags", [])
    output_parts: list[str] = []

    if icmp_res.get("notes"):
        output_parts.extend(icmp_res["notes"])
    if cred_res.get("creds"):
        output_parts.extend(cred_res["creds"][:10])
    if tcp_res.get("streams"):
        output_parts.extend(tcp_res["streams"][:10])

    return {
        "step": "pcap-deep",
        "summary": f"Deep PCAP triage (ICMP tunnel, credentials, TCP streams)",
        "output": "\n".join(output_parts) if output_parts else "No hidden ICMP tunnel or cleartext credentials detected.",
        "flags": all_flags,
    }
