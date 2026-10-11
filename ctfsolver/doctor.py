"""`ctf --doctor` — is this box a *perfect* CTF environment?

Checks the whole stack KRYPT leans on and prints a readiness report: the CLI
tools per category, the rockyou wordlist, the local Ollama model, the frontier
API key, and the MCP engines (hexstrike-ai, ghidra, claude, agy). Nothing here
is required to run triage — it is a "what will make me stronger" map so you know
exactly what to install/enable before a competition.

Authorized CTF use only.
"""
from __future__ import annotations

import os
import shutil
import sys
import urllib.request

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_C = {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m", "d": "\033[90m",
      "b": "\033[1m", "x": "\033[0m"} if _TTY else dict.fromkeys("gyrdbx", "")

OK, WARN, MISS = f"{_C['g']}✓{_C['x']}", f"{_C['y']}○{_C['x']}", f"{_C['r']}✗{_C['x']}"

# category -> [(tool, why)]. First of a "a|b" group satisfies it.
TOOLS = {
    "core": [("file", "type detection"), ("strings", "ascii/utf16 sweep"),
             ("exiftool", "metadata"), ("binwalk", "embedded-file carving")],
    "crypto / encoding": [("hashid|hash-identifier", "hash id"),
                          ("john", "john the ripper"), ("openssl", "ciphers")],
    "stego": [("zsteg", "PNG/BMP LSB"), ("steghide", "JPEG/WAV stego"),
              ("stegseek", "fast steghide+rockyou"), ("foremost", "carving")],
    "archive / crack": [("7z|7za", "7-zip"), ("unzip", "zip"),
                        ("zip2john", "zip->john hash"), ("hashcat", "GPU crack")],
    "pcap / forensics": [("tshark", "packet analysis"), ("capinfos", "pcap info"),
                         ("vol|volatility3|volatility", "memory forensics")],
    "binary / rev": [("radare2|r2", "disassembly"), ("objdump", "disasm"),
                     ("readelf", "ELF headers"), ("nm", "symbols"),
                     ("checksec", "mitigations"), ("ROPgadget|ropper", "ROP")],
    "web / network": [("curl", "http"), ("nmap", "port scan"),
                      ("whatweb", "tech fingerprint"), ("sqlmap", "sqli")],
}

PY_MODULES = [("pwn", "pwntools (pwn scaffolds)"), ("angr", "symbolic exec (rev)")]

ROCKYOU = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    os.path.expanduser("~/wordlists/rockyou.txt"),
]


def _have(spec: str) -> bool:
    return any(shutil.which(t) for t in spec.split("|"))


def _http_ok(url: str, timeout: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status < 500
    except Exception:
        return False


def _py_module(name: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def run() -> int:
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, ROOT)
    lines = [f"{_C['b']}KRYPT · CTF ENVIRONMENT DOCTOR{_C['x']}", ""]
    have = miss = 0

    for cat, items in TOOLS.items():
        lines.append(f"{_C['b']}{cat}{_C['x']}")
        for spec, why in items:
            ok = _have(spec)
            have += ok
            miss += not ok
            name = spec.replace("|", " / ")
            mark = OK if ok else MISS
            pad = " " * max(2, 24 - len(name))
            lines.append(f"  {mark} {name}{pad}{_C['d']}{why}{_C['x']}")
        lines.append("")

    # python solver libs
    lines.append(f"{_C['b']}python solver libs{_C['x']}")
    for mod, why in PY_MODULES:
        ok = _py_module(mod)
        pad = " " * max(2, 24 - len(mod))
        lines.append(f"  {OK if ok else WARN} {mod}{pad}{_C['d']}{why}{_C['x']}")
    lines.append("")

    # rockyou wordlist (powers every auto-crack)
    rk = next((p for p in ROCKYOU if os.path.exists(p)), None)
    lines.append(f"{_C['b']}wordlist{_C['x']}")
    lines.append(f"  {OK if rk else WARN} rockyou               "
                 f"{_C['d']}{rk or 'not found — put it at /usr/share/wordlists/rockyou.txt'}{_C['x']}")
    lines.append("")

    # engines
    lines.append(f"{_C['b']}engines{_C['x']}")
    try:
        from ctfsolver import ai, ai_api, agents
        local = ai.available()
        model = ai.default_model() if local else "—"
        lines.append(f"  {OK if local else WARN} LOCAL · GPU          "
                     f"{_C['d']}{('ollama: ' + model) if local else 'ollama not reachable (free offline engine)'}{_C['x']}")
        api = ai_api.available()
        api_msg = ("frontier: " + ai_api.DEFAULT_MODEL + " — the hard-challenge brain"
                   if api else
                   'no key — add {"anthropic_api_key": "sk-ant-..."} to '
                   "~/.config/krypt/config.json")
        lines.append(f"  {OK if api else WARN} CLAUDE · API         "
                     f"{_C['d']}{api_msg}{_C['x']}")
        eng = agents.available()
        lines.append(f"  {OK if eng.get('claude') else WARN} CLAUDE · MCP         "
                     f"{_C['d']}{'claude CLI (drives ghidra/hexstrike, scoped)' if eng.get('claude') else 'claude CLI not on PATH'}{_C['x']}")
        lines.append(f"  {OK if eng.get('agy') else WARN} AGY · MCP            "
                     f"{_C['d']}{'agy CLI (hand-off by default)' if eng.get('agy') else 'agy CLI not on PATH'}{_C['x']}")
    except Exception as e:
        lines.append(f"  {MISS} engine probe failed: {e}")

    # MCP tool servers
    hex_ok = _http_ok("http://127.0.0.1:8888/health") or _http_ok("http://127.0.0.1:8888/")
    ghidra = shutil.which("pyghidra-mcp") or os.path.exists(
        os.path.expanduser("~/tools/ghidra-mcp-env/bin/pyghidra-mcp"))
    lines.append(f"  {OK if hex_ok else WARN} hexstrike-ai (MCP)   "
                 f"{_C['d']}{'up on :8888 (150+ tools)' if hex_ok else 'server not on :8888 — start hexstrike_server.py'}{_C['x']}")
    lines.append(f"  {OK if ghidra else WARN} ghidra (MCP)         "
                 f"{_C['d']}{'pyghidra-mcp present (rev decompile)' if ghidra else 'pyghidra-mcp not found'}{_C['x']}")
    lines.append("")

    # verdict
    total = have + miss
    if miss == 0:
        verdict = f"{_C['g']}{_C['b']}PERFECT — every core tool present.{_C['x']}"
    elif miss <= 3:
        verdict = f"{_C['y']}{_C['b']}STRONG — {have}/{total} core tools; {miss} missing (optional).{_C['x']}"
    else:
        verdict = f"{_C['y']}{_C['b']}OK — {have}/{total} core tools; install the ✗ ones for full power.{_C['x']}"
    lines.append(verdict)
    lines.append(f"{_C['d']}Triage runs regardless; missing items only limit specific categories.{_C['x']}")
    print("\n".join(lines))
    return 0 if miss == 0 else 0  # advisory only — never a hard failure


if __name__ == "__main__":
    raise SystemExit(run())
