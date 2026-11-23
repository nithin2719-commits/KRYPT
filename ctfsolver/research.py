"""Dynamic Tools Research & Discovery Engine for KRYPT.

Researches, catalogs, and discovers all installed CTF tools, libraries, MCP servers,
and repositories across the user's environment:
  - ~/Tools & ~/Tools/venv (pwntools, angr, z3, pycryptodome, volatility3, gmpy2, scapy)
  - ~/tools/hexstrike-ai (150+ HexStrike AI MCP security tools)
  - ~/tools/pwndbg (GDB plugin for binary exploitation)
  - ~/tools/RsaCtfTool (automated RSA attack suite)
  - ~/tools/GHunt (Google OSINT)
  - ~/strix (autonomous pentesting agent framework)
  - ~/Public/EvidenceFlow (digital forensics workbench)
  - ~/Projects/Blackarch_Toolbox (pentest utilities)
  - Wordlists (/usr/share/wordlists/rockyou.txt)
  - System binaries (ghidra, r2, ROPgadget, ropper, checksec, tshark, binwalk, sqlmap, etc.)
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import Any, Dict, List, Optional

_TOOLS_VENV_PY = os.path.expanduser("~/Tools/venv/bin/python3")
TOOLS_PYTHON = _TOOLS_VENV_PY if (os.path.exists(_TOOLS_VENV_PY) and os.access(_TOOLS_VENV_PY, os.X_OK)) else (sys.executable or "python3")

LOCAL_REPOS = {
    "hexstrike-ai": os.path.expanduser("~/tools/hexstrike-ai"),
    "pwndbg": os.path.expanduser("~/tools/pwndbg"),
    "RsaCtfTool": os.path.expanduser("~/tools/RsaCtfTool"),
    "ghunt": os.path.expanduser("~/tools/GHunt"),
    "strix": os.path.expanduser("~/strix"),
    "evidenceflow": os.path.expanduser("~/Public/EvidenceFlow"),
    "blackarch-toolbox": os.path.expanduser("~/Projects/Blackarch_Toolbox"),
    "agent-team": os.path.expanduser("~/agent-team"),
}

TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    # PWN
    "checksec": {"category": "pwn", "type": "cli", "bin": "checksec", "desc": "Binary mitigations (Canary, NX, PIE, RELRO)"},
    "ROPgadget": {"category": "pwn", "type": "cli", "bin": "ROPgadget", "desc": "ROP gadget discovery across binary"},
    "ropper": {"category": "pwn", "type": "cli", "bin": "ropper", "desc": "Fast ROP gadget finder"},
    "pwntools": {"category": "pwn", "type": "python", "module": "pwn", "desc": "CTF exploit development framework"},
    "pwndbg": {"category": "pwn", "type": "repo", "path": LOCAL_REPOS["pwndbg"], "desc": "GDB exploit development extension"},
    "one_gadget": {"category": "pwn", "type": "cli", "bin": "one_gadget", "desc": "libc execve('/bin/sh') gadget finder"},
    "pwninit": {"category": "pwn", "type": "cli", "bin": "pwninit", "desc": "Automate CTF pwn challenge setup & ld/libc patching"},

    # REVERSE ENGINEERING
    "ghidra": {"category": "rev", "type": "mcp", "bin": "pyghidra-mcp", "desc": "Ghidra decompiler MCP server"},
    "radare2": {"category": "rev", "type": "cli", "bin": "r2", "desc": "Disassembly and binary analysis framework"},
    "angr": {"category": "rev", "type": "python", "module": "angr", "desc": "Symbolic execution for crackmes & path constraint solving"},
    "readelf": {"category": "rev", "type": "cli", "bin": "readelf", "desc": "ELF headers and section inspector"},
    "nm": {"category": "rev", "type": "cli", "bin": "nm", "desc": "Binary symbol and function listing"},
    "objdump": {"category": "rev", "type": "cli", "bin": "objdump", "desc": "Disassembler and section inspector"},
    "strings": {"category": "rev", "type": "cli", "bin": "strings", "desc": "ASCII & UTF-16 text search"},

    # CRYPTOGRAPHY
    "RsaCtfTool": {"category": "crypto", "type": "repo", "path": LOCAL_REPOS["RsaCtfTool"], "desc": "Attacks on weak RSA keys (Wiener, Fermat, Boneh-Durfee, etc.)"},
    "john": {"category": "crypto", "type": "cli", "bin": "john", "desc": "John the Ripper password cracker"},
    "hashcat": {"category": "crypto", "type": "cli", "bin": "hashcat", "desc": "Advanced GPU/CPU hash cracker"},
    "rockyou": {"category": "crypto", "type": "wordlist", "path": "/usr/share/wordlists/rockyou.txt", "desc": "RockYou 14M wordlist"},
    "openssl": {"category": "crypto", "type": "cli", "bin": "openssl", "desc": "Cryptographic toolkit and cipher tests"},
    "pycryptodome": {"category": "crypto", "type": "python", "module": "Crypto", "desc": "Cryptographic primitives in Python"},
    "z3": {"category": "crypto", "type": "python", "module": "z3", "desc": "Z3 SMT solver for mathematical constraint recovery"},
    "gmpy2": {"category": "crypto", "type": "python", "module": "gmpy2", "desc": "High-performance multiprecision arithmetic for RSA/ECC"},

    # WEB EXPLOITATION
    "sqlmap": {"category": "web", "type": "cli", "bin": "sqlmap", "desc": "Automated SQL injection and database takeover"},
    "ffuf": {"category": "web", "type": "cli", "bin": "ffuf", "desc": "Fast web fuzzer"},
    "feroxbuster": {"category": "web", "type": "cli", "bin": "feroxbuster", "desc": "Recursive content discovery fuzzer"},
    "katana": {"category": "web", "type": "cli", "bin": "katana", "desc": "Next-gen web crawler and endpoint spider"},
    "dalfox": {"category": "web", "type": "cli", "bin": "dalfox", "desc": "Parameter XSS scanner and verifier"},
    "arjun": {"category": "web", "type": "cli", "bin": "arjun", "desc": "HTTP parameter discovery suite"},
    "curl": {"category": "web", "type": "cli", "bin": "curl", "desc": "Command line HTTP client"},

    # FORENSICS & STEGANOGRAPHY
    "volatility3": {"category": "forensics", "type": "python", "module": "volatility3", "desc": "Advanced memory forensics framework"},
    "tshark": {"category": "forensics", "type": "cli", "bin": "tshark", "desc": "Terminal network packet analyzer"},
    "binwalk": {"category": "forensics", "type": "cli", "bin": "binwalk", "desc": "Firmware and embedded artifact extraction"},
    "foremost": {"category": "forensics", "type": "cli", "bin": "foremost", "desc": "File carving by file headers and trailers"},
    "exiftool": {"category": "forensics", "type": "cli", "bin": "exiftool", "desc": "Image/PDF/file metadata reader and editor"},
    "zsteg": {"category": "forensics", "type": "cli", "bin": "zsteg", "desc": "PNG & BMP steganography / LSB detector"},
    "steghide": {"category": "forensics", "type": "cli", "bin": "steghide", "desc": "JPEG/WAV steganography extraction tool"},
    "stegseek": {"category": "forensics", "type": "cli", "bin": "stegseek", "desc": "Lightning-fast steghide cracker with rockyou"},
    "evidenceflow": {"category": "forensics", "type": "repo", "path": LOCAL_REPOS["evidenceflow"], "desc": "Digital Forensics Artifact Workbench"},

    # OSINT & RECON
    "ghunt": {"category": "osint", "type": "repo", "path": LOCAL_REPOS["ghunt"], "desc": "Google account OSINT investigation suite"},
    "sherlock": {"category": "osint", "type": "cli", "bin": "sherlock", "desc": "Hunt social media accounts by username"},
    "theharvester": {"category": "osint", "type": "cli", "bin": "theHarvester", "desc": "E-mails, subdomains and names harvester"},
    "subfinder": {"category": "osint", "type": "cli", "bin": "subfinder", "desc": "Fast passive subdomain discovery"},
    "nmap": {"category": "osint", "type": "cli", "bin": "nmap", "desc": "Network exploration and port scanner"},
}


class ToolsResearchEngine:
    """Discovers, validates, and recommends security tools and pipelines."""

    def __init__(self):
        self._cache: Dict[str, bool] = {}

    def is_available(self, tool_name: str) -> bool:
        """Verify if a tool is operational."""
        if tool_name in self._cache:
            return self._cache[tool_name]

        meta = TOOL_REGISTRY.get(tool_name)
        if not meta:
            # Fallback to general PATH search
            avail = shutil.which(tool_name) is not None
            self._cache[tool_name] = avail
            return avail

        t_type = meta["type"]
        if t_type == "cli":
            avail = shutil.which(meta["bin"]) is not None
        elif t_type == "python":
            avail = self._check_python_module(meta["module"])
        elif t_type in ("repo", "wordlist"):
            avail = os.path.exists(meta["path"])
        elif t_type == "mcp":
            avail = (shutil.which(meta["bin"]) is not None) or os.path.exists(
                os.path.expanduser("~/tools/ghidra-mcp-env/bin/pyghidra-mcp")
            )
        else:
            avail = False

        self._cache[tool_name] = avail
        return avail

    def _check_python_module(self, module_name: str) -> bool:
        # Check in designated Tools virtualenv first
        if os.path.exists(_TOOLS_VENV_PY):
            ret = os.system(f"{_TOOLS_VENV_PY} -c 'import {module_name}' >/dev/null 2>&1")
            if ret == 0:
                return True
        # Check system python
        try:
            import importlib.util
            return importlib.util.find_spec(module_name) is not None
        except Exception:
            return False

    def inventory(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group available tools by category."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for name, meta in TOOL_REGISTRY.items():
            cat = meta["category"]
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append({
                "name": name,
                "desc": meta["desc"],
                "type": meta["type"],
                "available": self.is_available(name),
            })
        return grouped

    def recommend_pipeline(self, category: str) -> List[str]:
        """Return prioritized list of available tools for a challenge category."""
        cat = (category or "auto").lower()
        if cat == "auto":
            return ["strings", "file", "binwalk", "exiftool"]

        items = [name for name, meta in TOOL_REGISTRY.items() if meta["category"] == cat]
        available_tools = [name for name in items if self.is_available(name)]
        return available_tools


# Global singleton access
_RESEARCH_ENGINE: Optional[ToolsResearchEngine] = None


def get_research_engine() -> ToolsResearchEngine:
    global _RESEARCH_ENGINE
    if _RESEARCH_ENGINE is None:
        _RESEARCH_ENGINE = ToolsResearchEngine()
    return _RESEARCH_ENGINE
