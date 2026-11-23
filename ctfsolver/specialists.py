"""Specialized Domain Agents for KRYPT.

Provides dedicated CTF specialist agents tailored for each competition category:
  - PwnSpecialist: Binary exploitation, ROP gadgets, format strings, ret2win/ret2libc, shellcoding
  - RevSpecialist: Reverse engineering, crackmes, Ghidra decompilation, radare2, angr symbolic exploration
  - CryptoSpecialist: RSA parameter recovery (RsaCtfTool), hash cracking (rockyou), ciphers, esolangs
  - WebSpecialist: Web application penetration, SQLi, SSTI, SSRF, JWT analyzer, path fuzzing, API schemas
  - ForensicsSpecialist: Memory dumps (volatility3), PCAP stream reconstruction, file carving, steganography
  - OsintSpecialist: Identity tracking, username hunting (sherlock/maigret), email footprints, domain mapping
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from .agents import run as agent_run, command_for as agent_cmd, _fmt_hint
from .research import get_research_engine

SPECIALISTS_MAP: Dict[str, Dict[str, Any]] = {
    "pwn": {
        "title": "PWN Exploitation Specialist",
        "description": "Exploits memory corruption, stack/heap overflows, format strings, and constructs ROP/ret2libc chains.",
        "skills": ["performing-binary-exploitation-analysis", "analyzing-heap-spray-exploitation"],
        "recommended_mcp": [
            "mcp__hexstrike-ai__pwntools_exploit",
            "mcp__hexstrike-ai__gdb_analyze",
            "mcp__hexstrike-ai__ropgadget_search",
            "mcp__hexstrike-ai__ropper_gadget_search",
            "mcp__hexstrike-ai__one_gadget_search",
            "mcp__hexstrike-ai__checksec_analyze",
            "mcp__hexstrike-ai__libc_database_lookup",
            "mcp__hexstrike-ai__angr_symbolic_execution",
        ],
        "directives": (
            "PWN OPERATING INSTRUCTIONS:\n"
            "1. Inspect checksec mitigations (Canary, NX, PIE, RELRO).\n"
            "2. Identify the vulnerability primitive: buffer overflow offset via cyclic pattern, format string leak/write, or heap UAF/double-free.\n"
            "3. If ret2win is available, compute the RIP offset and jump to win().\n"
            "4. If NX is enabled without Canary, build a ROP chain (puts/printf leak libc -> ret2libc system('/bin/sh')).\n"
            "5. Execute exploit locally or against remote target to obtain shell and read the flag."
        ),
    },
    "rev": {
        "title": "Reverse Engineering Specialist",
        "description": "Decompiles binaries, traces data flow, solves crackmes, defeats anti-debugging, and recovers algorithmic keys.",
        "skills": ["reverse-engineering-malware-with-ghidra"],
        "recommended_mcp": [
            "mcp__ghidra__import_binary",
            "mcp__ghidra__decompile_function",
            "mcp__ghidra__list_functions",
            "mcp__ghidra__list_xrefs",
            "mcp__ghidra__search_strings",
            "mcp__hexstrike-ai__radare2_analyze",
            "mcp__hexstrike-ai__angr_symbolic_execution",
            "mcp__hexstrike-ai__binwalk_analyze",
        ],
        "directives": (
            "REVERSE ENGINEERING OPERATING INSTRUCTIONS:\n"
            "1. Decompile main() and key validation routines using Ghidra / radare2.\n"
            "2. Trace user input to comparison checks; isolate comparison arrays, XOR masks, or s-boxes.\n"
            "3. If logic is a mathematical constraint system, write a Z3 script in python (~/Tools/venv/bin/python3) to invert it.\n"
            "4. If binary is a crackme, run angr symbolic exploration to find the winning state automatically."
        ),
    },
    "crypto": {
        "title": "Cryptography Specialist",
        "description": "Breaks weak RSA keys, cracks hashes with wordlists, decodes complex multi-layer ciphers and esolangs.",
        "skills": ["performing-cryptographic-audit-of-application"],
        "recommended_mcp": [
            "mcp__hexstrike-ai__john_crack",
            "mcp__hexstrike-ai__hashcat_crack",
            "mcp__hexstrike-ai__hashpump_attack",
        ],
        "directives": (
            "CRYPTOGRAPHY OPERATING INSTRUCTIONS:\n"
            "1. Identify the cipher type: classical (Caesar, Affine, Vigenère crib, Baconian, Braille), hash, or asymmetric.\n"
            "2. If RSA parameters (n, e, c) are present: check for small e (cube root), small n (factorization/factordb), Wiener (large e / small d), Fermat (close primes), or common modulus.\n"
            "3. If hashes or locked archives: crack with rockyou.txt using john or hashcat.\n"
            "4. For XOR cipher: brute-force single-byte keys or use known flag wrapper as crib."
        ),
    },
    "web": {
        "title": "Web Application Pentest Specialist",
        "description": "Uncovers and exploits SQLi, SSTI, SSRF, JWT flaws, IDOR, GraphQL vulnerabilities, and bypasses authentication.",
        "skills": [
            "exploiting-sql-injection-vulnerabilities",
            "exploiting-server-side-request-forgery",
            "exploiting-jwt-algorithm-confusion-attack",
            "exploiting-template-injection-vulnerabilities",
            "exploiting-insecure-deserialization",
        ],
        "recommended_mcp": [
            "mcp__hexstrike-ai__sqlmap_scan",
            "mcp__hexstrike-ai__jwt_analyzer",
            "mcp__hexstrike-ai__ffuf_scan",
            "mcp__hexstrike-ai__feroxbuster_scan",
            "mcp__hexstrike-ai__katana_crawl",
            "mcp__hexstrike-ai__arjun_parameter_discovery",
            "mcp__hexstrike-ai__graphql_scanner",
            "mcp__hexstrike-ai__http_repeater",
        ],
        "directives": (
            "WEB EXPLOITATION OPERATING INSTRUCTIONS:\n"
            "1. Recon: inspect HTML comments, robots.txt, /.well-known/security.txt, /.git leak, cookies, and headers.\n"
            "2. Test authentication: check JWT header/payload, none-algorithm, weak secrets, or SQLi in login form (' or 1=1--).\n"
            "3. Inspect parameters: test SSTI ({{7*7}}, ${7*7}), command injection (; id, | cat /flag), SSRF, and LFI (/etc/passwd, /flag.txt).\n"
            "4. Extract the flag from database, environment variables, or admin response."
        ),
    },
    "forensics": {
        "title": "Digital Forensics & Steganography Specialist",
        "description": "Carves hidden data, analyzes PCAP streams, inspects volatile memory dumps, and extracts stego layers.",
        "skills": ["performing-memory-forensics-with-volatility3"],
        "recommended_mcp": [
            "mcp__hexstrike-ai__volatility3_analyze",
            "mcp__hexstrike-ai__volatility_analyze",
            "mcp__hexstrike-ai__binwalk_analyze",
            "mcp__hexstrike-ai__foremost_carving",
            "mcp__hexstrike-ai__exiftool_extract",
            "mcp__hexstrike-ai__steghide_analysis",
        ],
        "directives": (
            "FORENSICS & STEGO OPERATING INSTRUCTIONS:\n"
            "1. Metadata & Trailer: inspect exiftool metadata and check for data appended past image EOF (IEND/FF D9/3B).\n"
            "2. Steganography: run zsteg on PNG/BMP, steghide/stegseek with rockyou on JPEG/WAV.\n"
            "3. PCAP: analyze with tshark — filter DNS queries for exfiltration, reconstruct HTTP objects, inspect raw TCP streams.\n"
            "4. Memory Dump: run volatility3 (windows.pslist, windows.cmdline, windows.filescan, linux.bash) to recover processes, injected code, and flag artifacts."
        ),
    },
    "osint": {
        "title": "OSINT & Reconnaissance Specialist",
        "description": "Correlates entities across social media platforms, searches breached credentials, and maps domain footprints.",
        "skills": [],
        "recommended_mcp": [
            "mcp__hexstrike-ai__amass_scan",
            "mcp__hexstrike-ai__subfinder_scan",
            "mcp__hexstrike-ai__dnsenum_scan",
        ],
        "directives": (
            "OSINT OPERATING INSTRUCTIONS:\n"
            "1. Extract all target entities: usernames, emails, domains, phone numbers, and handles.\n"
            "2. Run username reconnaissance via sherlock/maigret and email footprinting via holehe.\n"
            "3. Inspect discovered profiles for posted flags, pastebin links, commit messages, or hidden comments."
        ),
    },
}


class SpecialistAgent:
    """Invokes a domain-focused specialist agent equipped with targeted directives and tools."""

    def __init__(self, category: str):
        self.category = (category or "auto").lower()
        self.meta = SPECIALISTS_MAP.get(self.category, SPECIALISTS_MAP["rev"])
        self.title = self.meta["title"]
        self.engine_research = get_research_engine()

    def build_specialist_prompt(self, target: str, briefing: str, evidence: str, flag_format: str = "") -> str:
        fmt_clause = _fmt_hint() if not flag_format else f" (regex: {flag_format})"
        tools_available = self.engine_research.recommend_pipeline(self.category)

        prompt = (
            f"You are the {self.title} in the KRYPT autonomous CTF solver swarm.\n"
            f"Role: {self.meta['description']}\n\n"
            f"Category: {self.category.upper()}. Target: {target or '(fileless / prompt challenge)'}.\n"
            f"{('Briefing: ' + briefing.strip() + chr(10)) if briefing else ''}\n"
            f"{self.meta['directives']}\n\n"
            f"Tools & MCP Arsenal:\n"
            f"• Available CLI/Python Tools: {', '.join(tools_available)}\n"
            f"• Pre-approved MCP Tools: {', '.join(self.meta['recommended_mcp'])}\n"
            f"• Python Environment: ~/Tools/venv/bin/python3 (equipped with pwntools, z3, angr, pycryptodome, volatility3, gmpy2, scapy)\n\n"
            f"Automated Triage & Pre-solve Evidence:\n{evidence[:6000]}\n\n"
            "OUTPUT PROTOCOL:\n"
            "Focus purely on capturing the flag. Verify it matches the target format"
            f"{fmt_clause}.\n"
            "Output strictly:\n"
            "  FLAG: <exact flag>\n"
            "  METHOD: 2-4 sentences detailing the decisive exploit step.\n"
            "  EVIDENCE: exact proof string, output, or offset."
        )
        return prompt

    def solve(
        self,
        target: str,
        briefing: str,
        evidence: str,
        workdir: str,
        provider: str = "claude",
        flag_format: str = "",
        timeout: int = 300,
    ) -> dict:
        """Execute the specialist agent against the challenge."""
        from gui import server as gui_server

        # Update environment flag format if given
        old_fmt = os.environ.get("CTF_FLAG_FORMAT")
        try:
            if flag_format:
                os.environ["CTF_FLAG_FORMAT"] = flag_format

            # If provider is 'all', race specialists
            if provider == "all":
                return gui_server.escalate(
                    target=target,
                    description=briefing,
                    category=self.category,
                    flag_format=flag_format,
                )

            return gui_server.deep(
                target=target,
                description=briefing,
                provider=provider,
                category=self.category,
                flag_format=flag_format,
            )
        finally:
            if flag_format:
                if old_fmt is not None:
                    os.environ["CTF_FLAG_FORMAT"] = old_fmt
                else:
                    os.environ.pop("CTF_FLAG_FORMAT", None)


def get_specialist(category: str) -> SpecialistAgent:
    """Factory function for specialist agents."""
    return SpecialistAgent(category)
