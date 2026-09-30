"""CTF domain map: each category → the right local tools, MCP tools, and
/cybersec-ctf skills, plus a "common" (no-file) text pipeline for challenges
that are just a prompt (osint / misc / a pasted cipher).

Used to (a) show the operator which arsenal fits, and (b) build a category-tuned
command for the CLAUDE/AGY deep engines so they reach for the correct tools fast.
"""
from __future__ import annotations

from .decoders import magic
from .flags import scan_text

# name -> {label, local (installed BlackArch tools), mcp (hexstrike/ghidra tool
# names), skills (/cybersec-ctf), hint}
CATEGORIES: dict[str, dict] = {
    "auto": {"label": "AUTO", "local": ["file", "binwalk", "strings", "exiftool"],
             "mcp": ["hexstrike: intelligent_smart_scan, select_optimal_tools_ai"],
             "skills": ["cybersec-ctf"],
             "hint": "Auto-detects the category from the file/target."},
    "pwn": {"label": "PWN",
            "local": ["pwntools", "gdb+gef", "ropper", "ROPgadget", "one_gadget",
                      "checksec", "angr", "pwninit"],
            "mcp": ["hexstrike: pwntools_exploit, gdb_peda_debug, ropgadget_search, "
                    "ropper_gadget_search, one_gadget_search, checksec_analyze, "
                    "angr_symbolic_execution, pwninit_setup, libc_database_lookup",
                    "ghidra: import_binary → decompile_function"],
            "skills": ["performing-binary-exploitation-analysis",
                       "analyzing-heap-spray-exploitation"],
            "hint": "Give the ELF (and host:port for remote). checksec → leak → ROP/ret2libc."},
    "rev": {"label": "REV",
            "local": ["ghidra", "radare2", "objdump", "strings", "ltrace", "strace", "angr"],
            "mcp": ["ghidra: import_binary, decompile_function, disassemble, search_strings, list_xrefs",
                    "hexstrike: ghidra_analysis, radare2_analyze, angr_symbolic_execution, binwalk_analyze"],
            "skills": ["reverse-engineering-malware-with-ghidra"],
            "hint": "Decompile main; watch for check/compare routines and embedded keys."},
    "web": {"label": "WEB",
            "local": ["curl", "ffuf", "feroxbuster", "gobuster", "sqlmap", "nuclei",
                      "nikto", "wpscan", "dalfox", "wfuzz", "httpx", "katana"],
            "mcp": ["hexstrike: sqlmap_scan, ffuf_scan, feroxbuster_scan, nuclei_scan, "
                    "nikto_scan, wpscan_analyze, dalfox_xss_scan, wfuzz_scan, "
                    "httpx_probe, katana_crawl, arjun_parameter_discovery, "
                    "jwt_analyzer, graphql_scanner, http_repeater"],
            "skills": ["exploiting-sql-injection-vulnerabilities",
                       "exploiting-server-side-request-forgery",
                       "exploiting-jwt-algorithm-confusion-attack",
                       "exploiting-insecure-deserialization",
                       "exploiting-template-injection-vulnerabilities"],
            "hint": "Give the URL. Enumerate paths, then match the bug class to the skill."},
    "crypto": {"label": "CRYPTO",
               "local": ["magic decoder", "rsactftool", "sage", "openssl", "hashcat", "john"],
               "mcp": ["hexstrike: hashcat_crack, john_crack, hashpump_attack"],
               "skills": ["performing-cryptographic-audit-of-application"],
               "hint": "Paste the ciphertext in the briefing — the magic decoder + XOR brute run automatically."},
    "forensics": {"label": "FORENSICS",
                  "local": ["volatility3/vol", "binwalk", "foremost", "scalpel",
                            "bulk_extractor", "testdisk", "photorec", "tshark",
                            "tcpdump", "networkminer", "exiftool"],
                  "mcp": ["hexstrike: volatility3_analyze, volatility_analyze, "
                          "binwalk_analyze, foremost_carving, exiftool_extract"],
                  "skills": ["performing-memory-forensics-with-volatility3",
                             "performing-disk-forensics-investigation",
                             "analyzing-network-traffic-with-wireshark"],
                  "hint": "Drop the memory/disk image or pcap. Timeline + carve + strings."},
    "stego": {"label": "STEGO",
              "local": ["zsteg", "steghide", "stegseek", "stegsolve", "outguess",
                        "exiftool", "binwalk"],
              "mcp": ["hexstrike: steghide_analysis, binwalk_analyze, exiftool_extract, foremost_carving"],
              "skills": ["performing-steganography-detection"],
              "hint": "Drop the image/audio. LSB, appended data, and rockyou steghide run automatically."},
    "osint": {"label": "OSINT",
              "local": ["theharvester", "sherlock", "maigret", "holehe", "recon-ng",
                        "amass", "subfinder", "dnsrecon", "whois"],
              "mcp": ["hexstrike: amass_scan, subfinder_scan, dnsenum_scan, "
                      "waybackurls_discovery, gau_discovery, paramspider_discovery"],
              "skills": ["bugbounty-osint-gathering",
                         "analyzing-certificate-transparency-for-phishing"],
              "hint": "No file needed — put the name/handle/domain in the briefing box."},
    "network": {"label": "NETWORK",
                "local": ["nmap", "masscan", "rustscan", "netexec", "crackmapexec",
                          "responder", "tshark"],
                "mcp": ["hexstrike: nmap_scan, masscan_high_speed, rustscan_fast_scan, "
                        "netexec_scan, responder_credential_harvest"],
                "skills": ["performing-network-forensics-with-wireshark"],
                "hint": "Give host:port or a pcap. Enumerate services / follow streams."},
    "misc": {"label": "MISC",
             "local": ["magic decoder", "strings", "binwalk", "exiftool", "python"],
             "mcp": ["hexstrike: intelligent_smart_scan, execute_command"],
             "skills": ["cybersec-ctf"],
             "hint": "Anything goes — paste text in the briefing or drop a file."},
}


def toolset(category: str) -> dict:
    return CATEGORIES.get((category or "auto").lower(), CATEGORIES["auto"])


def toolset_step(category: str) -> dict:
    """A results-log entry naming the arsenal for the chosen domain."""
    t = toolset(category)
    body = (f"local : {', '.join(t['local'])}\n"
            f"mcp   : {' | '.join(t['mcp'])}\n"
            f"skills: {', '.join(t['skills'])}\n"
            f"hint  : {t['hint']}")
    return {"step": f"arsenal[{t['label']}]",
            "summary": "tools & skills mapped for this domain",
            "output": body, "flags": []}


def text_triage(text: str) -> list[dict]:
    """Common/no-file pipeline: a pasted challenge is swept + magic-decoded."""
    steps: list[dict] = []
    fl = scan_text(text)
    steps.append({"step": "briefing-scan",
                  "summary": f"{len(fl)} flag candidate(s) in the text",
                  "output": text[:2000], "flags": fl})
    m = magic(text.encode("utf-8", "replace"))
    if m["found"]:
        steps.append({"step": "magic-decode",
                      "summary": "flag via decode chain: " + " -> ".join(m["path"]),
                      "output": m["sample"], "flags": m["flags"]})
    elif m["path"]:
        steps.append({"step": "magic-decode",
                      "summary": "no flag; deepest chain: " + " -> ".join(m["path"]),
                      "output": "", "flags": []})
    return steps
