# Changelog

## v1.5
- **Full MCP Arsenal & Port Migration**:
  - Unlocked **all 150+ HexStrike AI security tools** (Web, PWN, Reverse Engineering, Forensics, Steganography, Cryptography, and Threat Intelligence) and **Ghidra MCP** in the autonomous agent allowlist.
  - Relocated HexStrike AI server to port `8889` to prevent SearXNG collision, and updated `doctor.py` to verify server readiness and active tool availability.
  - Added comprehensive MCP category directives and pre-approved tool guidance to the solver agent system prompt.
- **CLI Autonomous Agent Escalation (`--agent`)**:
  - Added `--agent {claude,agy,all,api}` directly to the `./ctf` CLI to escalate to autonomous agents from the command line.
  - Added `--briefing` and `--flag-format` flags to the CLI for providing contextual descriptions, challenge text, and target formats.
  - Supported **Fileless Briefing Mode**: `./ctf --briefing "..."` now runs text, crypto, URL, and netcat triage pipelines directly without requiring a local file.

- **Expanded Crypto & Ciphers**:
  - **Affine cipher brute-force**: tests all 312 possible keys (`(a, b)` pairs with `gcd(a, 26) == 1`) in under a millisecond.
  - **Vigenère known-crib recovery**: mathematically derives repeating alphabetic keys from known flag wrappers (`flag{`, `picoCTF{`, or event format) and verifies cross-crib consistency with zero false positives.
  - **Baconian cipher decoder**: decodes 5-bit character groups (A/B and 0/1 binary) supporting both 24-letter (I=J, U=V) and full 26-letter alphabets.
  - **Base62 & Braille**: added Base62 (`0-9A-Za-z`) decode and unicode Braille alphabet decoding (`\u2800`–`\u28FF`) directly into the magic BFS.
- **Esolangs (Ook! + Brainfuck)**:
  - Added an **Ook!** translator directly into `brainfuck.py` and auto-detection in crypto triage to execute Ook! programs forward, reversed, and mirrored.
- **Forensics & Stego**:
  - **PCAP DNS exfiltration**: sweeps DNS query names, unpacks encoded subdomain prefixes, and flags exfiltrated credentials and tokens.
  - **HTTP object carving**: extracts files transferred over HTTP into artifacts for recursive hunt.
  - **Image trailer overlay carving**: automatically carves hidden data appended past image EOF markers (`IEND` in PNG, `FF D9` in JPEG, `3B` in GIF) into artifacts.
- **Web Depth**:
  - **JWT auto-unpacking**: automatically decodes base64url header and payload JSON in discovered tokens and sweeps claims for flags.
  - Added `/.well-known/security.txt` to common CTF discovery paths.
- **Branded Markdown writeups**:
  - Markdown writeup exports now feature the official KRYPT masthead and formatted badge mirroring the PDF styling.

## v1.3
- **Instant path gets the full decoder**: the "paste it / drop it and capture
  now" sweep (`instant_scan`, used by WATCH and every file's triage) no longer
  stops at one level of base64/hex — it now runs KRYPT's recursive **magic**
  decoder (base64/32/58/85, ascii85, hex, rot13/47, atbash, reverse, morse,
  binary, decimal, URL, gzip/zlib, single-byte & crib XOR, all 25 Caesar
  shifts) **chained**, so a `base64 → hex → rot13` flag is caught on drop in
  ~20 ms. Gated to text-ish input and capped so it stays instant; strict flag
  matching keeps false positives at zero.
- **Decoder hardening (perf/robustness)**: three unbounded-work landmines that
  could stall the tool for minutes on a large or hostile input are now bounded —
  (1) `magic()` only *expands* nodes under a size cap (large blobs are still
  flag-checked, never re-expanded), (2) base58's O(n²) big-int decode rejects
  over-length runs, and (3) the flag scanner skips its two low-confidence
  heuristic tiers above 1 MB and short-circuits brace-less input. A 1 MB blob
  that took minutes in the BFS now returns in ~17 ms; an 8 MB file scans in
  well under a second. Regression tests pin all three.

## v1.2
- **Frontier engine → Opus 5.5**: the CLAUDE·API engine now defaults to
  `claude-opus-5-5` (strongest for hard CTF; overridable via `$KRYPT_API_MODEL`),
  with current-family pricing for accurate local spend estimates.
- **`--doctor`**: `./ctf --doctor` reports CTF-environment readiness — per-category
  CLI tools, rockyou, the local model, the frontier API key, and the MCP engines
  (hexstrike-ai, ghidra, claude, agy) — with a PERFECT/STRONG/OK verdict.
- **Parallel engine racing** (ALL·AUTO): free engines still gate the paid ones
  (deterministic triage then the offline local model short-circuit on a flag),
  but the paid AI engines — CLAUDE·MCP, CLAUDE·API, and agy under
  `KRYPT_AGY_YOLO` — now **race concurrently** instead of one-at-a-time; the
  first real flag wins and the losers are abandoned. Response carries an
  `escalation: {tried, raced, solved_by}` block.
- **WATCH / auto-hunt**: point KRYPT at folders (`./ctf --watch ~/Downloads`)
  and it hunts flags in every new/changed file the instant it lands — content
  de-dup, write-settle guard, live log, optional `--deep` full pipeline and
  `--event` auto-save. New WATCH row in the GUI with a live capture panel.
- **Encoded-flag sweep**: one-level base64/hex decode sweep catches a flag
  encoded inside a file (`ZmxhZ3s…}` → `flag{…}`); wired into every file's
  triage, not just watch mode, with a near-zero false-positive guard.
- **Writeups, cooked**: flag stated up top, Overview block (inferred flag
  format + engine), numbered Solve-path timeline with the winning step flagged,
  an encoding-chain note, and a Reproduce block; event writeups get a
  by-category summary + Contents list.

## v1.1
- **Vault**: per-event session logbook; captured flags auto-save to the named
  event with a professional, deterministic writeup (no AI tokens).
- **Export**: download any writeup — or a whole event's writeups — as clean
  Markdown or PDF (rendered via headless Chrome).
- **Web depth**: form/input extraction, JWT detection, more discovery paths,
  optional arjun hidden-parameter discovery.
- **Forensics**: USB HID keystroke decoder (auto-solves keyboard-capture pcaps).
- **Crypto**: base58 and Morse code added to the magic decoder.
- **Tests + CI**: decoder/vault/category test suite, GitHub Actions workflow.

## v1.0
- Autonomous first-pass triage: file detection, strings, exiftool, binwalk +
  entropy, embedded extraction, recursive hunt, flag-regex sweep.
- Magic BFS decoder (base64/32/85, hex, decimal, binary, rot13/47, atbash,
  gzip/zlib) + single-byte XOR brute force.
- rockyou auto-crack for password ZIPs, steghide, and hashes.
- Autonomous solvers: angr (rev), auto ret2win (pwn), RSA (crypto).
- Domain arsenals mapping local BlackArch tools + MCP tools + skills.
- Engines: deterministic triage, local Ollama (auto-selects a cybersecurity
  model), and claude/agy MCP deep-hunt hand-off.
- Monochrome web UI with glitch boot, fullscreen launcher (Alt+T), domain and
  engine selectors, and a no-file "common box".
