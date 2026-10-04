# Changelog

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
