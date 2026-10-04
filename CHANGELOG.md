# Changelog

## Unreleased
- **Flag tool** (GUI `◇ FLAG`, Alt+T): enter or paste a captured flag, verify it
  against the event's format, save it to the Vault with a writeup, and submit it
  straight to the live scoreboard (CTFd, rCTF, or generic HTTP) — the verdict
  (correct / incorrect / already-solved / rate-limited / auth) shows inline, and
  a scored flag auto-saves to the Vault. Credentials are stored locally in
  `~/.config/krypt/config.json` (chmod 600) and the token is never sent back to
  the browser. New: `ctfsolver/submit.py`, `flags.validate_flag`,
  `vault.add_manual`; server endpoints `/api/flag/{config,verify,save,submit}`;
  deep-link `?flag=1`. Tests in `tests/test_submit.py` + `tests/test_flags.py`.

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
