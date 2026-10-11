# Changelog

## v1.2
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
