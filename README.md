# KRYPT

Autonomous **CTF triage & flag hunter**. Give it a file, URL, or `host:port`; it
classifies the challenge, runs the right tools, sweeps everything for flags, and
writes a report — so expensive human/agent reasoning only starts where the cheap
wins run out. Ships with a fullscreen black-and-white GUI (bound to **Alt+T**).

> **Authorized use only.** Run against CTF material or targets you have explicit
> permission to test. (Folder is `~/ctf-solver`; the product name is KRYPT.)

## Two ways to run

**CLI**
```bash
cd ~/ctf-solver
./ctf ./challenge.bin            # binary (pwn/rev)
./ctf ./stego.png               # image
./ctf ./capture.pcap            # network
./ctf ./cipher.txt              # crypto / encodings
./ctf https://target/chal       # web
./ctf 10.10.10.5:1337           # remote service
./ctf ./chal --ai               # + local Ollama hypothesis
```

**GUI** — press **Alt+T** (opens fullscreen), or `gui/launch.sh`. Type a target or
drop a file, add an optional **CHALLENGE BRIEFING**, pick an **ENGINE**, HUNT.

## How it works

1. **detect** — `file`/MIME + URL/host heuristics pick a category.
2. **generic triage** (every file) — `file`, `strings` (ascii+utf16), `exiftool`,
   `binwalk` + entropy, embedded-file extraction, and a flag-regex sweep over raw
   bytes *and* every tool's output.
3. **category triage**
   | category | tools |
   |---|---|
   | binary (pwn/rev) | checksec, readelf, nm/objdump, radare2, ROPgadget |
   | image (stego) | zsteg, steghide, **stegseek+rockyou** |
   | archive | 7z/unzip (detects `Encrypted=+` → **zip2john+rockyou**) |
   | pcap | capinfos, tshark |
   | text/data (crypto) | **magic BFS decoder** (base64/32/85, hex, decimal, binary, url, rot13/47, atbash, gzip/zlib, **single-byte XOR brute**), hashid, auto john |
   | url (web) | curl headers/body, common paths, whatweb |
   | host:port | banner grab + benign auto-probes |
4. **recursive hunt** — every carved/extracted member is re-run through the full
   pipeline (depth 2, sha1-dedup) so nested challenges unravel themselves.
5. **aggregate** — flag candidates ranked by confidence; top one printed.

## CHALLENGE BRIEFING

Paste the challenge prompt / hints / flag format. The backend then:
- **derives the flag format** (e.g. `picoCTF{…}`) → matches become custom conf-100
- **sweeps the briefing** for flags hidden in the prompt (format-example
  placeholders like `X{...}` are filtered out)
- **primes the AI/agent** with it as context

Or set it globally for the CLI: `export CTF_FLAG_FORMAT='picoCTF\{[^}]+\}'`.

## ENGINES

- **TRIAGE** — deterministic pipeline only (instant, never refuses).
- **LOCAL · <model>** — local Ollama hypothesis on the GPU (`ai.py`,
  `qwen2.5-coder:7b` default; override `CTF_OLLAMA_MODEL`).
- **CLAUDE · MCP / AGY · MCP** — hands you a ready-to-run `claude -p` / `agy -p`
  command that drives the real MCP tools (hexstrike-ai, ghidra, …) with normal
  per-tool approval. KRYPT never auto-runs an auto-approving agent itself.

## Layout

```
ctf                 CLI launcher
ctfsolver/
  __main__.py       CLI + orchestration + recursive hunt
  detect.py         input classification
  flags.py          flag-regex sweep (strict mode for noisy sources)
  decoders.py       magic BFS decoder + XOR brute
  crack.py          rockyou auto-crack (zip/steghide/hash)
  agents.py         claude/agy command builder (PATH-resolved; never executes)
  ai.py             local Ollama assist
  runner.py         safe subprocess wrapper
  triage/           per-category modules
gui/
  server.py         stdlib backend (127.0.0.1:8777) — /api/solve, /api/upload, /api/deep, /api/health
  index.html        KRYPT UI (glitch boot, monochrome, engine selector)
  launch.sh         start server + open fullscreen Chrome app (Alt+T)
workspace/          per-run outputs (gitignored)
```

No pip dependencies — pure stdlib driving installed CLI tools.

## Deep work continues via

hexstrike-ai (pwntools/sqlmap/john/volatility…), the `ghidra` MCP
(`import_binary` → `decompile_function`), and the `/cybersec-ctf` skill (818-skill
library). In Claude Code, those tools can be driven directly against a challenge.
