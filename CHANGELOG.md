# Changelog

## v2.8 — Instant In-Memory String Triage, Format Auto-Inference & Early-Exit Optimization
- **Instant In-Memory String Triage (`ctfsolver/god.py`)**:
  - Accelerated solving for non-file text, ciphertexts, base64 strings, hex runs, and equation tokens directly in Phase 1.
  - Sub-millisecond early exit for single and multi-layer encodings without writing temporary files to disk or launching subprocesses.
- **Intelligent Briefing Flag-Format Auto-Inference**:
  - Automatically parses challenge briefings and descriptions for declared flag formats (e.g., `flag format is incursion{...}`, `Format: CTF{...}`, `flag is: cyber{...}`).
  - Passes dynamic `format_hint` to `scan_text`, `scan_file`, and `scan_encoded` without polluting process-global environment variables.
- **Phase 2 Parallel Early Cancellation**:
  - Concurrently polls completed solver tasks in Phase 2 and cancels pending tasks the instant a high-confidence flag candidate ($\ge 90$) matching the format is discovered, reducing typical execution times from 60–90 seconds to under 2 seconds.
- **High-Fidelity Flag Sanitization & Deduplication (`ctfsolver/god.py` & `ctfsolver/flags.py`)**:
  - Strips wrapping single/double quotes and trailing punctuation artifacts from scraped inputs.
  - Prunes substring fragments in favor of complete parent flag structures (e.g. keeping `picoCTF{flag}` over partial `CTF{flag}`).
  - Extended placeholder blocklist filtering (`fake_placeholder`, `placeholder`, `fake_flag`).
  - Sorts valid candidates deterministically by confidence and length.
- **Unit Test Suite (`tests/test_god_fast.py`)**:
  - Added unit test suite covering instant in-memory string solving (0.05s execution), briefing format auto-inference, and flag ranking.
  - Total test suite expanded to 144 passing unit tests.

## v2.7 — Symbolic Execution & Deobfuscation Engine
- **Symbolic Execution & Input Recovery Suite (`ctfsolver/solvers/symbolic.py`)**:
  - Implements targeted input recovery using `angr` SimulationManagers to explore crackmes and reversing binaries.
  - Steers state exploration toward designated success markers (`correct`, `flag{`, `access granted`, `success`, etc.) while avoiding failure states (`wrong`, `incorrect`, `denied`, etc.).
  - Employs step-by-step deadline-aware simulation loops instead of unconstrained `.explore()` calls to strictly honor wall-clock timeouts.
  - Multi-length iterative search across common flag and password candidate lengths (4, 6, 8, 12, 16, 24, 32).
  - Robust claripy abstraction supporting both top-level and vendored module imports across angr versions.
- **Mixed Boolean-Arithmetic (MBA) Deobfuscation**:
  - Z3-based expression simplification (`simplify_obfuscated_expr`) folding obfuscated bitwise/arithmetic expressions (e.g. `(x ^ C) ^ C -> x`).
  - Formal expression equivalence checker (`expressions_equivalent`) verifying semantic identity before applying algebraic substitutions.
- **Static Pre-Check & Binary Triage**:
  - Fast ELF triage (`static_precheck`) evaluating dynamic imports (`nm -D`) and linker paths.
  - Distinguishes local crackmes from service/network binaries (rejecting binaries with socket/connect/bind symbols) and statically linked binaries (which incur higher simulation overhead).
- **Registry Integration**:
  - Registered via `@register_solver(name="symbolic_crackme", category="rev", priority=60, match_fn=_looks_like_crackme_elf)` with top-level `solve(target, workdir)` interface.
- **Unit Test Suite (`tests/test_symbolic.py`)**:
  - Added 9 unit tests compiling synthetic C fixtures on the fly (dynamic XOR crackmes, static crackmes, networked binaries) and validating pre-check heuristics, input recovery, MBA simplification, and equivalence proofs.
  - Total test suite expanded to 141 passing unit tests.

## v2.6 — Plugin Solver Registry & Dynamic Discovery API
- **Dynamic Solver Registry (`ctfsolver/solvers/registry.py`)**:
  - Implemented decorator-based plugin registration (`@register_solver`) with metadata:
    - Unique solver name, category (`crypto`, `forensics`, `pwn`, `web`, `rev`, `misc`), priority score (higher runs first), optional file extension match patterns (`match_ext`), custom context match callable (`match_fn`), and solver descriptions.
    - `SolverContext` model encapsulating `target`, `text`, `category`, `hints`, `workdir`, and combined challenge text.
    - Automatic signature adapter supporting `fn(ctx)`, `fn(target, workdir)`, and `fn(text)` to seamlessly integrate existing legacy solver functions.
  - Auto-discovery mechanism (`auto_discover()`) dynamically scanning and importing all solver modules under `ctfsolver/solvers/`.
  - Built-in fallback registration (`register_builtin_solvers()`) guaranteeing core solvers (`z3`, `rsa_attacks`, `sage`, `xor_solver`, `qr`, `png_forensics`, `audio`, `pcap`, `doc`, `zip_forensics`, `volatility`, `esoteric`, `sidechannel`) remain registered even if dynamic import fails or modules are shadowed.
- **Apex Engine Decoupling (`ctfsolver/god.py`)**:
  - Refactored `GodSolver._run_deep_solvers()` (Phase 2) to eliminate hardcoded solver invocations.
  - Solvers are now resolved dynamically using `get_matching_solvers(ctx)`, sorted by priority, and executed concurrently via `ThreadPoolExecutor`.
- **Decorator Integration on Solvers**:
  - Registered `zip_forensics.solve` (`forensics`, priority 68, `.zip`, `.jar`, `.apk`).
  - Registered `png_forensics.solve` (`forensics`, priority 72, `.png`).
  - Registered `rsa_attacks.solve` (`crypto`, priority 85, `.pem`, `.key`, `.rsa`, `.txt`, and crypto keywords).
  - Registered `xor_solver.solve` (`crypto`, priority 75, `.xor`, `.bin`, `.dat`, `.txt`, `.enc`, etc.).
- **Unit Test Suite (`tests/test_registry.py`)**:
  - Added unit test suite covering registration, decorator adapters, priority sorting, auto-discovery, and dynamic execution inside `GodSolver`. All 132 tests passing.

- **Pure-Python RSA Attack Suite (`ctfsolver/solvers/rsa_attacks.py`)**:
  - Implements direct cryptographic attacks on RSA without external binary dependencies:
    - Small/low public exponent attack ($m^e < n$, small $k \cdot n + c$ root search).
    - Wiener's continued fractions attack for small private exponent ($d < n^{0.25}$).
    - Fermat's factorization for close primes ($|p - q| \ll \sqrt{n}$).
    - Pollard's $p - 1$ factorization for $B$-smooth primes.
    - Common factor (pairwise GCD) across multiple moduli and common modulus (coprime exponents).
    - Hastad's broadcast attack using Chinese Remainder Theorem (CRT) and integer $e$-th root.
    - LSB / Parity Oracle bit-by-bit recovery via exact rational binary search.
    - Simplified Boneh-Durfee attack for small $d$ up to $n^{0.292}$.
    - FactorDB online database lookup and small-prime trial division.
    - Flexible parameter parser for free-form text, multi-line assignments, and PEM keys.
- **XOR Cryptanalysis Suite (`ctfsolver/solvers/xor_solver.py`)**:
  - Pure-Python XOR cryptanalysis:
    - Single-byte XOR brute-force with ETAOINSHRDLU character frequency scoring.
    - Repeating-key XOR solver via Kasiski examination, Index of Coincidence (IoC), and normalized pairwise Hamming distance.
    - Known-plaintext keystream recovery and primitive period simplification.
    - Many-time pad space-correlation attack across multiple ciphertexts and crib-dragging.
- **Deep PNG Forensics Solver (`ctfsolver/solvers/png_forensics.py`)**:
  - Complete structural PNG parser and validator:
    - Chunk parser with CRC32 verification and anomaly reporting.
    - Text chunk extractor (`tEXt`, `zTXt`, `iTXt`) with flag sweeping.
    - IHDR dimension validation, CRC brute-force dimension recovery, and trailing IDAT scanline height calculation.
    - Trailing overlay data extraction after `IEND`.
    - Palette/PLTE stego analysis (unused palette entries, per-channel bitstreams).
    - LSB replacement detection via Pairs of Values (PoV) $\chi^2$ and channel bitstream extraction.
- **Pure-Python ZIP Forensics & Anti-Stego Engine (`ctfsolver/solvers/zip_forensics.py`)**:
  - Detects and clears pseudo-encryption (ZipCenOp fake encryption bit flags) in local and central directory headers.
  - Brute-forces short plaintexts (1-4 bytes) directly from 32-bit CRC32 checksums without knowing the password.
  - Extracts End of Central Directory archive comments and per-file comments.
  - Detects Zip-Slip / path traversal directory anomalies.
- **Triage & Apex Pipeline Integration**:
  - Wired into `ctfsolver/god.py`, `ctfsolver/worker.py`, `ctfsolver/triage/crypto.py`, `ctfsolver/triage/image.py`, and `ctfsolver/triage/archive.py`.
- **Test Suite**:
  - Added `tests/test_png_forensics.py`, `tests/test_rsa_xor.py`, and `tests/test_zip_forensics.py` (total 126 passing unit tests).

## v2.4 — Apex Multi-Tier Autonomous Solver
- **Apex Multi-Tier Engine (`ctfsolver/god.py`)**:
  - Orchestrates all four solver tiers concurrently in an apex autonomous pipeline:
    - Phase 0: Target Acquisition and deep file classification (`ctfsolver.detect`).
    - Phase 1: Instant Magic BFS decoders and plaintext/base64/hex sweep.
    - Phase 2: Parallel Deep Domain Solvers (ThreadPoolExecutor across Z3 constraint solving, SageMath RSA/lattices, QR/visual bitplanes, audio DTMF, PCAP ICMP tunnel reassembly, document comment carving, memory forensics, esoteric ciphers, and side-channel timing analysis).
    - Phase 3: Multi-agent Swarm escalation across cross-domain specialists with shared blackboard.
    - Phase 4: Strict candidate flag validation, automated scoreboard submission, Vault capture recording, and webhook notifications.
  - CLI subcommand integration: `./ctf god <target>` and `./ctf <target> --god`.
  - Web GUI integration: `APEX · MULTI-TIER` engine selector and `/api/deep` provider routing.
- **Scoreboard & Vault Hardening**:
  - Added `Scoreboard.is_configured` property for robust credential and reachability verification.
  - Added time budget and early-exit fallback to prevent hanging in automated workflows.
- **Test Suite**:
  - Added comprehensive test coverage for `GodSolver` instant and fallback mechanics (106 passed in 6.93s).

## v2.3 — Hard CTF Solvers: SageMath Lattices, Side-Channel Crackmes & Payload Forge
- **SageMath Lattice & Hard RSA Engine (`ctfsolver/solvers/sage_crypto.py`)**:
  - Coppersmith's small root attack for stereotyped messages ($m^e \pmod N$ with known `flag{` prefix) using univariate polynomial root finding over $\mathbb{Z}_N$.
  - Common Modulus attack using extended Euclidean algorithm ($r e_1 + s e_2 = 1$).
  - Hastad's Broadcast attack combining multiple ciphertexts via Chinese Remainder Theorem (CRT) and computing integer $e$-th roots.
  - Integrated into crypto triage (`ctfsolver/triage/crypto.py`) and worker Tier 2 pipeline.
- **Side-Channel Timing & GDB Instruction Counting Crackme Solver (`ctfsolver/solvers/sidechannel_solve.py`)**:
  - Automated character-by-character crackme solver utilizing timing differential measurements and GDB batch instruction counters to break through non-symbolic verification loops and custom hashes.
- **Weaponized Payload Forge & Sandbox Escapes (`ctfsolver/solvers/payload_forge.py`)**:
  - Python pickle deserialization RCE payload generator (`__reduce__`).
  - Jinja2 SSTI filter bypass generator (attribute filters, string concatenation, lipsum/cycler globals).
  - Node.js `node-serialize` IIFE remote code execution generator.
  - Integrated into web triage (`ctfsolver/triage/web.py`).
- **Test Suite Expansion**:
  - Added test cases covering common modulus recovery, pickle/Jinja2 payload synthesis, and sidechannel fallback mechanics (105 unit tests passing with 100% success).

## v2.2 — Advanced Domain Solvers & Queue Strategy Engine
- **Visual Steganography & QR/Barcode Solver (`ctfsolver/solvers/qr_visual.py`)**:
  - Multi-engine QR, DataMatrix, and barcode reader (`pyzbar`, `zxingcpp`) with pre-processing (inversion, contrast boost, binary thresholding).
  - Bit-plane extraction across R, G, B, and Alpha channels (bit 0 LSB and sequential RGB bitstreams).
  - Integrated into image triage (`ctfsolver/triage/image.py`) and worker Tier 2 pipeline.
- **Deep Audio & DTMF Demodulator (`ctfsolver/solvers/audio_deep.py`)**:
  - DTMF touch-tone frequency decoder using Goertzel algorithm across sliding windows to recover secret keypad sequences and flag pins.
  - Audio LSB extraction from 16-bit PCM WAV audio samples.
  - Integrated into audio triage (`ctfsolver/triage/audio.py`) and worker Tier 2 pipeline.
- **Z3 Symbolic Constraint Solver (`ctfsolver/solvers/z3_solve.py`)**:
  - Automated parser and solver for crackme linear and bitwise character equations (`flag[i] ^ k == v`, `v0 + v1 == ...`).
  - Constrained character extraction to printable ASCII range with automatic flag wrapper formatting.
  - Integrated into crypto triage (`ctfsolver/triage/crypto.py`), binary triage, and worker Tier 2 pipeline.
- **Web & JWT Attack Suite (`ctfsolver/solvers/jwt_web.py`)**:
  - JWT algorithm 'none' token forgery with admin claim escalation.
  - HMAC-SHA256 secret key cracking with common CTF passwords and `rockyou.txt`.
  - Non-destructive automated SSTI (`{{7*7}}`) and SQLi parameter verification probes.
  - Integrated into web triage (`ctfsolver/triage/web.py`) and worker Tier 2 pipeline.
- **Deep PCAP Protocol Analysis (`ctfsolver/solvers/pcap_deep.py`)**:
  - ICMP data tunnel extraction and payload reassembly (`ping -p` data exfiltration).
  - Cleartext credential sweeping across FTP (`USER`/`PASS`), HTTP Basic Auth, and SMTP.
  - TCP conversation stream reassembly and flag extraction across active connections.
  - Integrated into network triage (`ctfsolver/triage/pcap.py`) and worker Tier 2 pipeline.
- **ret2libc Exploit Scaffold (`ctfsolver/solvers/pwn_scaffold.py`)**:
  - Expanded pwn scaffolding beyond ret2win to generate complete 64-bit ret2libc exploits with `puts@got` leaks and `system('/bin/sh')` shellcode.
- **Esoteric & Classical Ciphers Engine (`ctfsolver/solvers/esoteric_ciphers.py`)**:
  - DNA codon amino-acid translation and 2-bit binary mapping (`A=00, C=01, G=10, T=11`).
  - T9 phone keypad multi-tap decoder (`222 8 333` -> `ctf`).
  - NATO phonetic alphabet decoder (`Alfa Bravo Charlie` -> `ABC`).
  - Polybius square 5x5 coordinate decipher.
  - Rail fence transposition cipher brute-force (depths 2 to 10).
  - COW esoteric programming language interpreter.
  - Integrated into crypto triage (`ctfsolver/triage/crypto.py`).
- **Web Arsenal (`ctfsolver/solvers/web_arsenal.py`)**:
  - Werkzeug Debug Console PIN calculator (from leaked node & machine-id).
  - PHP loose comparison magic hashes (`0e...`) identifier.
  - Automated Local File Inclusion (LFI) parameter prober (`../../../../etc/passwd`, `php://filter/`).
  - Integrated into web triage (`ctfsolver/triage/web.py`).
- **GitHub Tool Arsenal Integration (`ctfsolver/research.py`)**:
  - Installed and cataloged `autorop` (`~/tools/autorop`) for automated ret2libc / ret2shellcode pwn pipelines.
  - Installed and cataloged `libc-database` (`~/tools/libc-database`) for remote libc symbol offset lookups.
- **Volatility 3 Memory Forensics Solver (`ctfsolver/solvers/volatility_solve.py`)**:
  - Automatically identifies memory captures (`.raw`, `.dmp`, `.vmem`, `.lime`, `.mem`).
  - Executes prioritized Volatility 3 plugins (`windows.cmdline`, `windows.envars`, `windows.pslist`, `linux.bash`) and sweeps memory strings for flag patterns.
  - Integrated into generic triage (`ctfsolver/triage/generic.py`) and worker Tier 2 pipeline.
- **Anti-Debug Bypass & Binary Patching (`ctfsolver/solvers/bin_patch.py`)**:
  - Automatically patches `ptrace(PTRACE_TRACEME)`, `alarm()`, and `sleep()` PLT entries in ELF binaries with `xor eax, eax; ret` (31 c0 c3) to neutralize debugger-detection and timeouts.
  - Integrated into binary triage (`ctfsolver/triage/binary.py`).
- **Document & PDF Deep Forensics (`ctfsolver/solvers/doc_carve.py`)**:
  - Extracts compressed FlateDecode streams (`qpdf --qdf`), embedded attachments (`pdfdetach`), and raw metadata.
  - Sweeps Office OpenXML documents (`.docx`, `.pptx`, `.xlsx`) for hidden comments and invisible XML tags.
  - Integrated into PDF triage (`ctfsolver/triage/pdf.py`) and worker Tier 2 pipeline.
- **Competition Webhook Alerting (`ctfsolver/worker.py`)**:
  - Automatically dispatches instant flag capture notifications to Discord, Telegram, or Slack webhooks when `CTF_WEBHOOK_URL` is set.
- **Queue Priority Strategy Controls (`ctfsolver/worker.py`, `ctfsolver/__main__.py`)**:
  - Added `--strategy {fifo, easy-first, high-points}` to allow tactical challenge scheduling during competitions.
- **Test Suite Expansion**:
  - Added `tests/test_advanced_solvers.py` (102 unit tests passing with 100% success).

## v2.1 — Multi-Agent Swarm Orchestrator & Dynamic Tools Research Engine
- **Dynamic Tools Research & Discovery Engine (`ctfsolver/research.py`)**:
  - Dynamically catalogs installed CTF repositories across the system (`~/tools/hexstrike-ai`, `pwndbg`, `RsaCtfTool`, `GHunt`, `strix`, `EvidenceFlow`, `agent-team`, etc.).
  - Inspects Python virtualenv modules (`pwntools`, `angr`, `z3`, `pycryptodome`, `volatility3`, `gmpy2`, `scapy`), system binaries, and wordlists (`rockyou.txt`).
  - Automatically recommends prioritized category tool pipelines and dynamic tool execution plans based on challenge evidence.
- **Specialist Domain Agents (`ctfsolver/specialists.py`)**:
  - Purpose-built specialist agents: `PwnSpecialist`, `RevSpecialist`, `CryptoSpecialist`, `WebSpecialist`, `ForensicsSpecialist`, and `OsintSpecialist`.
  - Category-tuned system prompts, tool allowlists (Ghidra MCP, HexStrike AI MCP, custom scripts), and automated execution bindings.
- **Multi-Agent Swarm Coordinator (`ctfsolver/swarm.py`)**:
  - `SwarmCoordinator` and `SwarmBlackboard` facilitating cross-agent artifact and clue handoffs (e.g., Forensics carves encrypted container -> Crypto cracks with rockyou -> Rev decompiles payload -> Pwn constructs exploit).
  - CLI support for `--agent swarm` as well as direct specialist escalation (`--agent pwn`, `--agent rev`, `--agent crypto`, `--agent web`, `--agent forensics`, `--agent osint`).
- **Web GUI Swarm Mode**:
  - Added `SWARM · MULTI-AGENT` engine button to `gui/index.html`.
  - Integrated swarm coordinator and specialist dispatch into `/api/deep` endpoint in `gui/server.py`.
- **Test Suite Coverage**:
  - Added `tests/test_research.py` covering repository discovery, pipeline recommendations, specialist configurations, and blackboard state progression (91 unit tests passing).

## v2.0 — Active CTF Worker & Scoreboard Integration
- **Active Autonomous CTF Worker Engine (`ctfsolver/worker.py`)**:
  - Continuous competition worker daemon (`./ctf worker`) that automates the complete CTF lifecycle: challenge ingestion, multi-tier solving, candidate verification, scoreboard submission, and Vault writeup generation.
  - Multi-tier solving pipeline:
    - **Tier 1 (Instant Magic)**: Recursive BFS multi-codec decoding, file carving, strings extraction.
    - **Tier 2 (Heuristic Domain Solvers)**: Autonomous symbolic execution (`angr_solve.py`), RSA attack suite (`rsa_solve.py`), rockyou hash cracking (`crack.py`), PCAP DNS/HTTP carving, and ret2win scaffold (`pwn_scaffold.py`).
    - **Tier 3 (AI Agent Escalation)**: Autonomous agent solver with HexStrike AI and Ghidra MCP pre-approved allowlists, parallel engine racing across free and paid engines.
  - Priority task queue with disk persistence (`workspace/worker_queue.json`) and live progress event emissions.
  - Interactive ANSI terminal dashboard with live status, phase indicators, and score progression.
- **Scoreboard Integration (`ctfsolver/scoreboard.py`)**:
  - Full API integration for **CTFd**, **rCTF**, and generic scoreboard endpoints.
  - Scoreboard sync: queries active competitions, filters already solved challenges, downloads challenge file attachments into local workspaces, and populates the worker queue.
  - Auto-submission: verified flags are automatically submitted to the competition scoreboard with verdict parsing (`correct`, `incorrect`, `already_solved`, `ratelimited`) and points tracking.
  - Secure credential storage in `~/.config/krypt/config.json` (chmod 600).
- **Active CTF Worker Persona (`agents.py`)**:
  - Updated solver prompt to enforce direct CTF copilot protocol: evidence-first reasoning, rapid hypothesis elimination, no generic lectures, and direct automated tool invocation.
- **Web GUI Active Worker HUD**:
  - Live Active Worker status widget in `gui/index.html` with real-time status polling, one-click start/pause, scoreboard sync, and queue clearing.
  - REST API endpoints for worker lifecycle (`/api/worker/*`) and scoreboard operations (`/api/scoreboard/*`).
- **CLI Subcommands**:
  - Added `./ctf worker`, `./ctf queue list/add/clear`, `./ctf submit`, and `./ctf sync` commands.
  - Integrated worker and scoreboard status reporting into `./ctf --doctor`.

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
