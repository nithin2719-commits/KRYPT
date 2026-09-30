"""Triage for ELF/PE binaries (pwn + rev): mitigations, symbols, RE hints,
plus autonomous solvers (angr symbolic execution, auto ret2win scaffold)."""
from __future__ import annotations

import os
import sys

from ..flags import scan_text
from ..runner import have, run

_SOLVERS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "solvers")


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []

    # Quick check: is a flag already sitting in the binary's strings? If so we
    # skip the expensive symbolic/exploit solvers and stay fast.
    _s = run(["strings", "-n", "6", path], timeout=60)
    has_flag = bool(scan_text(_s.stdout, strict=True)) if _s.ok() else False

    # Mitigations (drives pwn strategy: canary/NX/PIE/RELRO)
    if have("checksec"):
        r = run(["checksec", "--file=" + path])
        if not r.ok() or not r.stdout.strip():
            r = run(["checksec", "--file", path])
        steps.append({"step": "checksec",
                      "summary": "binary mitigations",
                      "output": (r.stdout or r.stderr)[:2000], "flags": []})

    # Header / arch
    r = run(["readelf", "-h", path])
    if r.ok():
        steps.append({"step": "readelf-header", "summary": "ELF header",
                      "output": r.stdout[:1500], "flags": []})

    # Dynamic symbols and imports (win() funcs, system, gets, etc.)
    r = run(["nm", "-C", path])
    syms = r.stdout if r.ok() else ""
    if not syms:
        r = run(["objdump", "-T", path])
        syms = r.stdout if r.ok() else ""
    hot = [ln for ln in syms.splitlines() if any(
        k in ln.lower() for k in ("win", "flag", "system", "gets", "printf",
                                  "strcpy", "memcpy", "read", "shell", "backdoor"))]
    steps.append({"step": "symbols",
                  "summary": f"{len(hot)} interesting symbol(s)",
                  "output": "\n".join(hot[:60]), "flags": scan_text(syms)})

    # radare2 quick auto-analysis: functions + main disassembly
    if have("r2"):
        cmds = "aaa; afl; s main; pdf; s sym.main; pdf"
        r = run(["r2", "-q", "-A", "-c", cmds, path], timeout=120)
        if r.ok():
            steps.append({"step": "r2-analysis",
                          "summary": "auto-analysis: functions + main",
                          "output": r.stdout[:6000],
                          "flags": scan_text(r.stdout)})

    # ROP gadget surface (only meaningful for exploitation challenges)
    if have("ROPgadget"):
        r = run(["ROPgadget", "--binary", path], timeout=90)
        if r.ok():
            n = len(r.stdout.splitlines())
            steps.append({"step": "ROPgadget",
                          "summary": f"{n} gadget line(s) (see artifact)",
                          "output": r.stdout[:1500], "flags": []})

    # --- autonomous solvers (only when the flag isn't already in the binary) -
    py = sys.executable or "python3"
    if not has_flag:
        # angr symbolic execution — auto-solves many crackmes/rev challenges
        ar = run([py, os.path.join(_SOLVERS, "angr_solve.py"), path], timeout=120)
        if ar.found:
            body = (ar.stdout or ar.stderr)
            steps.append({"step": "angr-solve",
                          "summary": ("SOLVED — symbolic input found" if "SOLVED" in body
                                      else "symbolic exploration (no solution in budget)"),
                          "output": body[:3000], "flags": scan_text(body)})

        # auto ret2win: find win() + overflow offset, emit exploit, local capture
        ps = run([py, os.path.join(_SOLVERS, "pwn_scaffold.py"), path, workdir], timeout=75)
        if ps.found and ps.stdout.strip():
            steps.append({"step": "auto-ret2win",
                          "summary": "win/overflow analysis + pwntools exploit scaffold",
                          "output": ps.stdout[:3000], "flags": scan_text(ps.stdout)})
    else:
        steps.append({"step": "solvers",
                      "summary": "flag already present in strings — skipped angr/ret2win "
                                 "(run them anyway via the deep engine if needed)",
                      "output": "", "flags": []})

    steps.append({"step": "next",
                  "summary": "Deeper: ghidra MCP import_binary → decompile_function('main'); "
                             "for pwn, the scaffold above is at <workdir>/exploit.py — "
                             "run it vs remote with `python exploit.py <host> <port>`.",
                  "output": "", "flags": []})
    return steps
