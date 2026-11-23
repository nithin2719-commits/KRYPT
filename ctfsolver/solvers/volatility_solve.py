"""Automated Volatility 3 Memory Forensics solver for memory dump challenges."""
from __future__ import annotations

import os
import shutil
from typing import Any

from ..flags import scan_text
from ..runner import have, run


def resolve_vol() -> str:
    """Find the volatility executable."""
    for candidate in ["/home/nithin/.local/bin/vol", "vol", "volatility3", "vol.py"]:
        p = shutil.which(candidate) if not os.path.isabs(candidate) else candidate
        if p and os.path.exists(p):
            return p
    return "vol"


def is_memory_dump(path: str) -> bool:
    """Check if file matches memory dump extensions or magic characteristics."""
    lower = path.lower()
    if lower.endswith((".raw", ".dmp", ".vmem", ".lime", ".mem", ".core", ".dd")):
        return True
    # If file size is large (> 50MB) and binary
    try:
        sz = os.path.getsize(path)
        if sz > 50 * 1024 * 1024:
            with open(path, "rb") as fh:
                magic = fh.read(16)
                if not any(magic.startswith(h) for h in [b"PK", b"\x7fELF", b"MZ", b"%PDF", b"\x89PNG", b"\xff\xd9"]):
                    return True
    except OSError:
        pass
    return False


def run_volatility_plugins(mem_path: str, workdir: str = "", timeout: int = 120) -> dict[str, Any]:
    """Run prioritized Volatility 3 plugins on a memory dump."""
    flags: list[dict[str, Any]] = []
    output_lines: list[str] = []
    vol_bin = resolve_vol()

    if not shutil.which(vol_bin) and not os.path.exists(vol_bin):
        return {
            "step": "volatility-memory",
            "summary": "Volatility 3 binary not found",
            "output": "",
            "flags": [],
        }

    # Plugins to run in order of CTF usefulness
    plugins = [
        ("windows.cmdline.CmdLine", "Windows process command lines"),
        ("windows.envars.Envars", "Windows environment variables"),
        ("windows.pslist.PsList", "Windows process listing"),
        ("linux.bash.Bash", "Linux bash command history"),
    ]

    for plugin, desc in plugins:
        try:
            r = run([vol_bin, "-f", mem_path, plugin], timeout=timeout)
            if r.ok() and r.stdout.strip():
                txt = r.stdout
                output_lines.append(f"=== {desc} ({plugin}) ===")
                output_lines.append(txt[:2500])
                fl = scan_text(txt)
                for f in fl:
                    f["method"] = f"volatility-{plugin}"
                    flags.append(f)
                if fl:
                    # Found flag, short-circuit
                    break
        except Exception:
            continue

    return {
        "step": "volatility-memory",
        "summary": f"Volatility 3 memory analysis ({len(flags)} flag candidate(s))",
        "output": "\n".join(output_lines) if output_lines else "No Volatility 3 process or command flags recovered.",
        "flags": flags,
    }


def solve(path: str, workdir: str = "") -> dict[str, Any]:
    """Execute memory dump forensics."""
    if not is_memory_dump(path):
        return {"step": "volatility-memory", "summary": "Not identified as a memory dump", "output": "", "flags": []}
    return run_volatility_plugins(path, workdir)
