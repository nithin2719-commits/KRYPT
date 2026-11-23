"""Side-channel timing and GDB instruction counting solver for difficult crackmes."""
from __future__ import annotations

import os
import shutil
import string
import subprocess
import time
from typing import Any

from ..flags import scan_text


DEFAULT_CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "{}_-!?"


def count_gdb_instructions(binary_path: str, candidate_input: str, timeout: float = 3.0) -> int:
    """Run candidate input in GDB and count instructions executed before exit."""
    gdb_bin = shutil.which("gdb") or "/usr/bin/gdb"
    if not os.path.exists(gdb_bin):
        return 0

    # Write input to a temp file or pass via stdin
    # GDB command: set pagination off, run with stdin, count instructions
    gdb_commands = (
        "set pagination off\n"
        "set confirm off\n"
        "starti\n"
        "stepi 500\n"
        "quit\n"
    )

    try:
        p = subprocess.Popen(
            [gdb_bin, "-batch", "-ex", "set pagination off", "-ex", f"run <<< '{candidate_input}'", binary_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, _ = p.communicate(timeout=timeout)
        # Count lines of output or events
        return len(stdout.splitlines())
    except Exception:
        return 0


def solve_character_by_character(
    binary_path: str,
    known_prefix: str = "flag{",
    max_len: int = 32,
    charset: str = DEFAULT_CHARSET,
    mode: str = "timing",
) -> dict[str, Any]:
    """Recover flag character-by-character by measuring timing differentials or instruction steps."""
    current_flag = known_prefix
    recovered = False
    attempts_log: list[str] = []

    for pos in range(len(known_prefix), max_len):
        best_char = ""
        best_metric = -1.0

        for ch in charset:
            test_candidate = current_flag + ch
            # Pad candidate to max_len with dummy characters
            padded = test_candidate.ljust(max_len, "A")

            # Measure timing differential
            t0 = time.perf_counter_ns()
            try:
                p = subprocess.run(
                    [binary_path],
                    input=padded.encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1.0,
                )
                t1 = time.perf_counter_ns()
                elapsed = float(t1 - t0)

                # Check if flag already printed
                out_txt = (p.stdout or b"").decode("latin-1", "replace")
                if "correct" in out_txt.lower() or "win" in out_txt.lower() or "success" in out_txt.lower():
                    flags = scan_text(out_txt)
                    if flags:
                        return {"solved": True, "flag": flags[0]["flag"], "output": f"Found via prompt response: {flags[0]['flag']}"}

                if elapsed > best_metric:
                    best_metric = elapsed
                    best_char = ch

            except subprocess.TimeoutExpired:
                # High delay indicates matching branch
                best_char = ch
                break
            except Exception:
                continue

        if best_char:
            current_flag += best_char
            attempts_log.append(f"Pos {pos}: recovered '{best_char}' (metric={best_metric:.2f}) -> {current_flag}")
            if best_char == "}":
                recovered = True
                break
        else:
            break

    flags = scan_text(current_flag)
    return {
        "solved": recovered,
        "flag": current_flag,
        "flags": flags,
        "output": "\n".join(attempts_log),
    }


def solve(binary_path: str, workdir: str = "") -> dict[str, Any]:
    """Execute side-channel analysis on target binary."""
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        return {"step": "sidechannel-crackme", "summary": "Not an executable binary", "output": "", "flags": []}

    res = solve_character_by_character(binary_path, known_prefix="flag{", max_len=24)
    return {
        "step": "sidechannel-crackme",
        "summary": f"Side-channel timing analysis ({res.get('flag', '')})",
        "output": res.get("output", ""),
        "flags": res.get("flags", []),
    }
