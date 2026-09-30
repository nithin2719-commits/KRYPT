#!/usr/bin/env python3
"""Brainfuck interpreter / auto-solver for esolang CTF challenges.

Runs the program forward AND reversed (challenges like "turnedaround" ship the
Brainfuck source reversed), prints whatever each run emits — which is usually
the password / flag. Safe: bounded steps and output, no input. Deterministic.

    python3 brainfuck.py <file>
"""
import sys

BF = set("><+-.,[]")


def run(code: str, max_steps: int = 20_000_000, max_out: int = 100_000) -> bytes | None:
    code = "".join(c for c in code if c in BF)
    if not code:
        return None
    jump, stack = {}, []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None            # unbalanced
            j = stack.pop()
            jump[i] = j
            jump[j] = i
    if stack:
        return None
    tape = bytearray(30000)
    ptr = pc = steps = 0
    out = bytearray()
    n = len(code)
    while pc < n and steps < max_steps:
        c = code[pc]
        steps += 1
        if c == ">":
            ptr = (ptr + 1) % 30000
        elif c == "<":
            ptr = (ptr - 1) % 30000
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ".":
            out.append(tape[ptr])
            if len(out) >= max_out:
                break
        elif c == "[":
            if tape[ptr] == 0:
                pc = jump[pc]
        elif c == "]":
            if tape[ptr] != 0:
                pc = jump[pc]
        pc += 1
    return bytes(out)


def _printable(b: bytes) -> bool:
    return bool(b) and sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126) / len(b) > 0.8


def main():
    if len(sys.argv) < 2:
        print("USAGE: brainfuck.py <file>")
        return 2
    try:
        with open(sys.argv[1], "r", errors="replace") as fh:
            src = fh.read(2_000_000)
    except OSError as e:
        print(f"READ_FAILED {e}")
        return 2
    if sum(1 for c in src if c in BF) < max(8, 0.5 * len(src.strip())):
        print("NOT_BRAINFUCK")
        return 1
    fwd = run(src)
    rev = run(src[::-1])
    printed = False
    if fwd and _printable(fwd):
        print("FORWARD:", fwd.decode("latin-1", "replace"))
        printed = True
    if rev and _printable(rev) and rev != fwd:
        print("REVERSED:", rev.decode("latin-1", "replace"))
        printed = True
    if not printed:
        print("NO_PRINTABLE_OUTPUT")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
