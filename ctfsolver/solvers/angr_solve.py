#!/usr/bin/env python3
"""Standalone angr auto-solver for rev / crackme challenges.

Symbolically explores the binary to find the stdin input that drives it into a
"success" state (prints correct/flag/win) while avoiding failure states. Prints
the recovered input and the success output — for crackmes the input often *is*
the flag, and the output frequently contains it.

Run as a subprocess with a timeout (angr can blow up); the caller kills it.
    python3 angr_solve.py <binary>
"""
import sys
import logging

logging.getLogger("angr").setLevel("CRITICAL")
logging.getLogger("cle").setLevel("CRITICAL")
logging.getLogger("claripy").setLevel("CRITICAL")

GOOD = [b"correct", b"flag{", b"ctf{", b"well done", b"congrat", b"access granted",
        b"you win", b"solved", b"good job", b"success", b"unlocked"]
BAD = [b"wrong", b"incorrect", b"try again", b"denied", b"nope", b"invalid",
       b"failed", b"no!", b"bad "]


def _out(state):
    try:
        return state.posix.dumps(1).lower()
    except Exception:
        return b""


def main():
    if len(sys.argv) < 2:
        print("USAGE: angr_solve.py <binary>")
        return 2
    path = sys.argv[1]
    try:
        import angr
    except Exception as e:  # pragma: no cover
        print(f"ANGR_UNAVAILABLE {e}")
        return 2
    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as e:
        print(f"LOAD_FAILED {e}")
        return 2

    state = proj.factory.full_init_state(
        add_options={angr.options.LAZY_SOLVES,
                     angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    sm = proj.factory.simulation_manager(state)

    def found(s):
        o = _out(s)
        return any(g in o for g in GOOD)

    def avoid(s):
        o = _out(s)
        return any(b in o for b in BAD)

    try:
        sm.explore(find=found, avoid=avoid, num_find=1)
    except Exception as e:
        print(f"EXPLORE_ERROR {e}")
        return 1

    if sm.found:
        f = sm.found[0]
        try:
            stdin = f.posix.dumps(0)
        except Exception:
            stdin = b""
        stdout = _out(f)
        print("SOLVED")
        print("INPUT:", stdin.decode("latin-1", "replace"))
        print("OUTPUT:", stdout.decode("latin-1", "replace"))
        return 0
    print("NO_SOLUTION")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
