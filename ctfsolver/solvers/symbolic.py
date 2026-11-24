"""
symbolic.py -- Symbolic Execution & Deobfuscation solver tier for KRYPT.

Adds automated input recovery for crackme/reversing binaries (via angr)
and a Z3-based simplifier/equivalence-checker for obfuscated arithmetic
and bitwise expressions. Sits alongside angr_solve.py, z3_solve.py, and
sidechannel_solve.py -- it doesn't replace them.

Scope, on purpose: given a binary you already have, drive symbolic
execution toward the branch that prints a "success" marker and read back
the concrete input that gets you there. That's test-case / input
generation -- the same category as a fuzzer -- not exploit or payload
construction. This module never builds a ROP chain, shellcode, or a
network payload.

CONFIRMED BY TESTING (real angr run against a synthetic XOR-check
crackme, not just read off docs):
  - angr 10.0.7 vendors its OWN claripy as `angr.claripy`, separate from
    the standalone `claripy` PyPI package. You MUST do
    `from angr import claripy` here -- a plain `import claripy` makes
    objects angr's own isinstance checks reject (fails with "String must
    be either string literal or claripy AST" inside entry_state()).
  - Dynamically-linked binaries solve in well under a second, because
    angr replaces common libc calls with fast symbolic summaries
    (SimProcedures). Statically-linked binaries make angr step through
    real glibc internals and can be dramatically slower or hang --
    static_precheck() below flags this so the caller can decide whether
    to budget more time or skip this tier for that target. Many real CTF
    crackmes ARE statically linked specifically to frustrate tools like
    this one, so don't be surprised if this tier is the slow/skipped one
    on those.
  - Driving the SimulationManager with .explore() does not reliably
    honor a wall-clock timeout once it starts. recover_input() instead
    steps manually in a loop and checks the deadline every iteration.

>>> TWO INTEGRATION POINTS I COULDN'T VERIFY -- I don't have the source
>>> for registry.py or SolverContext, so these are reasonable guesses,
>>> not confirmed:
  1. Import path for register_solver below. Copy the exact import line
     from the top of xor_solver.py or zip_forensics.py (both already
     wired into the real registry) instead of trusting mine.
  2. SolverContext's field name for the target path, and the exact dict
     shape god.py/the registry expects a solver to return. I guessed
     `ctx.target_path` / `ctx.path` and a `{"solver", "success", ...}`
     dict -- check those two spots (marked ADJUST below) against
     xor_solver.py and fix if they differ.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union

log = logging.getLogger(__name__)

try:
    from .registry import register_solver, SolverContext
except ImportError:  # pragma: no cover
    try:
        from registry import register_solver, SolverContext
    except ImportError:
        def register_solver(*_a, **_kw):
            def _wrap(fn):
                return fn
            return _wrap



DEFAULT_SUCCESS_MARKERS: tuple[bytes, ...] = (
    b"correct", b"Correct", b"success", b"Success", b"flag{", b"FLAG{",
    b"access granted", b"welcome",
)
DEFAULT_FAILURE_MARKERS: tuple[bytes, ...] = (
    b"wrong", b"Wrong", b"incorrect", b"Incorrect", b"denied", b"invalid", b"try again",
)
DEFAULT_LENGTHS: tuple[int, ...] = (4, 6, 8, 12, 16, 24, 32)


@dataclass
class SymbolicResult:
    success: bool
    recovered_input: Optional[bytes] = None
    input_mode: str = "argv"
    length_tried: Optional[int] = None
    elapsed_s: float = 0.0
    note: str = ""


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


_NETWORK_SYMS = {"socket", "connect", "bind", "accept", "recv", "send", "recvfrom", "sendto", "listen"}


def _dynamic_imports(path: Path) -> set:
    """Imported (undefined, dynamically-linked) symbol names, via `nm -D`.
    Only meaningful for dynamically-linked binaries -- see static_precheck.

    NOTE: an earlier version of this file tried to detect networking by
    substring-searching the raw file bytes for names like b"socket". That
    produced false positives on statically-linked binaries, because a
    static libc embeds the real implementations (and symbol strings) of
    socket()/connect()/etc. even when the program never calls them --
    confirmed by testing against our own non-networked static crackme
    fixture, which that approach wrongly flagged as a service binary.
    `nm -D`, scoped to dynamically-linked binaries only, only lists
    symbols actually imported, so it doesn't have that failure mode.
    """
    try:
        out = subprocess.run(
            ["nm", "-D", str(path)], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] == "U":
            names.add(parts[-1].split("@")[0])
    return names


def static_precheck(path: Union[str, Path]) -> dict:
    """
    Fast, non-symbolic triage: is this binary a plausible candidate for
    this tier, and roughly how expensive will it be? Deliberately crude
    -- meant to run before anything symbolic, not to be a precise
    classifier.

    Returns {"candidate": bool, "reason": str, "statically_linked": bool}
    """
    path = Path(path)
    if not _is_elf(path):
        return {"candidate": False, "reason": "not an ELF binary", "statically_linked": False}

    data = path.read_bytes()
    static_linked = (b"/lib64/ld-linux" not in data) and (b"/lib/ld-linux" not in data)

    if static_linked:
        # Can't reliably tell "service binary" from "crackme" here (see
        # _dynamic_imports docstring) -- just flag the cost, don't guess.
        return {
            "candidate": True,
            "reason": ("looks like a local crackme-style binary (statically linked -- confirmed "
                      "in testing this is much slower for angr, and network-import detection "
                      "doesn't work on static binaries; budget more time, or let an earlier tier "
                      "take it first)"),
            "statically_linked": True,
        }

    network_hit = _dynamic_imports(path) & _NETWORK_SYMS
    if network_hit:
        return {
            "candidate": False,
            "reason": f"imports network functions ({', '.join(sorted(network_hit))}) -- looks like a service binary, not a local crackme",
            "statically_linked": False,
        }

    return {"candidate": True, "reason": "looks like a local crackme-style binary", "statically_linked": False}


def recover_input(
    binary_path: Union[str, Path],
    *,
    input_mode: str = "argv",
    lengths: Sequence[int] = DEFAULT_LENGTHS,
    success_markers: Iterable[bytes] = DEFAULT_SUCCESS_MARKERS,
    failure_markers: Iterable[bytes] = DEFAULT_FAILURE_MARKERS,
    timeout_s: float = 60.0,
) -> SymbolicResult:
    """
    Try to symbolically recover an input (argv[1] or stdin) that drives
    `binary_path` to a state whose stdout contains one of
    `success_markers` without ever containing one of `failure_markers`.

    Tries each length in `lengths` in order, stopping at the first hit,
    sharing one wall-clock budget (`timeout_s`) across every attempt.
    """
    import angr
    try:
        from angr import claripy
    except ImportError:
        import claripy


    logging.getLogger("angr").setLevel(logging.ERROR)

    binary_path = str(binary_path)
    t0 = time.time()
    success_markers = tuple(success_markers)
    failure_markers = tuple(failure_markers)
    deadline = t0 + timeout_s

    proj = angr.Project(binary_path, auto_load_libs=False)

    for length in lengths:
        if time.time() >= deadline:
            break

        chars = [claripy.BVS(f"c{i}", 8) for i in range(length)]
        sym_input = claripy.Concat(*chars)

        if input_mode == "argv":
            state = proj.factory.entry_state(args=[binary_path, sym_input])
        elif input_mode == "stdin":
            state = proj.factory.entry_state(stdin=sym_input)
        else:
            raise ValueError("input_mode must be 'argv' or 'stdin'")

        for ch in chars:
            state.solver.add(ch != 0)
            state.solver.add(ch >= 0x20)
            state.solver.add(ch <= 0x7E)

        simgr = proj.factory.simgr(state)
        # manual stepping (not .explore()) so the deadline is actually honored
        while simgr.active and time.time() < deadline:
            simgr.step()
            simgr.move(
                from_stash="active", to_stash="found",
                filter_func=lambda s: any(m in s.posix.dumps(1) for m in success_markers),
            )
            simgr.move(
                from_stash="active", to_stash="avoid",
                filter_func=lambda s: any(m in s.posix.dumps(1) for m in failure_markers),
            )
            if simgr.found:
                break

        if simgr.found:
            solved = simgr.found[0].solver.eval(sym_input, cast_to=bytes)
            return SymbolicResult(
                success=True,
                recovered_input=solved,
                input_mode=input_mode,
                length_tried=length,
                elapsed_s=round(time.time() - t0, 2),
            )

    return SymbolicResult(
        success=False,
        elapsed_s=round(time.time() - t0, 2),
        note="no success state reached within the time/length budget",
    )


def simplify_obfuscated_expr(expr):
    """
    Z3-based cleanup for an obfuscated arithmetic/bitwise expression you
    already extracted (e.g. from static analysis of a check function).
    `expr` is a plain z3.BitVecRef -- this standalone helper doesn't talk
    to angr, so the angr/claripy class-identity gotcha above doesn't
    apply here; plain top-level `z3` is fine.

    Confirmed in testing: folds `(x ^ C) ^ C` down to `x`.
    """
    import z3
    return z3.simplify(expr)


def expressions_equivalent(a, b) -> bool:
    """
    True if two z3 BitVec expressions are equal for every input. Use this
    to confirm a guessed simpler form really matches the obfuscated
    original before trusting it.

    Confirmed in testing: proves the MBA identity
    (x & y) + (x | y) == x + y, and correctly rejects a wrong guess.
    """
    import z3
    s = z3.Solver()
    s.add(a != b)
    return s.check() == z3.unsat


def _target_path(ctx) -> Optional[str]:
    return (
        getattr(ctx, "target", None)
        or getattr(ctx, "target_path", None)
        or getattr(ctx, "path", None)
        or (str(ctx) if isinstance(ctx, (str, Path)) else None)
    )


def _looks_like_crackme_elf(ctx) -> bool:
    """Match function for the registry -- accepts either a SolverContext-
    like object or a plain path, to cover either calling convention."""
    path = _target_path(ctx)
    if not path:
        return False
    try:
        return static_precheck(path)["candidate"]
    except Exception:
        return False


@register_solver(name="symbolic_crackme", category="rev", priority=60, match_fn=_looks_like_crackme_elf)
def symbolic_solver(ctx) -> dict:
    """SolverContext-compatible entry point (fn(ctx) signature, per the
    registry's adapter)."""
    target_path = _target_path(ctx)
    if target_path is None:
        return {"solver": "symbolic_crackme", "success": False, "flags": []}

    pre = static_precheck(target_path)
    if not pre["candidate"]:
        log.debug("symbolic_solver skipping %s: %s", target_path, pre["reason"])
        return {"solver": "symbolic_crackme", "success": False, "flags": [], "reason": pre["reason"]}

    result = recover_input(target_path)
    if not result.success:
        return {"solver": "symbolic_crackme", "success": False, "flags": [], "elapsed_s": result.elapsed_s}

    rec_bytes = result.recovered_input or b""
    rec_str = rec_bytes.decode("latin-1", "replace")

    flags: list[dict] = []
    try:
        from ..flags import scan_text
        flags.extend(scan_text(rec_str))
    except Exception:
        pass
    if not flags and rec_str:
        flags.append({"flag": rec_str, "confidence": 0.9, "source": "symbolic_crackme"})

    return {
        "solver": "symbolic_crackme",
        "success": True,
        "flags": flags,
        "recovered_input": rec_str,
        "input_mode": result.input_mode,
        "confidence": "high",  # deterministic constraint solve, not a guess
        "elapsed_s": result.elapsed_s,
    }


def solve(target: str, workdir: str = "") -> dict:
    """Top-level solve interface matching KRYPT solver convention."""
    class _DummyCtx:
        pass
    ctx = _DummyCtx()
    ctx.target = target
    ctx.workdir = workdir
    return symbolic_solver(ctx)

