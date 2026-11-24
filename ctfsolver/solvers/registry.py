"""Plugin loader and decorator-based registration system for KRYPT solvers.

Allows solver modules under `ctfsolver/solvers/` to register themselves with
matching conditions (file extensions, categories, text patterns, custom matchers)
and priorities. The apex solver (`god.py`) auto-discovers and queries all registered
solvers rather than hardcoding them.
"""
from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class SolverContext:
    """Execution context provided to solvers."""
    target: str = ""
    briefing: str = ""
    combined_text: str = ""
    category: str = "auto"
    workdir: str = ""
    file_info: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RegisteredSolver:
    """Specification of a registered solver plugin."""
    name: str
    fn: Callable[[SolverContext], dict[str, Any]]
    category: str = "all"
    priority: int = 50
    match_ext: tuple[str, ...] = ()
    match_fn: Optional[Callable[[SolverContext], bool]] = None
    description: str = ""

    def matches(self, ctx: SolverContext) -> bool:
        """Evaluate whether this solver should execute on the given context."""
        # 1. Custom matching function has highest precedence
        if self.match_fn is not None:
            try:
                if self.match_fn(ctx):
                    return True
            except Exception:
                pass

        # 2. File extension match
        if self.match_ext and ctx.target:
            target_lower = ctx.target.lower()
            if any(target_lower.endswith(ext.lower()) for ext in self.match_ext):
                return True

        # 3. Explicit category match
        if self.category != "all" and ctx.category not in ("auto", "all", ""):
            if self.category.lower() == ctx.category.lower():
                return True

        return False


_REGISTRY: dict[str, RegisteredSolver] = {}
_DISCOVERED: bool = False


def register(solver: RegisteredSolver) -> None:
    """Register a solver specification."""
    _REGISTRY[solver.name] = solver


def get_registry() -> dict[str, RegisteredSolver]:
    """Return a copy of the active registry."""
    return dict(_REGISTRY)


def clear_registry() -> None:
    """Reset the registry (useful for unit testing)."""
    global _DISCOVERED
    _REGISTRY.clear()
    _DISCOVERED = False


def register_solver(
    name: str,
    category: str = "all",
    priority: int = 50,
    match_ext: tuple[str, ...] | list[str] = (),
    match_fn: Optional[Callable[[SolverContext], bool]] = None,
    description: str = "",
) -> Callable[[Callable], Callable]:
    """Decorator to register a solver function or module entry point.

    The decorated function can either accept:
      - `(ctx: SolverContext) -> dict[str, Any]`
      - `(target: str, workdir: str) -> dict[str, Any]` (auto-adapted)
      - `(text: str) -> dict[str, Any]` (auto-adapted)
    """
    exts = tuple(match_ext) if isinstance(match_ext, list) else match_ext

    def decorator(fn: Callable) -> Callable:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())

        if len(params) == 1 and params[0].name in ("ctx", "context"):
            adapted_fn = fn
        elif len(params) >= 2 and params[0].name in ("target", "path", "path_or_text") and params[1].name in ("workdir", "safe_workdir"):
            def adapted_fn(ctx: SolverContext) -> dict[str, Any]:
                return fn(ctx.target or ctx.combined_text, ctx.workdir)
        elif len(params) == 1 and params[0].name in ("text", "content", "code_block", "text_or_target"):
            def adapted_fn(ctx: SolverContext) -> dict[str, Any]:
                return fn(ctx.combined_text or ctx.target)
        else:
            # Fallback signature adapter
            def adapted_fn(ctx: SolverContext) -> dict[str, Any]:
                try:
                    return fn(ctx)
                except TypeError:
                    return fn(ctx.target, ctx.workdir)

        spec = RegisteredSolver(
            name=name,
            fn=adapted_fn,
            category=category,
            priority=priority,
            match_ext=exts,
            match_fn=match_fn,
            description=description or (fn.__doc__ or "").strip(),
        )
        register(spec)
        return fn

    return decorator


def register_builtin_solvers() -> None:
    """Register built-in solvers with their default triggers if not already present."""
    if "z3" not in _REGISTRY:
        def match_z3(ctx: SolverContext) -> bool:
            return bool(ctx.combined_text and any(sym in ctx.combined_text for sym in ("^", "==", "+", "-", "*", "flag[", "input[")))

        def run_z3(ctx: SolverContext) -> dict[str, Any]:
            from . import z3_solve
            return z3_solve.scan_and_solve(ctx.combined_text)

        register(RegisteredSolver(
            name="z3",
            fn=run_z3,
            category="crypto",
            priority=90,
            match_fn=match_z3,
            description="Z3 symbolic constraint solver for character equation systems",
        ))

    if "rsa_attacks" not in _REGISTRY:
        def match_rsa(ctx: SolverContext) -> bool:
            txt = ctx.combined_text.lower()
            return "begin" in txt or any(k in txt for k in ("n =", "e =", "c =", "n:", "e:", "c:")) or ctx.category == "crypto"

        def run_rsa(ctx: SolverContext) -> dict[str, Any]:
            from . import rsa_attacks
            return rsa_attacks.solve(ctx.target or ctx.combined_text, ctx.workdir)

        register(RegisteredSolver(
            name="rsa_attacks",
            fn=run_rsa,
            category="crypto",
            priority=85,
            match_ext=(".pem", ".key", ".rsa", ".txt"),
            match_fn=match_rsa,
            description="Pure-Python RSA attack suite (small-e, Wiener, Fermat, Pollard, Hastad)",
        ))

    if "sage_crypto" not in _REGISTRY:
        def match_sage(ctx: SolverContext) -> bool:
            txt = ctx.combined_text.lower()
            return "begin" in txt or any(k in txt for k in ("n =", "e =", "c ="))

        def run_sage(ctx: SolverContext) -> dict[str, Any]:
            from . import sage_crypto
            return sage_crypto.parse_and_attack(ctx.combined_text)

        register(RegisteredSolver(
            name="sage",
            fn=run_sage,
            category="crypto",
            priority=80,
            match_fn=match_sage,
            description="SageMath lattice attacks (Coppersmith small roots, common modulus, Hastad CRT)",
        ))

    if "xor_solver" not in _REGISTRY:
        def match_xor(ctx: SolverContext) -> bool:
            if ctx.category == "crypto":
                return True
            if ctx.combined_text:
                return True
            if ctx.target:
                lower = ctx.target.lower()
                return lower.endswith((".xor", ".bin", ".dat", ".txt", ".enc", ".raw", ".cipher")) or "." not in os.path.basename(ctx.target)
            return False

        def run_xor(ctx: SolverContext) -> dict[str, Any]:
            from . import xor_solver
            return xor_solver.solve(ctx.target or ctx.combined_text, ctx.workdir)

        register(RegisteredSolver(
            name="xor_solver",
            fn=run_xor,
            category="crypto",
            priority=75,
            match_fn=match_xor,
            description="Pure-Python XOR cryptanalysis (single-byte, repeating-key Kasiski, many-time pad)",
        ))

    if "qr" not in _REGISTRY:
        def run_qr(ctx: SolverContext) -> dict[str, Any]:
            from . import qr_visual
            return qr_visual.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="qr",
            fn=run_qr,
            category="forensics",
            priority=70,
            match_ext=(".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"),
            description="Visual stego, QR / Barcode reader and multichannel bitplane extraction",
        ))

    if "png_forensics" not in _REGISTRY:
        def run_png(ctx: SolverContext) -> dict[str, Any]:
            from . import png_forensics
            return png_forensics.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="png_forensics",
            fn=run_png,
            category="forensics",
            priority=72,
            match_ext=(".png",),
            description="PNG structural forensics (tEXt chunks, IHDR CRC dimension repair, trailing IEND)",
        ))

    if "audio" not in _REGISTRY:
        def run_audio(ctx: SolverContext) -> dict[str, Any]:
            from . import audio_deep
            return audio_deep.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="audio",
            fn=run_audio,
            category="forensics",
            priority=65,
            match_ext=(".wav", ".mp3", ".ogg", ".flac"),
            description="Audio forensics (DTMF tone demodulator and 16-bit PCM sample LSB extraction)",
        ))

    if "pcap" not in _REGISTRY:
        def run_pcap(ctx: SolverContext) -> dict[str, Any]:
            from . import pcap_deep
            return pcap_deep.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="pcap",
            fn=run_pcap,
            category="network",
            priority=65,
            match_ext=(".pcap", ".pcapng", ".cap"),
            description="Deep PCAP packet analysis (ICMP tunnels, credential extraction, TCP reassembly)",
        ))

    if "doc" not in _REGISTRY:
        def run_doc(ctx: SolverContext) -> dict[str, Any]:
            from . import doc_carve
            return doc_carve.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="doc",
            fn=run_doc,
            category="forensics",
            priority=60,
            match_ext=(".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods"),
            description="Document forensics (PDF FlateDecode streams, attachments, Office XML comments)",
        ))

    if "zip_forensics" not in _REGISTRY:
        def run_zip(ctx: SolverContext) -> dict[str, Any]:
            from . import zip_forensics
            return zip_forensics.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="zip_forensics",
            fn=run_zip,
            category="forensics",
            priority=68,
            match_ext=(".zip", ".jar", ".apk"),
            description="ZIP forensics (pseudo-encryption bypass, small-file CRC32 recovery, comments)",
        ))

    if "volatility" not in _REGISTRY:
        def match_vol(ctx: SolverContext) -> bool:
            if not ctx.target or not os.path.isfile(ctx.target):
                return False
            from . import volatility_solve
            return volatility_solve.is_memory_dump(ctx.target)

        def run_vol(ctx: SolverContext) -> dict[str, Any]:
            from . import volatility_solve
            return volatility_solve.run_volatility_plugins(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="volatility",
            fn=run_vol,
            category="forensics",
            priority=55,
            match_fn=match_vol,
            description="Volatility 3 automated memory dump plugin forensics",
        ))

    if "esoteric" not in _REGISTRY:
        def match_eso(ctx: SolverContext) -> bool:
            return bool(ctx.combined_text)

        def run_eso(ctx: SolverContext) -> dict[str, Any]:
            from . import esoteric_ciphers
            res = esoteric_ciphers.solve(ctx.combined_text)
            e_flags = []
            for r in res:
                e_flags.extend(r.get("flags", []))
            return {"flags": e_flags, "output": f"Esoteric ciphers evaluated {len(res)} method(s)"}

        register(RegisteredSolver(
            name="esoteric",
            fn=run_eso,
            category="crypto",
            priority=50,
            match_fn=match_eso,
            description="Esoteric ciphers (DNA, T9 keypad, NATO phonetics, Polybius, Rail fence)",
        ))

    if "sidechannel" not in _REGISTRY:
        def match_side(ctx: SolverContext) -> bool:
            return bool(ctx.target and os.path.isfile(ctx.target) and os.access(ctx.target, os.X_OK))

        def run_side(ctx: SolverContext) -> dict[str, Any]:
            from . import sidechannel_solve
            return sidechannel_solve.solve(ctx.target, ctx.workdir)

        register(RegisteredSolver(
            name="sidechannel",
            fn=run_side,
            category="rev",
            priority=45,
            match_fn=match_side,
            description="Side-channel instruction counting and timing crackme analysis",
        ))


def auto_discover() -> None:
    """Auto-discover all solver modules in ctfsolver/solvers/ and load them."""
    global _DISCOVERED
    if _DISCOVERED:
        return

    # First register built-ins so they are available
    register_builtin_solvers()

    # Discover and import all modules under ctfsolver.solvers
    pkg_dir = os.path.dirname(__file__)
    pkg_name = __package__ or "ctfsolver.solvers"

    for _, module_name, is_pkg in pkgutil.iter_modules([pkg_dir]):
        if module_name in ("registry", "__main__") or is_pkg:
            continue
        full_module_name = f"{pkg_name}.{module_name}"
        try:
            importlib.import_module(full_module_name)
        except Exception:
            # Solvers with missing optional dependencies or syntax fallbacks are skipped
            pass

    _DISCOVERED = True


def get_matching_solvers(ctx: SolverContext, auto_load: bool = True) -> list[RegisteredSolver]:
    """Return all solvers matching the context, sorted by descending priority."""
    if auto_load:
        auto_discover()
    matched = [s for s in _REGISTRY.values() if s.matches(ctx)]
    matched.sort(key=lambda s: s.priority, reverse=True)
    return matched
