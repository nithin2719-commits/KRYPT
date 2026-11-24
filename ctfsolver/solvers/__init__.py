"""Solvers package for KRYPT autonomous CTF solver.

Exposes the plugin registration API and dynamic solver registry.
"""
from __future__ import annotations

from .registry import (
    RegisteredSolver,
    SolverContext,
    auto_discover,
    clear_registry,
    get_matching_solvers,
    get_registry,
    register,
    register_solver,
)

__all__ = [
    "RegisteredSolver",
    "SolverContext",
    "auto_discover",
    "clear_registry",
    "get_matching_solvers",
    "get_registry",
    "register",
    "register_solver",
]
