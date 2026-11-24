"""Unit tests for GodSolver optimizations: in-memory string solving, format inference, and ranking."""
from __future__ import annotations

import base64
import os
import pytest

from ctfsolver.god import GodSolver


def test_god_instant_raw_string_solve():
    """Verify that a raw base64 or encoded string passed directly as target solves in Phase 1."""
    gs = GodSolver(event="test")
    raw_flag = b"flag{fast_in_memory_string_solve}"
    encoded = base64.b64encode(raw_flag).decode("ascii")

    res = gs.solve(target=encoded, category="crypto")
    assert res["solved"] is True
    assert res["flag"] == "flag{fast_in_memory_string_solve}"
    assert "tier1_magic" in res["phases_run"]


def test_god_briefing_format_autoinference():
    """Verify that GodSolver automatically infers custom flag format from briefing."""
    gs = GodSolver(event="test")
    briefing = "Welcome to the CTF! The flag format is incursion{...}. Good luck!"
    target_str = "incursion{autoinferred_custom_flag_prefix}"

    res = gs.solve(target=target_str, briefing=briefing)
    assert res["solved"] is True
    assert res["flag"] == "incursion{autoinferred_custom_flag_prefix}"


def test_validate_flags_strips_quotes_and_filters_substrings():
    """Verify that _validate_flags cleans quotes and drops shorter substrings."""
    gs = GodSolver(event="test")
    flags = [
        {"flag": "'picoCTF{longer_full_flag}'", "confidence": 90},
        {"flag": "CTF{longer_full_flag}", "confidence": 90},
        {"flag": "\"flag{fake_placeholder}\"", "confidence": 50},
    ]
    valid = gs._validate_flags(flags)
    assert len(valid) == 1
    assert valid[0]["flag"] == "picoCTF{longer_full_flag}"
