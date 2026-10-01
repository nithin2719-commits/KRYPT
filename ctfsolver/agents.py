"""Deep-solve hand-off to an authenticated agent CLI that can drive the full
MCP tool suite (hexstrike-ai, ghidra, …).

SAFETY: this module does NOT spawn autonomous, auto-approving agents. It only
detects which agent CLIs are installed and *prepares* a command for the user to
run themselves (with normal per-tool approval prompts). Running an agent that
auto-approves every tool call is a decision for the operator, not something this
tool does on its own.
"""
from __future__ import annotations

import os
import shlex
import shutil

# Resolve robustly even if the server was started without ~/.local/bin on PATH.
_CANDIDATES = {
    "claude": ["claude", os.path.expanduser("~/.local/bin/claude"),
               "/usr/local/bin/claude", "/usr/bin/claude"],
    "agy": ["agy", "/usr/bin/agy", os.path.expanduser("~/.local/bin/agy"),
            "/usr/local/bin/agy"],
}


def _resolve(provider: str) -> str | None:
    for c in _CANDIDATES.get(provider, []):
        if os.path.basename(c) == c:            # bare name -> search PATH
            p = shutil.which(c)
        else:                                   # explicit path
            p = c if os.path.exists(c) else None
        if p:
            return p
    return None


PROMPT = (
    "Solve this AUTHORIZED CTF challenge and print the flag. "
    "Category: {category}. Target: {target}. {briefing}"
    "Automated triage already ran. {tools}"
    "Use your MCP tools to capture the flag, then print it prefixed with FLAG:."
)


def available() -> dict:
    """Which agent CLIs are installed (a plain lookup, nothing is run)."""
    return {p: _resolve(p) is not None for p in _CANDIDATES}


def _build_prompt(target: str, briefing: str, evidence: str, category: str) -> str:
    brief = f"Briefing: {briefing.strip()}\n" if briefing.strip() else ""
    try:
        from .categories import toolset
        t = toolset(category)
        tools = f"Prefer tools: {' | '.join(t['mcp'])}. Skills: {', '.join(t['skills'])}.\n"
    except Exception:
        tools = ""
    return (PROMPT.format(category=category, target=target, briefing=brief, tools=tools)
            + f"\n\nAutomated triage evidence:\n{evidence[:8000]}")


def run(provider: str, target: str, briefing: str, evidence: str, workdir: str,
        category: str = "auto", timeout: int = 300) -> dict:
    """Actually invoke the agent CLI (its own print mode, WITHOUT
    --dangerously-skip-permissions, so it stays bounded) and return its output.
    """
    import subprocess
    binpath = _resolve(provider)
    if not binpath:
        return {"ok": False, "provider": provider, "output": "",
                "error": f"{provider} CLI not found"}
    prompt = _build_prompt(target, briefing, evidence, category)
    argv = [binpath, "-p", prompt, "--add-dir", workdir]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=workdir)
        out = proc.stdout.decode("utf-8", "replace").strip()
        err = proc.stderr.decode("utf-8", "replace").strip()
        return {"ok": bool(out), "provider": provider, "output": out,
                "error": "" if out else (err[:600] or "no output")}
    except subprocess.TimeoutExpired:
        return {"ok": False, "provider": provider, "output": "",
                "error": f"agent timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "provider": provider, "output": "",
                "error": f"{type(e).__name__}: {e}"}


def command_for(provider: str, target: str, briefing: str, workdir: str,
                category: str = "auto") -> dict:
    """Return a ready-to-run command string for the operator (not executed).

    No --dangerously-skip-permissions: the agent will ask before each tool, so
    the operator stays in control.
    """
    brief = f"Briefing: {briefing.strip()} " if briefing.strip() else ""
    try:
        from .categories import toolset
        t = toolset(category)
        tools = f"Prefer these tools: {' | '.join(t['mcp'])}. Skills: {', '.join(t['skills'])}. "
    except Exception:
        tools = ""
    prompt = PROMPT.format(category=category, target=target, briefing=brief, tools=tools)
    binpath = _resolve(provider)
    if not binpath:
        return {"provider": provider, "command": "",
                "note": f"{provider} CLI not found"}
    argv = [binpath, "-p", prompt, "--add-dir", workdir]
    return {
        "provider": provider,
        "command": " ".join(shlex.quote(a) for a in argv),
        "note": ("Run this in your terminal to let the agent drive the MCP "
                 "tools (it will prompt before each tool). Add "
                 "--dangerously-skip-permissions yourself only if you want it "
                 "fully autonomous."),
    }
