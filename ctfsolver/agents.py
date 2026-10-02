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
    "You are KRYPT, an expert CTF player solving ONE authorized challenge. "
    "This is a sanctioned competition/practice environment, so analysis of the "
    "provided artifact is in scope.\n\n"
    "Category: {category}. Target: {target}.\n{briefing}"
    "A deterministic triage pass already ran; its evidence is appended below — "
    "read it FIRST and do not repeat work it already did.\n\n"
    "{tools}"
    "Method — work the funnel, cheapest first, and stop the moment the real "
    "flag is in hand:\n"
    "1. Orient: confirm the file type / target and what the triage evidence "
    "already revealed. Form a hypothesis about where the flag hides.\n"
    "2. Act on the single most promising lead with the fitting tool. One focused "
    "step at a time; let each result steer the next.\n"
    "3. Recurse only when needed: decode nested layers, carve embedded data, "
    "or escalate to the category's heavier tools if the cheap wins ran dry.\n"
    "4. Verify: the flag MUST match the challenge's flag format{fmt}. If what "
    "you found does not match the format, it is not the flag — keep going.\n\n"
    "Rules: never invent, guess, or 'reconstruct' a flag — only report one you "
    "actually recovered from the artifact and can point to the step that "
    "produced it. If you genuinely cannot capture it, say so and list the most "
    "promising next lead instead of fabricating.\n\n"
    "Output, in this order:\n"
    "  FLAG: <the exact verified flag>   (omit this line entirely if not found)\n"
    "  METHOD: 2-5 sentences — the path that worked, naming the decisive tool/step.\n"
    "  EVIDENCE: the concrete output (hash cracked, decoded string, decompiled "
    "check, carved offset) that proves the flag is real."
)


def _fmt_hint() -> str:
    """Flag-format clause for the prompt, from CTF_FLAG_FORMAT if the operator
    set one for this event (e.g. 'picoCTF\\{[^}]+\\}'). Empty otherwise."""
    fmt = (os.environ.get("CTF_FLAG_FORMAT") or "").strip()
    return f" (regex: {fmt})" if fmt else ""


def available() -> dict:
    """Which agent CLIs are installed (a plain lookup, nothing is run)."""
    return {p: _resolve(p) is not None for p in _CANDIDATES}


def _build_prompt(target: str, briefing: str, evidence: str, category: str) -> str:
    brief = f"Briefing: {briefing.strip()}\n" if briefing.strip() else ""
    try:
        from .categories import toolset
        t = toolset(category)
        tools = ("You have LIVE MCP analysis tools — call them directly to work the "
                 "artifact: ghidra (decompile_function, disassemble, list_xrefs, "
                 "search_strings) for reversing, and hexstrike static analyzers "
                 "(strings_extract, binwalk_analyze, checksec_analyze, radare2_analyze, "
                 "angr_symbolic_execution, exiftool_extract, steghide_analysis). "
                 f"Prefer: {' | '.join(t['mcp'])}. Skills: {', '.join(t['skills'])}.\n")
    except Exception:
        tools = ""
    return (PROMPT.format(category=category, target=target, briefing=brief,
                          tools=tools, fmt=_fmt_hint())
            + f"\n\nAutomated triage evidence:\n{evidence[:8000]}")


# Least-privilege MCP allowlist for autonomous runs: the claude engine may call
# these WITHOUT --dangerously-skip-permissions. Deliberately READ-ONLY analysis
# only — all of ghidra (static RE) plus hexstrike's static/forensic analyzers.
# It intentionally EXCLUDES every shell/exec, network-attack, credential, and
# file-write tool (execute_command, execute_python_script, metasploit_run,
# msfvenom_generate, hydra_attack, the *_scan network tools, create/modify/
# delete_file, install_python_package, pwntools_exploit, ...). Those stay behind
# human approval via the prepared-command handoff.
SAFE_MCP_TOOLS = [
    "mcp__ghidra__*",                         # read-only reverse engineering
    "mcp__hexstrike-ai__strings_extract",
    "mcp__hexstrike-ai__xxd_hexdump",
    "mcp__hexstrike-ai__objdump_analyze",
    "mcp__hexstrike-ai__binwalk_analyze",
    "mcp__hexstrike-ai__checksec_analyze",
    "mcp__hexstrike-ai__exiftool_extract",
    "mcp__hexstrike-ai__steghide_analysis",
    "mcp__hexstrike-ai__foremost_carving",
    "mcp__hexstrike-ai__radare2_analyze",
    "mcp__hexstrike-ai__ghidra_analysis",
    "mcp__hexstrike-ai__angr_symbolic_execution",
    "mcp__hexstrike-ai__ropgadget_search",
    "mcp__hexstrike-ai__ropper_gadget_search",
    "mcp__hexstrike-ai__one_gadget_search",
    "mcp__hexstrike-ai__libc_database_lookup",
    "mcp__hexstrike-ai__volatility3_analyze",
    "mcp__hexstrike-ai__volatility_analyze",
]


def _mcp_args(provider: str) -> list:
    """Scoped MCP permission flags. Only the claude CLI supports a non-interactive
    allowlist (--allowedTools); agy only offers blanket --dangerously-skip-
    permissions, which we never add, so it gets no auto-approved MCP access."""
    if provider == "claude":
        return ["--allowedTools", *SAFE_MCP_TOOLS]
    return []


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
    argv = [binpath, "-p", prompt, "--add-dir", workdir, *_mcp_args(provider)]
    # give the agent access to the challenge file's directory too
    if os.path.isfile(target):
        d = os.path.dirname(os.path.abspath(target))
        if d and d != workdir:
            argv += ["--add-dir", d]
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
    prompt = PROMPT.format(category=category, target=target, briefing=brief,
                           tools=tools, fmt=_fmt_hint())
    binpath = _resolve(provider)
    if not binpath:
        return {"provider": provider, "command": "",
                "note": f"{provider} CLI not found"}
    argv = [binpath, "-p", prompt, "--add-dir", workdir, *_mcp_args(provider)]
    if provider == "agy":
        # agy has no scoped allowlist (unlike claude's --allowedTools), so the
        # only way for it to run its 150 hexstrike tools unattended is blanket
        # --dangerously-skip-permissions. We put that in the HANDED-OFF command
        # for the operator to run in their own terminal — never auto-executed by
        # the server — so a web request can't trigger arbitrary shell / metasploit
        # / pacu / delete_file on adversarial challenge input.
        argv.append("--dangerously-skip-permissions")
        note = ("agy has no read-only allowlist, so this command auto-approves "
                "ALL its tools (incl. execute_command, metasploit, hydra, pacu, "
                "delete_file). Run it yourself in a terminal where you can watch "
                "and Ctrl-C it; don't point it at hosts you're not authorized to "
                "test. Add --sandbox to restrict agy's own shell.")
    else:
        note = ("Run this in your terminal to drive the MCP tools. The claude "
                "engine auto-approves only a read-only analysis allowlist "
                "(ghidra + hexstrike static tools); it will still prompt for "
                "anything else. Add --dangerously-skip-permissions yourself "
                "only if you want it fully autonomous.")
    return {
        "provider": provider,
        "command": " ".join(shlex.quote(a) for a in argv),
        "note": note,
    }
