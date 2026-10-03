"""Optional local-LLM assist via Ollama (uses the GPU). Off unless --ai is passed.

This is a *fallback* reasoner for offline use. When you run the solver inside
Claude Code, Claude is the primary brain and this is usually unnecessary.
"""
from __future__ import annotations

import json
import os
import urllib.request

HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

# Prefer a cybersecurity-tuned model that fits the GPU (RTX 3070 Ti, 8GB VRAM),
# then a strong general/code model. Matched as substrings against installed tags.
_PREFERRED = [
    "whiterabbitneo-v1.5a",     # ~4.1GB — security-tuned, fits VRAM, fast
    "whiterabbit-neo",          # ~9.2GB — classic WhiteRabbitNeo pentest
    "whiterabbitneo",           # any other WhiteRabbitNeo build
    "notmythos",                # small cybersec model
    "qwen2.5-coder",            # strong code model (fallback)
]


def _list_models() -> list[str]:
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=3) as r:
            return [m.get("name", "") for m in json.load(r).get("models", [])]
    except Exception:
        return []


def best_model() -> str:
    env = os.environ.get("CTF_OLLAMA_MODEL")
    if env:
        return env
    names = _list_models()
    for pref in _PREFERRED:
        for n in names:
            if pref.lower() in n.lower():
                return n
    return names[0] if names else "qwen2.5-coder:7b"


# Resolved lazily (and cached) on first use — importing this module must NOT
# make a network call, or every GUI/CLI startup blocks on the Ollama probe
# (up to 3s) when Ollama is down.
_MODEL_CACHE: str | None = None


def default_model() -> str:
    """The model the LOCAL engine will use; resolved once, then cached."""
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        _MODEL_CACHE = best_model()
    return _MODEL_CACHE


SYSTEM = (
    "You are a CTF assistant. Given triage evidence from a challenge, state the "
    "most likely category, the single best next command to run, and any flag you "
    "can already see. Be terse. Never invent a flag; only report one present in "
    "the evidence."
)


def available(model: str | None = None) -> bool:
    model = model or default_model()
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=3) as r:
            tags = json.load(r)
        names = {m.get("name", "") for m in tags.get("models", [])}
        return any(model.split(":")[0] in n for n in names)
    except Exception:
        return False


def ask(evidence: str, model: str | None = None, timeout: int = 120) -> str:
    model = model or default_model()
    payload = {
        "model": model,
        "system": SYSTEM,
        "prompt": evidence[:12000],
        "stream": False,
        "options": {"temperature": 0.1},
    }
    req = urllib.request.Request(
        f"{HOST}/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r).get("response", "").strip()
    except Exception as e:
        return f"(ollama unavailable: {e})"
