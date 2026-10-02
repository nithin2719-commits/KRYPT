"""AI solve engine via the Anthropic Messages API (bring your own key).

Unlike ai.py (local Ollama, text-only) this can SEE the challenge image — which is
exactly what the deterministic triage can't do. When the clue is rendered in a
picture (a letter, a cipher, text drawn on pixels, an emphasised acrostic, a QR),
this engine reads it, reasons about it, and recovers the flag.

KRYPT has no pip dependencies, so this is raw HTTP via urllib — not the anthropic
SDK. Key resolution order:
  1. $ANTHROPIC_API_KEY
  2. ~/.config/krypt/config.json  ->  {"anthropic_api_key": "sk-ant-..."}
Model: $KRYPT_API_MODEL, else claude-opus-5.
"""
from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
CFG_PATH = os.path.expanduser("~/.config/krypt/config.json")
DEFAULT_MODEL = os.environ.get("KRYPT_API_MODEL", "claude-opus-5")
MAX_IMAGE_BYTES = 3_500_000  # ~3.5MB raw -> ~4.7MB base64, under the API's 5MB cap

_IMG_MEDIA = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
              ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/png"}

SYSTEM = (
    "You are KRYPT, an elite CTF player solving ONE authorized challenge in a "
    "sanctioned competition/practice environment, so full analysis of the provided "
    "artifact is in scope.\n\n"
    "Use everything you are given: the deterministic triage evidence, the operator "
    "briefing, and — crucially — anything you can SEE in an attached image. Images "
    "often hide the answer in rendered text, a cipher, stego, a QR code, or visual "
    "emphasis (bold/coloured/starred words forming an acrostic or a key). Read the "
    "whole image, including faint, marginal, or decorative text.\n\n"
    "Work the funnel cheapest-first and stop the moment the real flag is in hand. "
    "Classic ciphers (Caesar/Vigenere/Beaufort/substitution/XOR/base-N), stego, and "
    "multi-step chains (find a key, then decrypt) are all fair game — do the actual "
    "math.\n\n"
    "Rules: never invent, guess, or 'reconstruct' a flag — only report one you truly "
    "recovered and can justify from the artifact. If a flag format is given, the "
    "answer MUST match it; if what you have does not match, keep going.\n\n"
    "Output a few brief lines on the decisive steps, then end with EXACTLY one line:\n"
    "FLAG: <the exact flag>\n"
    "If you genuinely cannot recover it, do NOT write a FLAG: line at all — instead "
    "write 'NOT RECOVERED' and name the single most promising next lead."
)


def _load_key() -> str:
    k = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if k:
        return k
    try:
        with open(CFG_PATH) as fh:
            return (json.load(fh).get("anthropic_api_key") or "").strip()
    except Exception:
        return ""


def available() -> bool:
    return bool(_load_key())


def _fmt_regex(fmt: str) -> str:
    fmt = (fmt or "").strip()
    if not fmt:
        return ""
    if any(c in fmt for c in "[]*\\") or "+}" in fmt:
        return fmt
    m = re.match(r"([A-Za-z0-9_]{1,24})\{", fmt)
    if m:
        return re.escape(m.group(1)) + r"\{[^}]+\}"
    return re.escape(fmt.rstrip("{} .")) + r"\{[^}]+\}"


def _downscale(path: str):
    """Shrink an oversized image so it fits the API cap. PIL if present, else None."""
    try:
        import io

        from PIL import Image
        im = Image.open(path)
        im.thumbnail((1600, 1600))
        if im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        buf = io.BytesIO()
        im.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    except Exception:
        return None


def _image_block(path: str):
    ext = os.path.splitext(path)[1].lower()
    media = _IMG_MEDIA.get(ext)
    if not media:
        return None
    try:
        data = open(path, "rb").read()
        if len(data) > MAX_IMAGE_BYTES:
            data = _downscale(path)
            if not data or len(data) > MAX_IMAGE_BYTES * 1.3:
                return None
            media = "image/png"
        return {"type": "image", "source": {"type": "base64",
                "media_type": media, "data": base64.b64encode(data).decode()}}
    except Exception:
        return None


def _extract_flag(text: str, flag_format: str):
    for m in re.finditer(r"(?im)^\s*FLAG:\s*(\S.*)$", text):
        cand = m.group(1).strip().strip("`* ")
        low = cand.lower()
        if cand and "not " not in low and not cand.startswith("("):
            return cand
    rx = _fmt_regex(flag_format)
    if rx:
        try:
            m = re.search(rx, text)
            if m:
                return m.group(0)
        except re.error:
            pass
    m = re.search(r"[A-Za-z0-9_]{2,20}\{[^}\n]{1,200}\}", text)
    return m.group(0) if m else None


def solve(target: str, briefing: str, evidence: str, flag_format: str = "",
          category: str = "auto", model: str | None = None,
          timeout: int = 300) -> dict:
    """Send the challenge (image + text context) to Claude and return the flag.

    Returns {ok, flag, output, error, model, usage}."""
    key = _load_key()
    if not key:
        return {"ok": False, "flag": None, "output": "",
                "error": "no API key — set ANTHROPIC_API_KEY or put "
                         '{"anthropic_api_key": "sk-ant-..."} in ~/.config/krypt/config.json'}
    model = model or DEFAULT_MODEL
    parts = []
    img = _image_block(target) if (target and os.path.isfile(target)) else None
    if img:
        parts.append(img)
    ctx = [f"Category: {category}."]
    if target:
        ctx.append(f"Target: {target}")
    if (flag_format or "").strip():
        ctx.append(f"Flag format: {flag_format.strip()}")
    if (briefing or "").strip():
        ctx.append(f"Operator briefing:\n{briefing.strip()}")
    if evidence:
        ctx.append(f"Deterministic triage evidence (already run — build on it, "
                   f"don't repeat it):\n{evidence[:12000]}")
    if img:
        ctx.append("The challenge image is attached above. Read it closely, "
                   "including faint, marginal, decorative, or emphasised text.")
    parts.append({"type": "text", "text": "\n\n".join(ctx)})

    body = {
        "model": model,
        "max_tokens": 8000,
        "system": SYSTEM,
        "thinking": {"type": "adaptive"},
        "messages": [{"role": "user", "content": parts}],
    }
    req = urllib.request.Request(
        API_URL, json.dumps(body).encode(),
        {"content-type": "application/json", "x-api-key": key,
         "anthropic-version": API_VERSION})
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:600]
        return {"ok": False, "flag": None, "output": "",
                "error": f"API HTTP {e.code}: {detail}", "model": model}
    except Exception as e:
        return {"ok": False, "flag": None, "output": "",
                "error": f"{type(e).__name__}: {e}", "model": model}

    if resp.get("stop_reason") == "refusal":
        return {"ok": False, "flag": None, "output": "",
                "error": "model declined this request (refusal)", "model": model}
    text = "".join(b.get("text", "") for b in resp.get("content", [])
                   if b.get("type") == "text").strip()
    flag = _extract_flag(text, flag_format)
    return {"ok": bool(flag), "flag": flag, "output": text or "(no text returned)",
            "error": "" if text else "empty response", "model": model,
            "usage": resp.get("usage", {})}
