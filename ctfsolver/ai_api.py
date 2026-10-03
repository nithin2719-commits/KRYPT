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
USAGE_PATH = os.path.expanduser("~/.config/krypt/usage.json")
DEFAULT_MODEL = os.environ.get("KRYPT_API_MODEL", "claude-opus-5")
MAX_IMAGE_BYTES = 3_500_000  # ~3.5MB raw -> ~4.7MB base64, under the API's 5MB cap

# $ per 1M tokens (input, output). The Messages API does not return an account
# credit balance, so KRYPT estimates spend from returned token usage × these
# rates and tracks it locally against a per-account budget you set.
PRICES = {
    "claude-opus-5": (5.0, 25.0), "claude-opus-4-8": (5.0, 25.0),
    "claude-opus-4-7": (5.0, 25.0), "claude-opus-4-6": (5.0, 25.0),
    "claude-sonnet-5": (2.0, 10.0), "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-fable-5-1": (10.0, 50.0), "claude-fable-5": (10.0, 50.0),
}
DEFAULT_PRICE = (5.0, 25.0)

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


def _load_accounts() -> list:
    """Accounts to rotate through, in priority order. Supports:
      {"anthropic_api_keys": [{"name","key","budget_usd"}, ...]}  (multi-account)
      {"anthropic_api_key": "sk-ant-..."}                         (single, legacy)
      $ANTHROPIC_API_KEY                                          (env)
    budget_usd None/absent = unlimited."""
    accts, seen = [], set()
    cfg = {}
    try:
        with open(CFG_PATH) as fh:
            cfg = json.load(fh)
    except Exception:
        cfg = {}
    for a in (cfg.get("anthropic_api_keys") or []):
        key = (a.get("key") or "").strip()
        if key and key not in seen:
            seen.add(key)
            accts.append({"name": a.get("name") or f"acct{len(accts)+1}",
                          "key": key, "budget_usd": a.get("budget_usd")})
    single = (cfg.get("anthropic_api_key") or "").strip()
    if single and single not in seen:
        seen.add(single)
        accts.append({"name": "default", "key": single, "budget_usd": None})
    env = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if env and env not in seen:
        accts.append({"name": "env", "key": env, "budget_usd": None})
    return accts


def _load_usage() -> dict:
    try:
        with open(USAGE_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_usage(u: dict) -> None:
    try:
        os.makedirs(os.path.dirname(USAGE_PATH), exist_ok=True)
        tmp = USAGE_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(u, fh)
        os.replace(tmp, USAGE_PATH)
    except Exception:
        pass


def _cost(model: str, usage: dict) -> float:
    pin, pout = PRICES.get(model, DEFAULT_PRICE)
    it = usage.get("input_tokens", 0) + usage.get("cache_read_input_tokens", 0) \
        + usage.get("cache_creation_input_tokens", 0)
    ot = usage.get("output_tokens", 0)
    return it / 1e6 * pin + ot / 1e6 * pout


def _record(name: str, model: str, usage: dict) -> float:
    cost = _cost(model, usage)
    u = _load_usage()
    rec = u.get(name) or {"input_tokens": 0, "output_tokens": 0,
                          "cost_usd": 0.0, "requests": 0}
    rec["input_tokens"] += usage.get("input_tokens", 0)
    rec["output_tokens"] += usage.get("output_tokens", 0)
    rec["cost_usd"] = round(rec["cost_usd"] + cost, 6)
    rec["requests"] += 1
    u[name] = rec
    _save_usage(u)
    return cost


def _spent(name: str) -> float:
    return float((_load_usage().get(name) or {}).get("cost_usd", 0.0))


def _has_budget(acct: dict) -> bool:
    b = acct.get("budget_usd")
    return b is None or _spent(acct["name"]) < float(b)


def _pick_account(exclude=()):
    """First account (in config order) that still has budget; else the one with the
    most headroom; else None."""
    accts = [a for a in _load_accounts() if a["key"] not in exclude]
    if not accts:
        return None
    for a in accts:
        if _has_budget(a):
            return a
    return None


def available() -> bool:
    return bool(_load_accounts())


def status() -> dict:
    """Per-account spend/budget/remaining for the UI."""
    out = []
    for a in _load_accounts():
        spent = _spent(a["name"])
        b = a.get("budget_usd")
        out.append({"name": a["name"], "budget_usd": b,
                    "spent_usd": round(spent, 4),
                    "remaining_usd": (None if b is None else round(float(b) - spent, 4)),
                    "has_budget": _has_budget(a)})
    active = _pick_account()
    return {"accounts": out, "active": active["name"] if active else None,
            "model": DEFAULT_MODEL}


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

    Rotates across configured accounts by remaining credit, failing over to the
    next on a 429/credit error. Records token usage + estimated cost per account.
    Returns {ok, flag, output, error, model, usage, cost_usd, account}."""
    if not _load_accounts():
        return {"ok": False, "flag": None, "output": "",
                "error": "no API key — put {\"anthropic_api_key\": \"sk-ant-...\"} (or "
                         "an \"anthropic_api_keys\" list) in ~/.config/krypt/config.json"}
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

    body = json.dumps({
        "model": model,
        "max_tokens": 8000,
        "system": SYSTEM,
        "thinking": {"type": "adaptive"},
        "messages": [{"role": "user", "content": parts}],
    }).encode()

    tried, last_err = set(), "no usable account"
    while True:
        acct = _pick_account(exclude=tried)
        if not acct:
            return {"ok": False, "flag": None, "output": "",
                    "error": f"all accounts exhausted or failing ({last_err})",
                    "model": model}
        tried.add(acct["key"])
        req = urllib.request.Request(
            API_URL, body,
            {"content-type": "application/json", "x-api-key": acct["key"],
             "anthropic-version": API_VERSION})
        try:
            resp = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            last_err = f"{acct['name']}: HTTP {e.code} {detail}"
            # 429 rate-limit or 400/402 credit issues -> fail over to next account
            if e.code in (429, 402, 529) or "credit" in detail.lower():
                continue
            return {"ok": False, "flag": None, "output": "",
                    "error": f"API {last_err}", "model": model, "account": acct["name"]}
        except Exception as e:
            last_err = f"{acct['name']}: {type(e).__name__}: {e}"
            continue

        if resp.get("stop_reason") == "refusal":
            return {"ok": False, "flag": None, "output": "", "account": acct["name"],
                    "error": "model declined this request (refusal)", "model": model}
        usage = resp.get("usage", {}) or {}
        cost = _record(acct["name"], model, usage)
        text = "".join(b.get("text", "") for b in resp.get("content", [])
                       if b.get("type") == "text").strip()
        flag = _extract_flag(text, flag_format)
        return {"ok": bool(flag), "flag": flag,
                "output": text or "(no text returned)",
                "error": "" if text else "empty response", "model": model,
                "usage": usage, "cost_usd": round(cost, 4), "account": acct["name"]}
