"""KRYPT flag submission — send a captured flag to a CTF scoreboard.

Closes the loop: KRYPT finds the flag, this submits it to the live platform and
reports back whether it SCORED. Pure stdlib (urllib) — no pip deps, same as the
rest of the harness.

Supported platforms
-------------------
  ctfd     CTFd                POST {url}/api/v1/challenges/attempt
                               header: Authorization: Token <token>
                               body:   {"challenge_id": <id>, "submission": flag}
  rctf     rCTF                POST {url}/api/v1/challs/{id}/submit
                               header: Authorization: Bearer <token>
                               body:   {"flag": flag}
  generic  anything else       POST {url} with {<field>: flag} (field default
                               "flag"); the verdict is read from the response
                               text via correct/incorrect markers.

Credentials live in ~/.config/krypt/config.json under "scoreboard" so you set the
platform URL + token once. The token is NEVER returned to the UI (only
has_token), so it can't leak back into the browser/localStorage.

Authorized CTF use only — submit flags only to scoreboards you are competing on.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

CFG_PATH = os.path.expanduser("~/.config/krypt/config.json")

PLATFORMS = ("ctfd", "rctf", "generic")

# default verdict markers for the generic platform (searched in the response)
_GEN_OK = re.compile(r"(?i)\b(correct|solved|accepted|congrat|well\s*done|right)\b")
_GEN_NO = re.compile(r"(?i)\b(incorrect|wrong|invalid|nope|denied|try\s*again|bad\s*flag)\b")
_GEN_DUP = re.compile(r"(?i)already\s*(solved|submitted|captured)")


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def _read_cfg() -> dict:
    try:
        with open(CFG_PATH) as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def _write_cfg(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CFG_PATH), exist_ok=True)
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CFG_PATH)
    try:
        os.chmod(CFG_PATH, 0o600)  # token lives here — keep it private
    except OSError:
        pass


def load_scoreboard() -> dict:
    """Stored scoreboard settings, TOKEN-SAFE for the UI.

    Returns the platform/url/challenge_id/field plus has_token (bool) — never the
    token itself, so the secret stays server-side.
    """
    sb = _read_cfg().get("scoreboard") or {}
    return {
        "platform": sb.get("platform", "ctfd"),
        "url": sb.get("url", ""),
        "challenge_id": sb.get("challenge_id", ""),
        "field": sb.get("field", "flag"),
        "has_token": bool(sb.get("token")),
    }


def save_scoreboard(platform: str, url: str, token: str, challenge_id: str = "",
                    field: str = "flag") -> None:
    """Persist scoreboard settings. An empty token KEEPS the stored one (so the
    UI, which never receives the token back, doesn't wipe it on a plain re-save)."""
    cfg = _read_cfg()
    sb = cfg.get("scoreboard") or {}
    sb["platform"] = platform
    sb["url"] = url.strip()
    sb["challenge_id"] = str(challenge_id or "").strip()
    sb["field"] = (field or "flag").strip() or "flag"
    if token.strip():
        sb["token"] = token.strip()
    cfg["scoreboard"] = sb
    _write_cfg(cfg)


def _token(given: str) -> str:
    """Use the token the caller passed; else fall back to the stored one."""
    given = (given or "").strip()
    if given:
        return given
    return ((_read_cfg().get("scoreboard") or {}).get("token") or "").strip()


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #
def _post(url: str, body: dict, headers: dict, timeout: int = 20):
    """POST JSON; return (http_status, parsed_json_or_text). Non-2xx is captured
    (CTFd uses 403/429 with a JSON body) rather than raised."""
    data = json.dumps(body).encode()
    hdr = {"Content-Type": "application/json", "Accept": "application/json",
           "User-Agent": "KRYPT-ctf-solver", **headers}
    req = urllib.request.Request(url, data=data, headers=hdr, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        code = e.code
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, {"_neterror": str(e)}
    try:
        return code, json.loads(raw)
    except ValueError:
        return code, raw


def _result(status: str, message: str, platform: str, http: int = 0,
            raw=None) -> dict:
    """status is one of: correct, incorrect, already_solved, ratelimited,
    auth_error, error."""
    out = {"status": status, "message": message, "platform": platform, "http": http}
    if raw is not None:
        out["raw"] = raw if isinstance(raw, str) else json.dumps(raw)[:800]
    return out


# --------------------------------------------------------------------------- #
# platforms
# --------------------------------------------------------------------------- #
def _submit_ctfd(url, flag, token, challenge_id, **_):
    if not challenge_id:
        return _result("error", "CTFd needs a challenge_id", "ctfd")
    if not token:
        return _result("auth_error", "CTFd needs an API token (Authorization: Token …)", "ctfd")
    try:
        cid = int(str(challenge_id).strip())
    except ValueError:
        return _result("error", f"challenge_id must be a number, got {challenge_id!r}", "ctfd")
    ep = url.rstrip("/") + "/api/v1/challenges/attempt"
    code, body = _post(ep, {"challenge_id": cid, "submission": flag},
                       {"Authorization": f"Token {token}"})
    if isinstance(body, dict) and "_neterror" in body:
        return _result("error", "connection failed: " + body["_neterror"], "ctfd")
    if code in (401, 403):
        return _result("auth_error", "CTFd rejected the token (401/403)", "ctfd", code, body)
    if code == 429:
        return _result("ratelimited", "CTFd rate-limited the submission", "ctfd", code, body)
    data = body.get("data", {}) if isinstance(body, dict) else {}
    st = (data.get("status") or "").lower()
    msg = data.get("message") or ""
    mapping = {"correct": "correct", "incorrect": "incorrect",
               "already_solved": "already_solved", "ratelimited": "ratelimited",
               "paused": "error"}
    return _result(mapping.get(st, "error"), msg or f"CTFd status={st or '?'}",
                   "ctfd", code, body)


def _submit_rctf(url, flag, token, challenge_id, **_):
    if not challenge_id:
        return _result("error", "rCTF needs a challenge id/slug", "rctf")
    if not token:
        return _result("auth_error", "rCTF needs a team token (Authorization: Bearer …)", "rctf")
    ep = url.rstrip("/") + f"/api/v1/challs/{urllib.parse.quote(str(challenge_id))}/submit"
    code, body = _post(ep, {"flag": flag}, {"Authorization": f"Bearer {token}"})
    if isinstance(body, dict) and "_neterror" in body:
        return _result("error", "connection failed: " + body["_neterror"], "rctf")
    kind = (body.get("kind") or "") if isinstance(body, dict) else ""
    msg = ""
    if isinstance(body, dict):
        m = body.get("message")
        msg = m if isinstance(m, str) else json.dumps(m) if m else ""
    mapping = {
        "goodFlag": "correct",
        "badFlag": "incorrect",
        "badAlreadySolvedChallenge": "already_solved",
        "badRateLimit": "ratelimited",
        "badChallenge": "error",
        "badFlagFormat": "incorrect",
        "badUnknownUser": "auth_error",
        "badToken": "auth_error",
        "badNotStarted": "error",
    }
    if code in (401, 403):
        return _result("auth_error", msg or "rCTF rejected the token", "rctf", code, body)
    return _result(mapping.get(kind, "error"), msg or f"rCTF kind={kind or '?'}",
                   "rctf", code, body)


def _submit_generic(url, flag, token, field="flag", **_):
    if not url:
        return _result("error", "generic submit needs a URL", "generic")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    code, body = _post(url, {field or "flag": flag}, headers)
    if isinstance(body, dict) and "_neterror" in body:
        return _result("error", "connection failed: " + body["_neterror"], "generic")
    text = body if isinstance(body, str) else json.dumps(body)
    if _GEN_DUP.search(text):
        return _result("already_solved", "already solved", "generic", code, body)
    if _GEN_OK.search(text) and not _GEN_NO.search(text):
        return _result("correct", "matched a success marker", "generic", code, body)
    if _GEN_NO.search(text):
        return _result("incorrect", "matched a failure marker", "generic", code, body)
    if code and code >= 400:
        return _result("error", f"HTTP {code}", "generic", code, body)
    return _result("error", "no correct/incorrect marker in response — check manually",
                   "generic", code, body)


_DISPATCH = {"ctfd": _submit_ctfd, "rctf": _submit_rctf, "generic": _submit_generic}


def submit_flag(flag: str, platform: str = "ctfd", url: str = "", token: str = "",
                challenge_id: str = "", field: str = "flag",
                remember: bool = False) -> dict:
    """Submit a flag to a scoreboard and return the verdict.

    -> {"status": correct|incorrect|already_solved|ratelimited|auth_error|error,
        "message": str, "platform": str, "http": int, "raw"?: str}
    """
    flag = (flag or "").strip()
    if not flag:
        return _result("error", "no flag given", platform)
    platform = (platform or "ctfd").lower()
    if platform not in _DISPATCH:
        return _result("error", f"unknown platform {platform!r} (use ctfd/rctf/generic)",
                       platform)
    url = (url or "").strip()
    if not url:
        return _result("error", "no scoreboard URL given", platform)
    tok = _token(token)
    if remember:
        try:
            save_scoreboard(platform, url, token, challenge_id, field)
        except OSError:
            pass
    return _DISPATCH[platform](url=url, flag=flag, token=tok,
                               challenge_id=challenge_id, field=field)
