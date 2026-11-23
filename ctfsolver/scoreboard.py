"""Scoreboard integration for CTFd, rCTF, and generic CTF platforms.

Supports:
  1. Fetching challenge metadata, categories, points, hints, and file attachments.
  2. Submitting captured flags and recording verdicts (correct, incorrect, already_solved, ratelimited).
  3. Automatic synchronization with the KRYPT Active CTF Worker queue.
  4. Credential persistence in ~/.config/krypt/config.json with chmod 600.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

CFG_PATH = os.path.expanduser("~/.config/krypt/config.json")

# Regex for generic scoreboard response parsing
_GEN_OK = re.compile(r"(?i)\b(correct|success|congrat|flag\s*accepted|points?\s*awarded|well\s*done)\b")
_GEN_NO = re.compile(r"(?i)\b(incorrect|wrong|invalid|bad\s*flag|try\s*again|failure|nope)\b")
_GEN_DUP = re.compile(r"(?i)\b(already\s*solved|duplicate|already\s*submitted)\b")


def _read_cfg() -> dict:
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _write_cfg(data: dict) -> None:
    os.makedirs(os.path.dirname(CFG_PATH), exist_ok=True)
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, CFG_PATH)
    try:
        os.chmod(CFG_PATH, 0o600)
    except OSError:
        pass


def get_scoreboard_config() -> dict:
    sb = (_read_cfg().get("scoreboard") or {})
    return {
        "platform": sb.get("platform", "ctfd"),
        "url": sb.get("url", ""),
        "challenge_id": sb.get("challenge_id", ""),
        "field": sb.get("field", "flag"),
        "has_token": bool(sb.get("token")),
        "auto_submit": sb.get("auto_submit", False),
    }


def save_scoreboard_config(platform: str, url: str, token: str = "", challenge_id: str = "",
                           field: str = "flag", auto_submit: bool = False) -> None:
    cfg = _read_cfg()
    sb = cfg.get("scoreboard") or {}
    sb["platform"] = (platform or "ctfd").lower().strip()
    sb["url"] = url.strip().rstrip("/")
    sb["challenge_id"] = str(challenge_id or "").strip()
    sb["field"] = (field or "flag").strip() or "flag"
    sb["auto_submit"] = bool(auto_submit)
    if token and token.strip():
        sb["token"] = token.strip()
    cfg["scoreboard"] = sb
    _write_cfg(cfg)


def _token(given: str = "") -> str:
    given = (given or "").strip()
    if given:
        return given
    return ((_read_cfg().get("scoreboard") or {}).get("token") or "").strip()


def _http_request(url: str, method: str = "GET", body: Optional[dict] = None,
                  headers: Optional[dict] = None, timeout: int = 25) -> Tuple[int, Any]:
    hdr = {
        "User-Agent": "KRYPT-Active-CTF-Worker/2.0",
        "Accept": "application/json",
    }
    if headers:
        hdr.update(headers)

    data = None
    if body is not None:
        hdr["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
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


def _result(status: str, message: str, platform: str, http: int = 0, raw=None, points: int = 0) -> dict:
    out = {
        "status": status,
        "message": message,
        "platform": platform,
        "http": http,
        "points": points,
    }
    if raw is not None:
        out["raw"] = raw if isinstance(raw, str) else json.dumps(raw)[:800]
    return out


class Scoreboard:
    """Unified client for CTFd, rCTF, and generic CTF scoreboards."""

    def __init__(self, url: str = "", token: str = "", platform: str = "ctfd", field: str = "flag"):
        cfg = get_scoreboard_config()
        self.url = (url or cfg.get("url") or "").strip().rstrip("/")
        self.token = _token(token)
        self.platform = (platform or cfg.get("platform") or "ctfd").lower().strip()
        self.field = (field or cfg.get("field") or "flag").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.url and self.token)

    def test_connection(self) -> dict:
        """Verify scoreboard reachability and credentials."""
        if not self.url:
            return {"ok": False, "error": "No scoreboard URL configured"}

        if self.platform == "ctfd":
            ep = f"{self.url}/api/v1/users/me"
            code, body = _http_request(ep, headers={"Authorization": f"Token {self.token}"})
            if code == 200 and isinstance(body, dict) and body.get("success"):
                user_data = body.get("data") or {}
                return {
                    "ok": True,
                    "platform": "ctfd",
                    "user": user_data.get("name", "Unknown"),
                    "email": user_data.get("email", ""),
                    "score": user_data.get("score", 0),
                    "place": user_data.get("place", 0),
                }
            if code in (401, 403):
                return {"ok": False, "error": "CTFd authentication failed (invalid API token)"}
            err = body.get("_neterror") if isinstance(body, dict) else f"HTTP {code}"
            return {"ok": False, "error": f"CTFd connection failed: {err}"}

        elif self.platform == "rctf":
            ep = f"{self.url}/api/v1/users/me"
            code, body = _http_request(ep, headers={"Authorization": f"Bearer {self.token}"})
            if code == 200 and isinstance(body, dict) and body.get("kind") == "goodUserData":
                data = body.get("data") or {}
                return {
                    "ok": True,
                    "platform": "rctf",
                    "user": data.get("name", "Unknown"),
                    "score": data.get("score", 0),
                }
            if code in (401, 403):
                return {"ok": False, "error": "rCTF authentication failed (invalid team token)"}
            err = body.get("_neterror") if isinstance(body, dict) else f"HTTP {code}"
            return {"ok": False, "error": f"rCTF connection failed: {err}"}

        else:  # generic
            code, body = _http_request(self.url)
            if code and code < 400:
                return {"ok": True, "platform": "generic", "user": "generic"}
            err = body.get("_neterror") if isinstance(body, dict) else f"HTTP {code}"
            return {"ok": False, "error": f"Generic scoreboard unreachable: {err}"}

    def fetch_challenges(self) -> List[dict]:
        """Fetch all challenge listings from the scoreboard."""
        if not self.url:
            return []

        if self.platform == "ctfd":
            ep = f"{self.url}/api/v1/challenges"
            code, body = _http_request(ep, headers={"Authorization": f"Token {self.token}"})
            if code != 200 or not isinstance(body, dict) or not body.get("success"):
                return []
            challs = []
            for c in body.get("data") or []:
                challs.append({
                    "id": str(c.get("id")),
                    "name": c.get("name", "Untitled"),
                    "category": (c.get("category") or "misc").lower(),
                    "value": int(c.get("value") or 0),
                    "solves": int(c.get("solves") or 0),
                    "solved": bool(c.get("solved_by_me")),
                    "tags": [t.get("value") if isinstance(t, dict) else str(t) for t in (c.get("tags") or [])],
                })
            return challs

        elif self.platform == "rctf":
            ep = f"{self.url}/api/v1/challs"
            code, body = _http_request(ep, headers={"Authorization": f"Bearer {self.token}"})
            if code != 200 or not isinstance(body, dict) or body.get("kind") != "goodChallenges":
                return []
            challs = []
            for c in body.get("data") or []:
                challs.append({
                    "id": str(c.get("id")),
                    "name": c.get("name", "Untitled"),
                    "category": (c.get("category") or "misc").lower(),
                    "value": int(c.get("points") or 0),
                    "solves": int(c.get("solves") or 0),
                    "solved": bool(c.get("solved")),
                    "description": c.get("description", ""),
                    "files": [f.get("url") for f in (c.get("files") or []) if isinstance(f, dict)],
                })
            return challs

        return []

    def fetch_challenge_detail(self, challenge_id: str) -> dict:
        """Fetch detailed challenge briefing, hints, and file attachment links."""
        if not self.url or not challenge_id:
            return {}

        if self.platform == "ctfd":
            ep = f"{self.url}/api/v1/challenges/{challenge_id}"
            code, body = _http_request(ep, headers={"Authorization": f"Token {self.token}"})
            if code != 200 or not isinstance(body, dict) or not body.get("success"):
                return {}
            data = body.get("data") or {}
            files = []
            for f in data.get("files") or []:
                if isinstance(f, str):
                    f_url = f if f.startswith("http") else f"{self.url}{f}"
                    files.append(f_url)
                elif isinstance(f, dict) and "location" in f:
                    loc = f["location"]
                    f_url = loc if loc.startswith("http") else f"{self.url}{loc}"
                    files.append(f_url)
            return {
                "id": str(data.get("id")),
                "name": data.get("name", ""),
                "category": (data.get("category") or "misc").lower(),
                "value": int(data.get("value") or 0),
                "description": data.get("description", ""),
                "connection_info": data.get("connection_info", ""),
                "files": files,
                "hints": [h.get("content") if isinstance(h, dict) else str(h) for h in (data.get("hints") or [])],
                "solved": bool(data.get("solved_by_me")),
            }

        return {}

    def download_file(self, file_url: str, dest_dir: str) -> Optional[str]:
        """Download challenge attachment file to dest_dir."""
        try:
            os.makedirs(dest_dir, exist_ok=True)
            url_path = urllib.parse.urlparse(file_url).path
            fname = os.path.basename(url_path) or "challenge_file.bin"
            # Clean filename from query strings or tokens
            fname = re.sub(r"\?.*$", "", fname)
            out_path = os.path.join(dest_dir, fname)

            hdr = {"User-Agent": "KRYPT-Active-CTF-Worker/2.0"}
            if self.token:
                hdr["Authorization"] = f"Token {self.token}" if self.platform == "ctfd" else f"Bearer {self.token}"

            req = urllib.request.Request(file_url, headers=hdr)
            with urllib.request.urlopen(req, timeout=40) as resp, open(out_path, "wb") as out_fh:
                chunk = resp.read(65536)
                while chunk:
                    out_fh.write(chunk)
                    chunk = resp.read(65536)
            return out_path
        except Exception:
            return None

    def submit_flag(self, flag: str, challenge_id: str = "") -> dict:
        """Submit flag to the scoreboard and return standardized verdict."""
        flag = (flag or "").strip()
        if not flag:
            return _result("error", "No flag provided for submission", self.platform)
        if not self.url:
            return _result("error", "No scoreboard URL configured", self.platform)

        if self.platform == "ctfd":
            cid = challenge_id or get_scoreboard_config().get("challenge_id")
            if not cid:
                return _result("error", "CTFd submission requires challenge_id", "ctfd")
            try:
                cid_int = int(str(cid).strip())
            except ValueError:
                return _result("error", f"Invalid CTFd challenge_id: {cid!r}", "ctfd")

            ep = f"{self.url}/api/v1/challenges/attempt"
            code, body = _http_request(
                ep,
                method="POST",
                body={"challenge_id": cid_int, "submission": flag},
                headers={"Authorization": f"Token {self.token}"},
            )
            if isinstance(body, dict) and "_neterror" in body:
                return _result("error", f"CTFd connection failed: {body['_neterror']}", "ctfd")
            if code in (401, 403):
                return _result("auth_error", "CTFd rejected token (401/403)", "ctfd", code, body)
            if code == 429:
                return _result("ratelimited", "CTFd rate limit reached; slow down", "ctfd", code, body)

            data = body.get("data", {}) if isinstance(body, dict) else {}
            st = (data.get("status") or "").lower()
            msg = data.get("message") or ""
            mapping = {
                "correct": "correct",
                "incorrect": "incorrect",
                "already_solved": "already_solved",
                "ratelimited": "ratelimited",
                "paused": "error",
            }
            return _result(mapping.get(st, "error"), msg or f"CTFd status: {st}", "ctfd", code, body)

        elif self.platform == "rctf":
            cid = challenge_id or get_scoreboard_config().get("challenge_id")
            if not cid:
                return _result("error", "rCTF submission requires challenge_id", "rctf")

            ep = f"{self.url}/api/v1/challs/{urllib.parse.quote(str(cid))}/submit"
            code, body = _http_request(
                ep,
                method="POST",
                body={"flag": flag},
                headers={"Authorization": f"Bearer {self.token}"},
            )
            if isinstance(body, dict) and "_neterror" in body:
                return _result("error", f"rCTF connection failed: {body['_neterror']}", "rctf")

            kind = (body.get("kind") or "") if isinstance(body, dict) else ""
            msg = body.get("message", "") if isinstance(body, dict) else ""
            mapping = {
                "goodFlag": "correct",
                "badFlag": "incorrect",
                "badAlreadySolvedChallenge": "already_solved",
                "badRateLimit": "ratelimited",
                "badChallenge": "error",
                "badFlagFormat": "incorrect",
                "badUnknownUser": "auth_error",
                "badToken": "auth_error",
            }
            if code in (401, 403):
                return _result("auth_error", msg or "rCTF rejected token", "rctf", code, body)
            return _result(mapping.get(kind, "error"), msg or f"rCTF kind: {kind}", "rctf", code, body)

        else:  # Generic HTTP form/endpoint
            code, body = _http_request(
                self.url,
                method="POST",
                body={self.field: flag},
                headers={"Authorization": f"Bearer {self.token}"} if self.token else None,
            )
            if isinstance(body, dict) and "_neterror" in body:
                return _result("error", f"Generic submit failed: {body['_neterror']}", "generic")

            text = body if isinstance(body, str) else json.dumps(body)
            if _GEN_DUP.search(text):
                return _result("already_solved", "Already solved marker detected", "generic", code, body)
            if _GEN_OK.search(text) and not _GEN_NO.search(text):
                return _result("correct", "Success marker detected in response", "generic", code, body)
            if _GEN_NO.search(text):
                return _result("incorrect", "Failure marker detected in response", "generic", code, body)
            if code and code >= 400:
                return _result("error", f"HTTP {code}", "generic", code, body)
            return _result("error", "No clear verdict marker detected in response", "generic", code, body)


# Global singleton access
_SCOREBOARD = None


def get_scoreboard() -> Scoreboard:
    global _SCOREBOARD
    if _SCOREBOARD is None:
        _SCOREBOARD = Scoreboard()
    return _SCOREBOARD
