#!/usr/bin/env python3
"""Local web backend for KRYPT (the ctf-solver GUI).

Binds to 127.0.0.1 only. Serves the themed single-page UI and exposes:
  GET  /                -> index.html
  POST /api/solve       -> {"target","description","ai"} -> report
  POST /api/upload?desc= -> raw file bytes (X-Filename) -> saved + report
  GET  /api/health      -> {"ok": true, "ollama": <model|null>}

The optional description/briefing is used to (a) derive the flag format, so the
sweep is precise, (b) get swept for flags itself, and (c) prime the AI assist.

Authorized CTF use only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ~/ctf-solver
GUI = os.path.join(ROOT, "gui")
UPLOADS = os.path.join(GUI, "uploads")
sys.path.insert(0, ROOT)

from ctfsolver.__main__ import run_pipeline, to_markdown, WORKSPACE  # noqa: E402
from ctfsolver import ai, agents, categories, vault, export  # noqa: E402
from ctfsolver.flags import scan_text  # noqa: E402

HOST = "127.0.0.1"
PORT = int(os.environ.get("CTF_GUI_PORT", "8777"))
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FMT_RE = re.compile(r"([A-Za-z0-9_]{2,20})\{[^}]{0,60}\}")
MAX_UPLOAD = 512 * 1024 * 1024

# CTF_FLAG_FORMAT is a process-global env var that solve() sets then restores.
# ThreadingHTTPServer handles requests concurrently, so serialise the
# format-sensitive section to stop overlapping solves clobbering each other.
_SOLVE_LOCK = threading.Lock()


# Phrases that mean the briefing is declaring the flag FORMAT (vs. just
# containing a wrapped-looking token that is really ciphertext to decode).
_FMT_HINT = re.compile(
    r"(?i)\b(flag\s*format|format\s*[:=]|flags?\s+(?:are|look|is|will|should)"
    r"|wrapped\s+in|submit|answer\s+format)\b")


def _derive_format(desc: str):
    """Pull a flag wrapper (e.g. picoCTF{...}) out of a briefing, but ONLY when
    the briefing is really declaring the flag format — not when it merely
    contains a wrapped-looking token that is actually the ciphertext to decode
    (e.g. 'decode this: synt{...}'). Mistaking ciphertext for the format makes
    the decoder match the raw input and skip the real decoded flag.

    Returns (format_regex, example_string) so the example can be excluded, or
    (None, None) when no format should be assumed."""
    desc = desc or ""
    m = FMT_RE.search(desc)
    if not m:
        return (None, None)
    wrapper, token = m.group(1), m.group(0)
    w = wrapper.lower()
    flaggy = w in ("flag", "ctf") or w.endswith("ctf") or wrapper.upper() in ("HTB", "KEY")
    # Derive a format only with a clear signal: an explicit "flag format" hint,
    # a flag-ish wrapper, or a placeholder body (FLAG{xxxx}, EVENT{...}).
    if _FMT_HINT.search(desc) or flaggy or _is_placeholder(token):
        return (re.escape(wrapper) + r"\{[^}]+\}", token)
    return (None, None)


# inner words that mean "the flag/password goes here", not an actual flag
_PLACEHOLDER_WORDS = {
    "password", "passwd", "pass", "flag", "the_flag", "theflag", "your_flag",
    "yourflag", "flag_here", "flaghere", "redacted", "input", "content",
    "something", "secret", "answer", "value", "text", "here",
}


def _is_placeholder(flag: str) -> bool:
    """A format example like myEvent{...}, FLAG{xxxx}, or bushbash{password} —
    not a real flag."""
    m = re.search(r"\{([^}]*)\}", flag)
    if not m:
        return False
    inner = m.group(1).strip()
    if inner in ("", "...", "…") or re.fullmatch(r"[.\s…xX*?_\-]+", inner):
        return True
    return inner.lower().strip("_- ") in _PLACEHOLDER_WORDS


def _aggregate(steps: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for st in steps:
        for f in st.get("flags") or []:
            cur = seen.get(f["flag"])
            if not cur or f["confidence"] > cur["confidence"]:
                seen[f["flag"]] = {**f, "source": st["step"]}
    return sorted(seen.values(), key=lambda d: -d["confidence"])


def _clean(res: dict) -> dict:
    for st in res.get("steps", []):
        if st.get("output"):
            st["output"] = ANSI.sub("", st["output"])
    res["markdown"] = ANSI.sub("", to_markdown(res))
    return res


def _fileless(description: str, category: str) -> dict:
    """Common/no-file mode: the briefing itself is the challenge. Text triage +
    magic decode, PLUS it extracts any nc host:port / URL mentioned in the
    briefing and actually probes them."""
    from ctfsolver.detect import extract_targets
    from ctfsolver.triage import netcat as _nc, web as _web

    import hashlib
    steps = categories.text_triage(description) if description else []
    digest = hashlib.sha1((description or "").encode("utf-8", "replace")).hexdigest()[:8]
    workdir = os.path.join(WORKSPACE, "common-" + digest)
    os.makedirs(workdir, exist_ok=True)

    # OSINT: pull usernames/emails/domains/phones from the briefing and actually
    # run the installed OSINT tools (sherlock/maigret/holehe/theHarvester/...).
    if category == "osint" and description:
        from ctfsolver.triage import osint as _osint
        steps += _osint.triage(description, workdir)

    for kind, host, port in extract_targets(description)[:3]:
        if kind == "netcat":
            steps.append({"step": "target-found",
                          "summary": f"service in briefing: {host}:{port} — connecting",
                          "output": "", "flags": []})
            steps += _nc.triage(host, port, workdir)
        elif kind == "url":
            steps.append({"step": "target-found",
                          "summary": f"URL in briefing: {host} — recon",
                          "output": "", "flags": []})
            steps += _web.triage(host, workdir)

    return {"target": {"kind": "common", "subkind": category, "raw": description[:80],
                       "mime": ""}, "workdir": workdir, "steps": steps, "flags": []}


def _format_to_regex(fmt: str) -> str:
    """Turn a user-entered flag format into a search regex. Accepts a wrapper
    sample like 'POCTF{...}' or 'flag{}' (-> POCTF\\{[^}]+\\}), or, if it already
    looks like a regex, uses it verbatim."""
    fmt = (fmt or "").strip()
    if not fmt:
        return ""
    if any(c in fmt for c in "[]*\\") or "+}" in fmt:
        return fmt
    m = re.match(r"([A-Za-z0-9_]{1,24})\{", fmt)
    if m:
        return re.escape(m.group(1)) + r"\{[^}]+\}"
    return re.escape(fmt.rstrip("{} .")) + r"\{[^}]+\}"


def solve(target: str, description: str = "", use_ai: bool = False,
          category: str = "auto", event: str = "", engine: str = "triage",
          flag_format: str = "") -> dict:
    """Run the pipeline with an optional briefing driving format + AI context.
    With no target but a briefing, runs the common (no-file) text pipeline.
    An explicit `flag_format` (from the UI field) overrides everything.
    When `event` is set and a flag is found, auto-saves it to the Vault + writeup."""
    description = (description or "").strip()
    _SOLVE_LOCK.acquire()
    old_fmt = os.environ.get("CTF_FLAG_FORMAT")
    set_fmt = False
    example = None
    try:
        if flag_format and flag_format.strip():
            os.environ["CTF_FLAG_FORMAT"] = _format_to_regex(flag_format)
            set_fmt = True
            # exclude the literal format the operator typed (e.g. POCTF{...}) so
            # it can never be reported back as the captured flag.
            example = flag_format.strip()
        elif description and not old_fmt:
            fmt, example = _derive_format(description)
            if fmt:
                os.environ["CTF_FLAG_FORMAT"] = fmt
                set_fmt = True
        res = run_pipeline(target) if target else _fileless(description, category)
        if description and target:
            dfl = [f for f in scan_text(description)
                   if not _is_placeholder(f["flag"]) and f["flag"] != example]
            res["steps"].insert(0, {
                "step": "briefing",
                "summary": "operator-supplied context"
                           + ("; derived flag format" if set_fmt else ""),
                "output": description[:2000], "flags": dfl})
        # always map the domain arsenal, then aggregate flags
        res["steps"].append(categories.toolset_step(category))
        # strip the format-example and any placeholder from every step's flags
        for st in res["steps"]:
            if st.get("flags"):
                st["flags"] = [f for f in st["flags"]
                               if f["flag"] != example and not _is_placeholder(f["flag"])]
        res["flags"] = _aggregate(res["steps"])
        if description:
            res["briefing"] = description
        res["category"] = category
        res = _clean(res)
        if use_ai and ai.available():
            ctx = (f"BRIEFING:\n{description}\n\n" if description else "") + res["markdown"]
            res["ai"] = ai.ask(ctx)
        # auto-save the top flag to the active event (with a generated writeup)
        if event and event.strip() and res["flags"]:
            try:
                top = res["flags"][0]["flag"]
                res["saved"] = vault.add_solve(event.strip(), res, top, engine)
            except Exception as e:
                res["saved"] = {"error": str(e)}
        return res
    finally:
        if set_fmt:
            if old_fmt is not None:
                os.environ["CTF_FLAG_FORMAT"] = old_fmt
            else:
                os.environ.pop("CTF_FLAG_FORMAT", None)
        _SOLVE_LOCK.release()


def deep(target: str, description: str, provider: str,
         category: str = "auto", event: str = "", flag_format: str = "") -> dict:
    """Fast triage, then escalate to an AI engine to try to capture the flag.

    provider 'api'  -> Anthropic API with vision (sees the challenge image).
    provider 'claude'/'agy' -> the local CLI agent (bounded, no skip-permissions).
    """
    res = solve(target, description, use_ai=False, category=category,
                event=event, engine=provider, flag_format=flag_format)
    subject = target or f"(no file) {description[:120]}"
    if provider == "api":
        from ctfsolver import ai_api
        r = ai_api.solve(target, (description or "").strip(),
                         res.get("markdown", ""), flag_format, category)
        note = ("" if r.get("output") else r.get("error", ""))
        ag = {"ok": r.get("ok", False), "provider": "api",
              "output": r.get("output", "") or note, "error": r.get("error", "")}
    elif provider == "agy":
        # agy has no read-only allowlist; running it unattended would need blanket
        # --dangerously-skip-permissions, which auto-approves its full offensive
        # arsenal (execute_command / metasploit / hydra / pacu / delete_file). We
        # OFF by default: we hand off the ready-to-run command for the operator to
        # launch in their own terminal. The operator can opt in to auto-running it
        # from the tool by exporting KRYPT_AGY_YOLO=1 (their deliberate choice).
        if _truthy(os.environ.get("KRYPT_AGY_YOLO")):
            ag = agents.run("agy", subject, (description or "").strip(),
                            res.get("markdown", ""), res["workdir"], category,
                            allow_skip=True)
        else:
            ag = {"ok": False, "provider": "agy", "output": "",
                  "error": "agy is hand-off by default: copy the command below and "
                           "run it in your own terminal (it auto-approves every "
                           "tool). To let KRYPT run it automatically, export "
                           "KRYPT_AGY_YOLO=1. For safe in-tool solving use CLAUDE·MCP."}
    else:
        ag = agents.run(provider, subject, (description or "").strip(),
                        res.get("markdown", ""), res["workdir"], category)
    res["agent"] = ag
    if ag.get("output"):
        # scan the agent's answer for flags (named formats + FLAG: lines)
        afl = [f for f in scan_text(ag["output"]) if not _is_placeholder(f["flag"])]
        for line in ag["output"].splitlines():
            ln = line.strip()
            if ln.upper().startswith("FLAG:"):
                val = ln[5:].strip()
                if val and not _is_placeholder(val) and val not in [x["flag"] for x in afl]:
                    afl.insert(0, {"flag": val, "kind": "agent", "confidence": 90})
        res["steps"].append({
            "step": f"deep-agent({provider})",
            "summary": ("captured " + str(len(afl)) + " flag(s)" if afl
                        else "agent ran; no flag in output"),
            "output": ag["output"][:8000], "flags": afl})
        if afl:
            res["flags"] = _aggregate(res["steps"])
            if event and event.strip():
                try:
                    res["saved"] = vault.add_solve(event.strip(), res,
                                                   res["flags"][0]["flag"], provider)
                except Exception:
                    pass
    else:
        res["steps"].append({"step": f"deep-agent({provider})",
                             "summary": "agent did not return output",
                             "output": ag.get("error", ""), "flags": []})
    # keep the runnable command for transparency / manual re-run (CLI engines only)
    if provider != "api":
        res["handoff"] = agents.command_for(provider, subject,
                                            (description or "").strip(),
                                            res["workdir"], category)
    return res


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def escalate(target: str, description: str, category: str = "auto",
             event: str = "", flag_format: str = "") -> dict:
    """'Every AI' mode: run each available engine in order, stopping at the first
    real flag. triage(+LOCAL) -> CLAUDE·MCP -> CLAUDE·API -> agy. agy is the
    hand-off command unless KRYPT_AGY_YOLO is set. Cheap stages gate the costly
    ones: an easy challenge is solved by triage for free and never calls an API."""
    from ctfsolver import ai_api
    tried = []

    def done(res, by):
        res["escalation"] = {"tried": tried, "solved_by": by}
        return res

    # 1. deterministic triage — fast and free; solves the easy wins with no AI cost
    res = solve(target, description, use_ai=False, category=category,
                event=event, engine="triage", flag_format=flag_format)
    tried.append("triage")
    if res.get("flags"):
        return done(res, "triage")

    # 2. LOCAL GPU model (offline) — only if triage missed
    if ai.available():
        res = solve(target, description, use_ai=True, category=category,
                    event=event, engine="local", flag_format=flag_format)
        tried.append("local")
        if res.get("flags"):
            return done(res, "local")

    # 3. CLAUDE · MCP (scoped read-only ghidra/hexstrike)
    if agents.available().get("claude"):
        res = deep(target, description, "claude", category, event, flag_format)
        tried.append("claude-mcp")
        if res.get("flags"):
            return done(res, "claude-mcp")

    # 3. CLAUDE · API (vision — sees images)
    if ai_api.available():
        res = deep(target, description, "api", category, event, flag_format)
        tried.append("claude-api")
        if res.get("flags"):
            return done(res, "claude-api")

    # 4. agy last — auto-runs only under KRYPT_AGY_YOLO, else handed off
    res = deep(target, description, "agy", category, event, flag_format)
    tried.append("agy")
    return done(res, "agy" if res.get("flags") else None)


def _safe_name(name: str) -> str:
    name = os.path.basename(name or "upload.bin")
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name) or "upload.bin"


class Handler(BaseHTTPRequestHandler):
    server_version = "krypt/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", nocache=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if nocache:
            self.send_header("Cache-Control", "no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(GUI, "index.html"), "rb") as fh:
                    self._send(200, fh.read().decode(), "text/html; charset=utf-8",
                               nocache=True)
            except OSError:
                self._send(500, {"error": "index.html missing"})
        elif path == "/api/health":
            model = ai.default_model() if ai.available() else None
            from ctfsolver import ai_api
            engines = agents.available()
            engines["api"] = ai_api.available()
            self._send(200, {"ok": True, "ollama": model, "engines": engines,
                             "api_model": ai_api.DEFAULT_MODEL})
        elif path == "/api/events":
            self._send(200, vault.list_events())
        elif path == "/api/writeup":
            sid = parse_qs(urlparse(self.path).query).get("id", [""])[0]
            self._send(200, {"id": sid, "writeup": vault.get_writeup(sid)})
        elif path in ("/api/export", "/api/export_event"):
            q = parse_qs(urlparse(self.path).query)
            wid = q.get("id", [""])[0]
            fmt = q.get("fmt", ["md"])[0]
            if path == "/api/export":
                md, name = vault.get_writeup(wid), "writeup-" + wid
            else:
                ename, md = vault.event_writeup(wid)
                name = vault._slug(ename) + "-writeups" if ename else "event"
            if not md:
                return self._send(404, {"error": "nothing to export"})
            self._send_download(md, name, fmt)
        else:
            self._send(404, {"error": "not found"})

    def _send_download(self, md: str, name: str, fmt: str):
        if fmt == "pdf":
            out = os.path.join(WORKSPACE, name + ".pdf")
            if export.md_to_pdf(md, out, name):
                with open(out, "rb") as fh:
                    data = fh.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f'attachment; filename="{name}.pdf"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            fmt = "md"  # fall back to markdown if no browser for PDF
        data = md.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{name}.md"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", "0"))
        return b"" if n > MAX_UPLOAD else self.rfile.read(n)

    def _stream_to_file(self, dest: str) -> int:
        """Stream the request body straight to disk in chunks instead of buffering
        it all in RAM, so large forensics artifacts (memory dumps, pcaps, disk
        images) upload reliably without risking an out-of-memory kill. Returns
        bytes written, or -1 if the body is empty or over MAX_UPLOAD."""
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0 or n > MAX_UPLOAD:
            return -1
        remaining, written = n, 0
        with open(dest, "wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                written += len(chunk)
                remaining -= len(chunk)
        return written

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            if path == "/api/solve":
                data = json.loads(self._read_body() or b"{}")
                target = (data.get("target") or "").strip()
                desc = data.get("description", "")
                if not target and not desc.strip():
                    return self._send(400, {"error": "give a target or a briefing"})
                return self._send(200, solve(target, desc, bool(data.get("ai")),
                                             data.get("category", "auto"),
                                             data.get("event", ""),
                                             "local" if data.get("ai") else "triage",
                                             data.get("flag_format", "")))
            if path == "/api/upload":
                os.makedirs(UPLOADS, exist_ok=True)
                fname = _safe_name(self.headers.get("X-Filename", "upload.bin"))
                dest = os.path.join(UPLOADS, fname)
                if self._stream_to_file(dest) <= 0:
                    return self._send(400, {"error": "empty or too-large upload"})
                q = parse_qs(urlparse(self.path).query)
                desc = q.get("desc", [""])[0]
                cat = q.get("category", ["auto"])[0]
                ev = q.get("event", [""])[0]
                fmt = q.get("flag_format", [""])[0]
                ai_on = self.headers.get("X-Ai") == "1"
                return self._send(200, solve(dest, desc, ai_on, cat, ev,
                                             "local" if ai_on else "triage", fmt))
            if path == "/api/deep":
                data = json.loads(self._read_body() or b"{}")
                target = (data.get("target") or "").strip()
                desc = data.get("description", "")
                provider = data.get("provider") or "claude"
                if not target and not desc.strip():
                    return self._send(400, {"error": "give a target or a briefing"})
                cat = data.get("category", "auto")
                ev = data.get("event", "")
                fmt = data.get("flag_format", "")
                if provider == "all":
                    return self._send(200, escalate(target, desc, cat, ev, fmt))
                return self._send(200, deep(target, desc, provider, cat, ev, fmt))
            if path == "/api/event/delete":
                data = json.loads(self._read_body() or b"{}")
                ok = vault.delete_event(data.get("event_id", ""))
                return self._send(200, {"ok": ok})
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    os.makedirs(UPLOADS, exist_ok=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"KRYPT on http://{HOST}:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
