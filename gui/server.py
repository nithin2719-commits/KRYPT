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


def _derive_format(desc: str):
    """Pull a flag wrapper (e.g. picoCTF{...}) out of a briefing.
    Returns (format_regex, example_string) so the example can be excluded."""
    m = FMT_RE.search(desc or "")
    if not m:
        return (None, None)
    return (re.escape(m.group(1)) + r"\{[^}]+\}", m.group(0))


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


def solve(target: str, description: str = "", use_ai: bool = False,
          category: str = "auto", event: str = "", engine: str = "triage") -> dict:
    """Run the pipeline with an optional briefing driving format + AI context.
    With no target but a briefing, runs the common (no-file) text pipeline.
    When `event` is set and a flag is found, auto-saves it to the Vault + writeup."""
    description = (description or "").strip()
    _SOLVE_LOCK.acquire()
    old_fmt = os.environ.get("CTF_FLAG_FORMAT")
    set_fmt = False
    example = None
    try:
        if description and not old_fmt:
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
            os.environ.pop("CTF_FLAG_FORMAT", None)
        _SOLVE_LOCK.release()


def deep(target: str, description: str, provider: str,
         category: str = "auto", event: str = "") -> dict:
    """Fast triage, then actually RUN the chosen agent (claude/agy, bounded — no
    skip-permissions) to try to capture the flag."""
    res = solve(target, description, use_ai=False, category=category,
                event=event, engine=provider)
    subject = target or f"(no file) {description[:120]}"
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
    # keep the runnable command for transparency / manual re-run
    res["handoff"] = agents.command_for(provider, subject,
                                        (description or "").strip(),
                                        res["workdir"], category)
    return res


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
            self._send(200, {"ok": True, "ollama": model,
                             "engines": agents.available()})
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
                                             "local" if data.get("ai") else "triage"))
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
                ai_on = self.headers.get("X-Ai") == "1"
                return self._send(200, solve(dest, desc, ai_on, cat, ev,
                                             "local" if ai_on else "triage"))
            if path == "/api/deep":
                data = json.loads(self._read_body() or b"{}")
                target = (data.get("target") or "").strip()
                desc = data.get("description", "")
                provider = data.get("provider") or "claude"
                if not target and not desc.strip():
                    return self._send(400, {"error": "give a target or a briefing"})
                return self._send(200, deep(target, desc, provider,
                                            data.get("category", "auto"),
                                            data.get("event", "")))
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
