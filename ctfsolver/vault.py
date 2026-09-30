"""KRYPT Vault — persistent per-event session store + auto writeups.

Organises solves under CTF events (jeopardy-style). Each captured flag is saved
with its target, category, engine, timestamp, the full triage log, and a
generated markdown writeup so you can see exactly how the flag was captured.

Storage (JSON + markdown files, human-readable):
  ~/ctf-solver/vault/events.json
  ~/ctf-solver/vault/writeups/<solve_id>.md
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULT = os.path.join(ROOT, "vault")
EVENTS = os.path.join(VAULT, "events.json")
WRITEUPS = os.path.join(VAULT, "writeups")


def _now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def _load() -> dict:
    try:
        with open(EVENTS) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"events": []}


def _save(data: dict) -> None:
    os.makedirs(VAULT, exist_ok=True)
    tmp = EVENTS + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    os.replace(tmp, EVENTS)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "event").lower()).strip("-") or "event"


def list_events() -> dict:
    """All events with their solves (newest event first)."""
    data = _load()
    data["events"].sort(key=lambda e: e.get("created", ""), reverse=True)
    return data


def ensure_event(name: str, event_id: str = "") -> dict:
    data = _load()
    name = (name or "Untitled Event").strip()
    for e in data["events"]:
        if (event_id and e["id"] == event_id) or e["name"].lower() == name.lower():
            return e
    ev = {"id": _slug(name) + "-" + uuid.uuid4().hex[:6], "name": name,
          "created": _now(), "solves": []}
    data["events"].append(ev)
    _save(data)
    return ev


def make_writeup(res: dict, flag: str, event_name: str) -> str:
    t = res.get("target", {})
    steps = res.get("steps", [])
    cat = t.get("subkind") or t.get("kind") or "?"
    md = [f"# {t.get('raw') or 'challenge'}", "",
          f"- **Event:** {event_name}",
          f"- **Category:** {cat}",
          f"- **Flag:** `{flag}`",
          f"- **Captured:** {_now()}", ""]
    # highlight the step(s) that produced the flag
    hits = [s for s in steps if s.get("flags")]
    if hits:
        md.append("## How it was captured")
        for s in hits:
            md.append(f"- **`{s['step']}`** — {s.get('summary','')}")
        md.append("")
    # full method log
    md.append("## Method (full triage log)")
    for s in steps:
        md.append(f"### {s['step']}\n{s.get('summary','')}")
        out = (s.get("output") or "").strip()
        if out:
            md.append("```\n" + out[:1500] + "\n```")
    return "\n".join(md)


def add_solve(event_name: str, res: dict, flag: str, engine: str = "triage",
              event_id: str = "") -> dict:
    """Save a solved challenge (+ writeup) under an event. De-dupes by flag."""
    ev = ensure_event(event_name, event_id)
    data = _load()
    ev = next(e for e in data["events"] if e["id"] == ev["id"])
    if any(s.get("flag") == flag for s in ev["solves"]):
        return {"event_id": ev["id"], "duplicate": True}

    solve_id = uuid.uuid4().hex[:12]
    os.makedirs(WRITEUPS, exist_ok=True)
    writeup = make_writeup(res, flag, ev["name"])
    with open(os.path.join(WRITEUPS, solve_id + ".md"), "w") as fh:
        fh.write(writeup)

    t = res.get("target", {})
    ev["solves"].append({
        "id": solve_id, "ts": _now(),
        "target": t.get("raw", ""),
        "category": t.get("subkind") or t.get("kind") or "?",
        "flag": flag, "engine": engine,
    })
    _save(data)
    return {"event_id": ev["id"], "solve_id": solve_id, "duplicate": False}


def get_writeup(solve_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{6,32}", solve_id or ""):
        return ""
    try:
        with open(os.path.join(WRITEUPS, solve_id + ".md")) as fh:
            return fh.read()
    except OSError:
        return ""


def delete_event(event_id: str) -> bool:
    data = _load()
    n = len(data["events"])
    for e in data["events"]:
        if e["id"] == event_id:
            for s in e["solves"]:
                try:
                    os.remove(os.path.join(WRITEUPS, s["id"] + ".md"))
                except OSError:
                    pass
    data["events"] = [e for e in data["events"] if e["id"] != event_id]
    _save(data)
    return len(data["events"]) < n
