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


def _title(t: dict) -> str:
    raw = t.get("raw") or "challenge"
    if t.get("kind") == "file":
        return os.path.basename(raw.rstrip("/")) or raw
    return raw


def _clip(s: str, n: int = 140) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[:n - 1] + "…"


# steps that are scaffolding, not solve actions — hidden from the solve path
_META_STEPS = {"briefing", "next", "solvers", "toolset", "target-found"}
# step names (or substrings) that indicate a decode/escalation won it
_DECODE_HINT = ("decode", "encoded", "xor", "magic", "rot", "base", "hex")


def _flag_format(flag: str) -> str:
    """Infer the wrapper so the writeup can state the flag format, e.g.
    `picoCTF{...}` from picoCTF{real_thing}."""
    m = re.match(r"([A-Za-z0-9_]{1,24})\{", flag or "")
    return f"{m.group(1)}{{...}}" if m else "—"


def _encoding_note(win: dict) -> str:
    """If the flag only showed up after a decode, say so (and name the codec)."""
    if not win:
        return ""
    fl = win.get("flags") or []
    enc = next((f.get("kind") for f in fl
                if f.get("encoded") or f.get("kind") in ("base64", "hex")), None)
    step = (win.get("step") or "").lower()
    if enc:
        return (f"The flag was **{enc}**-encoded inside the target; KRYPT "
                f"decoded it automatically during the sweep.")
    if any(h in step for h in _DECODE_HINT):
        return ("The flag was hidden behind an encoding/transform that KRYPT's "
                "decoder unwound automatically.")
    return ""


def _reproduce(t: dict, brief: str) -> list[str]:
    raw = (t.get("raw") or "").strip()
    kind = t.get("kind")
    if kind in ("file", "url", "netcat") and raw:
        cmd = raw if kind != "file" else f"./{os.path.basename(raw)}"
        return ["```bash", "cd ~/ctf-solver",
                f"./ctf {cmd}", "```"]
    if brief:
        return ["Paste the briefing into KRYPT (GUI) or set",
                "`CTF_FLAG_FORMAT` and run the relevant `./ctf` target."]
    return ["```bash", "cd ~/ctf-solver", "./ctf <target>", "```"]


def make_writeup(res: dict, flag: str, event_name: str,
                 engine: str = "triage") -> str:
    """Generate a professional, deterministic CTF writeup (no LLM tokens used).

    Format: prominent flag + metadata overview, the challenge, a TL;DR, a
    numbered SOLVE PATH timeline (winning step flagged) with evidence and an
    encoding-chain note, the flag, a tools/method list, a reproduce block, and
    takeaways. Renders cleanly in the GUI and in the Markdown/PDF export.
    """
    t = res.get("target", {})
    steps = res.get("steps", [])
    cat = (t.get("subkind") or t.get("kind") or "misc")
    brief = (res.get("briefing") or "").strip()
    hits = [s for s in steps if s.get("flags")]
    win = hits[0] if hits else None
    actions = [s for s in steps if s.get("step") not in _META_STEPS]

    # ---- header: flag first, then a one-line context strip -----------------
    md = [f"# {_title(t)}", "",
          f"**Flag** · `{flag}`", "",
          f"> **◆ KRYPT WRITEUP**  ·  **{event_name}**  ·  `{cat.upper()}`  ·  engine `{engine}`  "
          f"·  captured {_now()}", "", "---", ""]

    # ---- overview ----------------------------------------------------------
    typ = (t.get("kind", "?")
           + (f" / {t.get('subkind')}" if t.get("subkind") else "")
           + (f" ({t.get('mime')})" if t.get("mime") else ""))
    md += ["## Overview", "",
           f"- **Event:** {event_name}",
           f"- **Category:** {cat.upper()}",
           f"- **Target:** `{t.get('raw','') or '—'}`",
           f"- **Type:** {typ}",
           f"- **Flag format:** `{_flag_format(flag)}`",
           f"- **Engine:** {engine}",
           f"- **Captured:** {_now()}", ""]

    # ---- challenge ---------------------------------------------------------
    md += ["## Challenge", "",
           brief if brief else "_No description provided — captured from the "
           "target directly._", ""]

    # ---- TL;DR -------------------------------------------------------------
    md += ["## TL;DR", ""]
    if win:
        md.append(f"Flag recovered via **`{win['step']}`** — "
                  f"{_clip(win.get('summary',''), 160)}")
    else:
        md.append("Recovered through the solve path below.")
    md.append("")

    # ---- solve path (numbered timeline) ------------------------------------
    md += ["## Solve path", ""]
    if actions:
        for i, s in enumerate(actions, 1):
            mark = "  🚩" if s.get("flags") else ""
            md.append(f"{i}. **{s['step']}** — {_clip(s.get('summary',''), 120)}{mark}")
    else:
        md.append("1. Automated triage swept the target for the cheap wins.")
    md.append("")

    if win:
        md += [f"### Winning move — `{win['step']}`", "",
               _clip(win.get("summary", ""), 220), ""]
        note = _encoding_note(win)
        if note:
            md += [note, ""]
        out = (win.get("output") or "").strip()
        if out:
            md += ["```", out[:2000], "```", ""]

    # ---- flag --------------------------------------------------------------
    md += ["## Flag", "", "```", flag, "```", ""]

    # ---- tools & method ----------------------------------------------------
    md += ["## Tools & method", ""]
    for s in actions:
        mark = "  ⟵ **flag**" if s.get("flags") else ""
        md.append(f"- `{s['step']}` — {_clip(s.get('summary',''), 100)}{mark}")
    md.append("")

    # ---- reproduce ---------------------------------------------------------
    md += ["## Reproduce", ""]
    md += _reproduce(t, brief)
    md.append("")

    # ---- takeaways ---------------------------------------------------------
    md += ["## Takeaways", "",
           f"- **Category:** {cat}.",
           ("- Won by deterministic triage — "
            f"`{win['step']}` — with no AI tokens spent." if win
            else "- Needed escalation beyond the first pass.")]
    enc = _encoding_note(win)
    if enc:
        md.append("- Lesson: always decode before you despair — "
                  "the answer was one transform away.")
    md += ["",
           "---",
           "_Generated by ◆ KRYPT — deterministic writeup, no AI tokens used._"]
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
    writeup = make_writeup(res, flag, ev["name"], engine)
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


def get_event(event_id: str) -> dict | None:
    return next((e for e in _load()["events"] if e["id"] == event_id), None)


def event_writeup(event_id: str) -> tuple[str, str]:
    """Combine every solve in an event into one master writeup. -> (name, md)."""
    ev = get_event(event_id)
    if not ev:
        return ("", "")
    n = len(ev["solves"])
    cats = {}
    for s in ev["solves"]:
        cats[s.get("category", "?")] = cats.get(s.get("category", "?"), 0) + 1
    bycat = ", ".join(f"{k} ×{v}" for k, v in sorted(cats.items())) or "—"
    md = [f"# ◆ KRYPT · {ev['name']} — CTF Writeups", "",
          f"> **{n} flag{'s' if n != 1 else ''} captured**  ·  created {ev['created']}",
          "", f"**By category:** {bycat}", "", "---", "",
          "## Contents", ""]
    for i, s in enumerate(ev["solves"], 1):
        title = (s.get("target", "").split("/")[-1] or s["flag"])
        md.append(f"{i}. **{title}** — `{s['flag']}` "
                  f"· {s['category'].upper()} ({s['ts']})")
    md += ["", "---", ""]
    for s in ev["solves"]:
        w = get_writeup(s["id"])
        if w:
            md += [w, "", "---", ""]
    return (ev["name"], "\n".join(md))


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
