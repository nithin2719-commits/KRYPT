"""ctf-solver — autonomous first-pass CTF triage & flag hunter.

Usage:
    python -m ctfsolver <file | url | host:port> [--ai] [--json]

Runs the appropriate triage pipeline, sweeps everything for flags, writes a
markdown + JSON report under workspace/<name>/, and prints ranked flag
candidates plus the recommended next move.

Authorized use only: run against CTF challenge material or targets you have
explicit permission to test.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

from . import flags as flagmod
from .detect import classify
from .triage import (archive, audio, binary, crypto, generic, image, netcat,
                     pcap, pdf, web)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.join(ROOT, "workspace")

# file subkind -> specialised triage module
FILE_ROUTER = {
    "binary": binary,
    "image": image,
    "audio": audio,
    "archive": archive,
    "pcap": pcap,
    "pdf": pdf,
    "text": crypto,
    "data": crypto,
}


def _slug(raw: str) -> str:
    base = os.path.basename(raw.rstrip("/")) or "target"
    keep = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{keep}-{ts}"


MAX_DEPTH = 2          # how deep to recurse into carved/extracted files
MAX_HUNT_FILES = 40    # global cap on files processed in one hunt


def _sha1(path: str) -> str | None:
    import hashlib
    h = hashlib.sha1()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def run_pipeline(arg: str, depth: int = 0, seen: set | None = None,
                 parent_workdir: str | None = None) -> dict:
    t = classify(arg)
    workdir = parent_workdir or os.path.join(WORKSPACE, _slug(arg))
    os.makedirs(workdir, exist_ok=True)
    if seen is None:
        seen = set()

    steps: list[dict] = []
    if t.kind == "file":
        sig = _sha1(t.raw)
        if sig:
            seen.add(sig)
        steps += generic.triage(t.raw, workdir)
        mod = FILE_ROUTER.get(t.subkind)
        if mod:
            steps += mod.triage(t.raw, workdir)

        # Recursive hunt: run the full pipeline on every carved/extracted file.
        artifacts = [art for st in steps for art in (st.get("artifacts") or [])
                     if os.path.isfile(art)]
        if depth < MAX_DEPTH:
            for art in artifacts:
                if len(seen) >= MAX_HUNT_FILES:
                    break
                asig = _sha1(art)
                if not asig or asig in seen:
                    continue
                seen.add(asig)
                sub = run_pipeline(art, depth + 1, seen, workdir)
                for st in sub["steps"]:
                    st = dict(st)
                    st["step"] = f"↳[{os.path.basename(art)}] {st['step']}"
                    steps.append(st)
        else:
            for art in artifacts:  # depth cap: cheap flag sweep only
                fl = flagmod.scan_file(art)
                if fl:
                    steps.append({"step": f"flag-sweep({os.path.basename(art)})",
                                  "summary": f"{len(fl)} candidate(s) in artifact",
                                  "output": "\n".join(f["flag"] for f in fl[:10]),
                                  "flags": fl})
    elif t.kind == "url":
        steps += web.triage(t.raw, workdir)
    elif t.kind == "netcat":
        steps += netcat.triage(t.host, t.port, workdir)
    else:
        steps.append({"step": "unknown",
                      "summary": f"Could not classify '{arg}'. Pass a file path, "
                                 "http(s) URL, or host:port.",
                      "output": "", "flags": []})

    # aggregate + rank flags (distinct from the sha1 dedup `seen` set above)
    agg: dict[str, dict] = {}
    for st in steps:
        for f in st.get("flags", []) or []:
            cur = agg.get(f["flag"])
            if not cur or f["confidence"] > cur["confidence"]:
                agg[f["flag"]] = {**f, "source": st["step"]}
    ranked = sorted(agg.values(), key=lambda d: -d["confidence"])

    return {"target": t.__dict__, "workdir": workdir,
            "steps": steps, "flags": ranked}


def to_markdown(res: dict) -> str:
    t = res["target"]
    out = [f"# CTF triage — {t['raw']}",
           f"- kind: **{t['kind']}**"
           + (f" / {t['subkind']}" if t.get("subkind") else "")
           + (f" ({t['mime']})" if t.get("mime") else ""),
           f"- workdir: `{res['workdir']}`", ""]
    if res["flags"]:
        out.append("## 🚩 Flag candidates")
        for f in res["flags"]:
            out.append(f"- `{f['flag']}`  "
                       f"(conf {f['confidence']}, {f['kind']}, via {f['source']})")
        out.append("")
    else:
        out.append("## 🚩 Flag candidates\n_None found in first pass._\n")
    out.append("## Steps")
    for st in res["steps"]:
        out.append(f"### {st['step']}\n{st['summary']}")
        if st.get("output"):
            body = st["output"].strip()
            if body:
                out.append("```\n" + body[:3000] + "\n```")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctf-solver")
    ap.add_argument("target", nargs="?",
                    help="file path, http(s) URL, or host:port")
    ap.add_argument("--ai", action="store_true",
                    help="also ask the local Ollama model for a hypothesis")
    ap.add_argument("--json", action="store_true",
                    help="print JSON instead of markdown")
    ap.add_argument("--watch", nargs="+", metavar="DIR",
                    help="WATCH mode: auto-hunt flags in new/changed files in "
                         "these directories (the moment a challenge lands)")
    ap.add_argument("--deep", action="store_true",
                    help="with --watch, run the full triage pipeline on each "
                         "file (default: instant plaintext+base64/hex sweep)")
    ap.add_argument("--event", default="",
                    help="with --watch, auto-save captured flags to this Vault event")
    ap.add_argument("--interval", type=float, default=0.8,
                    help="with --watch, seconds between polls (default 0.8)")
    ap.add_argument("--no-recursive", action="store_true",
                    help="with --watch, do not descend into subdirectories")
    ap.add_argument("--doctor", action="store_true",
                    help="check the CTF environment (tools, wordlist, engines) "
                         "and print a readiness report")
    ap.add_argument("--agent", choices=["claude", "agy", "all", "api"],
                    help="escalate to autonomous AI/MCP agent to capture flag (claude, agy, all, api)")
    ap.add_argument("--briefing", default="",
                    help="challenge description / context to guide the hunt")
    ap.add_argument("--flag-format", default="",
                    help="custom flag format (e.g. picoCTF{...})")
    args = ap.parse_args(argv)


    if args.doctor:
        from . import doctor
        return doctor.run()

    if args.watch:
        from . import watch
        return watch.watch_cli(args.watch, deep=args.deep, event=args.event,
                               interval=args.interval,
                               recursive=not args.no_recursive)

    if args.agent:
        target = args.target or ""
        briefing = args.briefing or ""
        if not target and not briefing:
            ap.error("a target (or --briefing 'description') is required with --agent")

        try:
            from gui import server as gui_server
        except ImportError:
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if repo_root not in sys.path:
                sys.path.insert(0, repo_root)
            from gui import server as gui_server

        if args.agent == "agy":
            os.environ["KRYPT_AGY_YOLO"] = "1"

        print(f"[*] Escalating to autonomous agent ({args.agent})...", file=sys.stderr)
        if args.agent == "all":
            res = gui_server.escalate(target, description=briefing, event=args.event or "", flag_format=args.flag_format)
        else:
            res = gui_server.deep(target, description=briefing, provider=args.agent, event=args.event or "", flag_format=args.flag_format)

        md = res.get("markdown") or to_markdown(res)
        workdir = res.get("workdir")
        if workdir:
            with open(os.path.join(workdir, "report.md"), "w") as fh:
                fh.write(md)
            with open(os.path.join(workdir, "report.json"), "w") as fh:
                json.dump(res, fh, indent=2, default=str)

        print(json.dumps(res, indent=2, default=str) if args.json else md)

        if res.get("flags"):
            top = res["flags"][0]
            print(f"\n>>> CAPTURED FLAG: {top['flag']}", file=sys.stderr)
            return 0
        return 2

    if not args.target:
        if args.briefing:
            try:
                from gui import server as gui_server
            except ImportError:
                repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if repo_root not in sys.path:
                    sys.path.insert(0, repo_root)
                from gui import server as gui_server
            res = gui_server.solve("", description=args.briefing, use_ai=args.ai,
                                   event=args.event or "", flag_format=args.flag_format)
            md = res.get("markdown") or to_markdown(res)
            workdir = res.get("workdir")
            if workdir:
                with open(os.path.join(workdir, "report.md"), "w") as fh:
                    fh.write(md)
                with open(os.path.join(workdir, "report.json"), "w") as fh:
                    json.dump(res, fh, indent=2, default=str)
            print(json.dumps(res, indent=2, default=str) if args.json else md)
            if res.get("flags"):
                top = res["flags"][0]
                print(f"\n>>> TOP CANDIDATE: {top['flag']}", file=sys.stderr)
                return 0
            return 2
        ap.error("a target is required (or use --watch DIR ... for watch mode)")

    res = run_pipeline(args.target)

    md = to_markdown(res)
    with open(os.path.join(res["workdir"], "report.md"), "w") as fh:
        fh.write(md)
    with open(os.path.join(res["workdir"], "report.json"), "w") as fh:
        json.dump(res, fh, indent=2, default=str)

    if args.ai:
        from . import ai
        if ai.available():
            hint = ai.ask(md)
            res["ai"] = hint
            md += f"\n\n## 🤖 Local model hypothesis\n{hint}\n"
        else:
            md += ("\n\n## 🤖 Local model\n_Model not ready yet "
                   "(still pulling?). Skipped._\n")

    print(json.dumps(res, indent=2, default=str) if args.json else md)

    if res["flags"]:
        top = res["flags"][0]
        print(f"\n>>> TOP CANDIDATE: {top['flag']}", file=sys.stderr)
        return 0
    return 2  # no flag yet -> needs deeper work


if __name__ == "__main__":
    raise SystemExit(main())
