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
    ap.add_argument("target", nargs="*",
                    help="file path, http(s) URL, host:port, or command ('worker', 'queue [list|clear|add]', 'submit <flag>', 'sync')")
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
                    help="with --watch or --worker, auto-save captured flags to this Vault event")
    ap.add_argument("--interval", type=float, default=0.8,
                    help="with --watch or --worker, seconds between polls")
    ap.add_argument("--no-recursive", action="store_true",
                    help="with --watch, do not descend into subdirectories")
    ap.add_argument("--doctor", action="store_true",
                    help="check the CTF environment (tools, wordlist, engines) "
                         "and print a readiness report")
    ap.add_argument("--agent", choices=["claude", "agy", "all", "api", "pwn", "rev", "crypto", "web", "forensics", "osint", "swarm"],
                    help="escalate to autonomous AI/MCP agent or specialized domain swarm (pwn, rev, crypto, web, forensics, osint, swarm, all)")
    ap.add_argument("--briefing", default="",
                    help="challenge description / context to guide the hunt")
    ap.add_argument("--flag-format", default="",
                    help="custom flag format (e.g. picoCTF{...})")

    # Active CTF Worker arguments
    ap.add_argument("--worker", action="store_true",
                    help="run ACTIVE CTF WORKER: autonomous multi-tier solving loop & queue manager")
    ap.add_argument("--inbox", nargs="+", metavar="DIR",
                    help="inbox directories to monitor for challenge drops in worker mode")
    ap.add_argument("--ctfd", default="",
                    help="CTFd scoreboard URL (e.g. https://demo.ctfd.io)")
    ap.add_argument("--token", default="",
                    help="scoreboard API token")
    ap.add_argument("--no-submit", action="store_true",
                    help="disable automatic scoreboard submission in worker mode")
    ap.add_argument("--once", action="store_true",
                    help="worker single pass over inbox/queue then exit")
    ap.add_argument("--status", action="store_true",
                    help="print active worker queue & performance stats")
    ap.add_argument("--sync", action="store_true",
                    help="sync challenges from scoreboard into worker queue")
    ap.add_argument("--queue-add", default="",
                    help="enqueue challenge target into worker queue")
    ap.add_argument("--queue-list", action="store_true",
                    help="list challenges in worker queue")
    ap.add_argument("--queue-clear", action="store_true",
                    help="clear worker challenge queue")
    ap.add_argument("--submit", default="",
                    help="submit a flag directly to the configured scoreboard")
    ap.add_argument("--challenge-id", default="",
                    help="scoreboard challenge ID for submission")
    ap.add_argument("--category", default="auto",
                    help="challenge category for queueing (pwn, rev, web, crypto, forensics, osint, misc)")
    ap.add_argument("--points", type=int, default=0,
                    help="challenge points for queueing")
    ap.add_argument("--strategy", choices=["fifo", "easy-first", "high-points"], default="fifo",
                    help="worker queue priority strategy (fifo, easy-first [lowest points first], high-points [highest points first])")
    args = ap.parse_args(argv)

    # Subcommand normalization
    raw_targets = args.target if isinstance(args.target, list) else ([args.target] if args.target else [])
    cmd = raw_targets[0].lower().strip() if raw_targets else ""

    if cmd == "worker":
        args.worker = True
        args.target = ""
    elif cmd == "sync":
        args.sync = True
        args.target = ""
    elif cmd == "queue":
        args.target = ""
        sub = raw_targets[1].lower().strip() if len(raw_targets) > 1 else "list"
        if sub == "clear":
            args.queue_clear = True
        elif sub == "add" and len(raw_targets) > 2:
            args.queue_add = raw_targets[2]
        else:
            args.queue_list = True
    elif cmd in ("submit", "flag"):
        args.target = ""
        if len(raw_targets) > 1:
            args.submit = raw_targets[1]
        elif args.briefing and not args.submit:
            args.submit = args.briefing
    else:
        args.target = raw_targets[0] if raw_targets else ""

    if args.doctor:
        from . import doctor
        return doctor.run()

    if args.watch:
        from . import watch
        return watch.watch_cli(args.watch, deep=args.deep, event=args.event,
                               interval=args.interval,
                               recursive=not args.no_recursive)

    # Scoreboard Direct Submit
    if args.submit:
        from .scoreboard import get_scoreboard, save_scoreboard_config
        sb = get_scoreboard()
        if args.ctfd:
            sb.url = args.ctfd.rstrip("/")
        if args.token:
            sb.token = args.token
        res = sb.submit_flag(args.submit, challenge_id=args.challenge_id)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            st = res.get("status")
            col = "\033[92m" if st == "correct" else "\033[91m"
            print(f"Scoreboard Verdict: {col}{st.upper()}\033[0m — {res.get('message')}")
        return 0 if res.get("status") in ("correct", "already_solved") else 1

    # Worker Queue Management
    if args.queue_clear:
        from .worker import get_worker
        w = get_worker(args.event)
        w.clear_queue()
        print("[*] Worker challenge queue cleared.")
        return 0

    if args.queue_list:
        from .worker import get_worker
        w = get_worker(args.event)
        q = w.get_queue()
        if args.json:
            print(json.dumps(q, indent=2))
        else:
            print(f"\n=== KRYPT Worker Queue ({len(q)} challenges) ===")
            for i, t in enumerate(q, 1):
                pts = f" [{t['points']} pts]" if t.get('points') else ""
                print(f" {i}. [{t['status'].upper()}] {t['name']} ({t['category']}){pts}")
                if t.get('target'):
                    print(f"    Target: {t['target']}")
                if t.get('briefing'):
                    print(f"    Briefing: {t['briefing'][:80]}...")
            print()
        return 0

    if args.queue_add:
        from .worker import get_worker
        w = get_worker(args.event)
        task = w.enqueue(
            target=args.queue_add,
            name=os.path.basename(args.queue_add),
            category=args.category,
            briefing=args.briefing,
            points=args.points,
            challenge_id=args.challenge_id,
        )
        print(f"[+] Enqueued task: {task.name} ({task.id})")
        return 0

    # Scoreboard Sync
    if args.sync:
        from .scoreboard import Scoreboard
        from .worker import get_worker
        sb = Scoreboard(url=args.ctfd, token=args.token)
        w = get_worker(args.event)
        w.scoreboard = sb
        print(f"[*] Syncing challenges from {sb.url or 'configured scoreboard'}...")
        res = w.sync_scoreboard()
        if res.get("ok"):
            print(f"[✓] Synced! Enqueued {res['enqueued']} new challenges ({res['already_solved']} already solved).")
            return 0
        else:
            print(f"[!] Sync failed: {res.get('error')}", file=sys.stderr)
            return 1

    # Active Worker Mode
    if args.worker or args.status:
        from .scoreboard import Scoreboard
        from .worker import get_worker, run_cli
        sb = Scoreboard(url=args.ctfd, token=args.token) if (args.ctfd or args.token) else None
        w = get_worker(args.event or "default")
        if sb:
            w.scoreboard = sb
        if args.inbox:
            w.inbox_dirs = [os.path.abspath(os.path.expanduser(d)) for d in args.inbox]
        if args.no_submit:
            w.auto_submit = False
        if args.agent:
            w.escalate_engine = args.agent
        if args.flag_format:
            w.flag_format = args.flag_format
        if args.interval:
            w.poll_interval = args.interval
        if args.strategy:
            w.strategy = args.strategy

        if args.status:
            st = w.status()
            print(json.dumps(st, indent=2) if args.json else
                  f"Worker State: {st['state'].upper()} | Solved: {st['solves_count']} (+{st['total_points']} pts) | Queue: {st['queue_length']}")
            return 0

        return run_cli(w, continuous=not args.once)

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

        print(f"[*] Escalating to autonomous agent / specialist ({args.agent})...", file=sys.stderr)
        if args.agent == "swarm":
            from .swarm import get_swarm
            res = get_swarm(event=args.event or "", flag_format=args.flag_format).solve(
                target=target, briefing=briefing, category=args.category, flag_format=args.flag_format
            )
        elif args.agent in ("pwn", "rev", "crypto", "web", "forensics", "osint"):
            from .specialists import get_specialist
            spec = get_specialist(args.agent)
            res = spec.solve(
                target=target, briefing=briefing, evidence="", workdir="", provider="all", flag_format=args.flag_format
            )
        elif args.agent == "all":
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
