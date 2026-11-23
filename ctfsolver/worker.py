"""KRYPT Active CTF Worker Engine.

An autonomous worker daemon and task runner that actively:
  1. Ingests challenges from local inbox directories, drop folders, or CTFd/rCTF scoreboards.
  2. Executes an iterative multi-tier solving loop:
       Tier 1: Instant Triage & Recursive Magic BFS Decoders (b64/hex/rot/affine/bacon/etc.)
       Tier 2: Domain-Specific Heuristic Solvers (angr symbolic execution, RSA attacks,
               hash cracking, pcap carving, EOF stego, ret2win exploit scaffold)
       Tier 3: Autonomous AI Agent Escalation (HexStrike AI MCP + Ghidra MCP via Claude/AGY)
  3. Verifies flag candidate formats, rejects placeholders, and prevents false positives.
  4. Automatically submits verified flags to the scoreboard (CTFd / rCTF / generic) and tracks points.
  5. Automatically writes comprehensive Vault writeups (Markdown & KRYPT-branded PDF).
  6. Emits live progress events for terminal dashboards and web GUI polling.
"""
from __future__ import annotations

import datetime as dt
import glob
import json
import os
import re
import shutil
import sys
import threading
import time
import uuid
import zipfile
from typing import Any, Callable, Dict, List, Optional, Set

from . import flags as flagmod
from .detect import classify
from .runner import have, run as tool_run
from .scoreboard import Scoreboard, get_scoreboard, get_scoreboard_config
from .vault import add_solve, ensure_event

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.join(ROOT, "workspace")
QUEUE_FILE = os.path.join(WORKSPACE, "worker_queue.json")
STATS_FILE = os.path.join(WORKSPACE, "worker_stats.json")
SOLVERS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "solvers")

_TOOLS_PYTHON = os.path.expanduser("~/Tools/venv/bin/python3")
PYTHON_BIN = _TOOLS_PYTHON if (os.path.exists(_TOOLS_PYTHON) and os.access(_TOOLS_PYTHON, os.X_OK)) else (sys.executable or "python3")


class CTFTask:
    """Represents a discrete CTF challenge to be solved by the worker."""

    def __init__(
        self,
        target: str = "",
        name: str = "",
        category: str = "auto",
        briefing: str = "",
        points: int = 0,
        challenge_id: str = "",
        event: str = "default",
        flag_format: str = "",
        files: Optional[List[str]] = None,
        task_id: str = "",
    ):
        self.id = task_id or f"task-{uuid.uuid4().hex[:8]}"
        self.name = name or os.path.basename(target.rstrip("/")) or "Challenge"
        self.category = (category or "auto").lower()
        self.target = target
        self.briefing = (briefing or "").strip()
        self.points = int(points or 0)
        self.challenge_id = str(challenge_id or "").strip()
        self.event = (event or "default").strip()
        self.flag_format = (flag_format or "").strip()
        self.files = list(files or [])
        if target and os.path.isfile(target) and target not in self.files:
            self.files.append(target)

        self.status = "pending"  # pending, triage, solving, escalating, submitting, solved, failed
        self.flags: List[dict] = []
        self.solved_flag: str = ""
        self.solved_by: str = ""
        self.submission_verdict: dict = {}
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.duration_sec: float = 0.0
        self.error: str = ""
        self.stages_run: List[str] = []
        self.report_md: str = ""
        self.workdir: str = os.path.join(WORKSPACE, "tasks", self.id)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "target": self.target,
            "briefing": self.briefing,
            "points": self.points,
            "challenge_id": self.challenge_id,
            "event": self.event,
            "flag_format": self.flag_format,
            "files": self.files,
            "status": self.status,
            "flags": self.flags,
            "solved_flag": self.solved_flag,
            "solved_by": self.solved_by,
            "submission_verdict": self.submission_verdict,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": self.duration_sec,
            "error": self.error,
            "stages_run": self.stages_run,
            "workdir": self.workdir,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CTFTask:
        t = cls(
            target=data.get("target", ""),
            name=data.get("name", ""),
            category=data.get("category", "auto"),
            briefing=data.get("briefing", ""),
            points=data.get("points", 0),
            challenge_id=data.get("challenge_id", ""),
            event=data.get("event", "default"),
            flag_format=data.get("flag_format", ""),
            files=data.get("files", []),
            task_id=data.get("id", ""),
        )
        t.status = data.get("status", "pending")
        t.flags = data.get("flags", [])
        t.solved_flag = data.get("solved_flag", "")
        t.solved_by = data.get("solved_by", "")
        t.submission_verdict = data.get("submission_verdict", {})
        t.created_at = data.get("created_at", time.time())
        t.started_at = data.get("started_at")
        t.finished_at = data.get("finished_at")
        t.duration_sec = data.get("duration_sec", 0.0)
        t.error = data.get("error", "")
        t.stages_run = data.get("stages_run", [])
        t.workdir = data.get("workdir", os.path.join(WORKSPACE, "tasks", t.id))
        return t


class CTFWorker:
    """Active CTF Worker solving daemon."""

    def __init__(
        self,
        event: str = "default",
        inbox_dirs: Optional[List[str]] = None,
        scoreboard: Optional[Scoreboard] = None,
        auto_submit: bool = True,
        escalate_engine: str = "all",
        flag_format: str = "",
        poll_interval: float = 1.0,
        on_event: Optional[Callable[[str, Any], None]] = None,
        workdir: Optional[str] = None,
        strategy: str = "fifo",
    ):
        self.event = event or "default"
        self.strategy = strategy or "fifo"
        self.workdir = os.path.abspath(workdir) if workdir else WORKSPACE
        self.queue_file = os.path.join(self.workdir, "worker_queue.json")
        self.stats_file = os.path.join(self.workdir, "worker_stats.json")
        self.tasks_dir = os.path.join(self.workdir, "tasks")

        self.inbox_dirs = [os.path.abspath(os.path.expanduser(d)) for d in (inbox_dirs or [os.path.join(self.workdir, "inbox")])]
        self.scoreboard = scoreboard or get_scoreboard()
        self.auto_submit = auto_submit
        self.escalate_engine = escalate_engine or "all"
        self.flag_format = flag_format or os.environ.get("CTF_FLAG_FORMAT", "")
        self.poll_interval = max(0.2, float(poll_interval))
        self.on_event = on_event

        self._queue: List[CTFTask] = []
        self._completed: List[CTFTask] = []
        self._current_task: Optional[CTFTask] = None
        self._seen_inbox_files: Set[str] = set()

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.state = "idle"  # idle, running, solving, stopped
        self.total_points = 0
        self.solves_count = 0
        self.fails_count = 0

        # Ensure directories exist
        for d in self.inbox_dirs:
            os.makedirs(d, exist_ok=True)
        os.makedirs(self.workdir, exist_ok=True)
        os.makedirs(self.tasks_dir, exist_ok=True)

        self._load_state()

    def _emit(self, event_type: str, data: Any = None) -> None:
        if self.on_event:
            try:
                self.on_event(event_type, data)
            except Exception:
                pass

    def _save_state(self) -> None:
        try:
            with self._lock:
                q_data = [t.to_dict() for t in self._queue]
                tmp = self.queue_file + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(q_data, fh, indent=2)
                os.replace(tmp, self.queue_file)

                stats = {
                    "total_points": self.total_points,
                    "solves_count": self.solves_count,
                    "fails_count": self.fails_count,
                    "completed_count": len(self._completed),
                    "last_updated": dt.datetime.now().isoformat(),
                }
                st_tmp = self.stats_file + ".tmp"
                with open(st_tmp, "w", encoding="utf-8") as fh:
                    json.dump(stats, fh, indent=2)
                os.replace(st_tmp, self.stats_file)
        except OSError:
            pass

    def _load_state(self) -> None:
        try:
            if os.path.exists(self.queue_file):
                with open(self.queue_file, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                    self._queue = [CTFTask.from_dict(d) for d in raw if isinstance(d, dict)]
            if os.path.exists(self.stats_file):
                with open(self.stats_file, "r", encoding="utf-8") as fh:
                    st = json.load(fh)
                    self.total_points = st.get("total_points", 0)
                    self.solves_count = st.get("solves_count", 0)
                    self.fails_count = st.get("fails_count", 0)
        except Exception:
            pass

    def enqueue(
        self,
        target: str = "",
        name: str = "",
        category: str = "auto",
        briefing: str = "",
        points: int = 0,
        challenge_id: str = "",
        files: Optional[List[str]] = None,
    ) -> CTFTask:
        """Enqueue a new challenge into the worker queue."""
        task = CTFTask(
            target=target,
            name=name,
            category=category,
            briefing=briefing,
            points=points,
            challenge_id=challenge_id,
            event=self.event,
            flag_format=self.flag_format,
            files=files,
        )
        with self._lock:
            # Check duplicate by challenge_id or target
            for existing in self._queue:
                if challenge_id and existing.challenge_id == challenge_id:
                    return existing
                if target and existing.target == target and not briefing:
                    return existing
            self._queue.append(task)
        self._save_state()
        self._emit("task_enqueued", task.to_dict())
        return task

    def get_queue(self) -> List[dict]:
        with self._lock:
            return [t.to_dict() for t in self._queue]

    def get_completed(self) -> List[dict]:
        with self._lock:
            return [t.to_dict() for t in self._completed]

    def clear_queue(self) -> None:
        with self._lock:
            self._queue.clear()
        self._save_state()
        self._emit("queue_cleared")

    def sync_scoreboard(self, categories: Optional[List[str]] = None, download_files: bool = True) -> dict:
        """Query scoreboard, download attachments, and enqueue all unsolved challenges."""
        self._emit("scoreboard_sync_start")
        challs = self.scoreboard.fetch_challenges()
        if not challs:
            conn = self.scoreboard.test_connection()
            return {"ok": False, "error": conn.get("error", "No challenges returned from scoreboard")}

        enqueued_count = 0
        already_solved_count = 0
        target_cats = [c.lower() for c in categories] if categories else []

        for ch in challs:
            cid = str(ch.get("id"))
            cname = ch.get("name", f"Chall-{cid}")
            cat = (ch.get("category") or "misc").lower()
            pts = int(ch.get("value") or 0)
            is_solved = bool(ch.get("solved"))

            if is_solved:
                already_solved_count += 1
                continue

            if target_cats and cat not in target_cats:
                continue

            # Fetch details (briefing, connection info, files)
            detail = self.scoreboard.fetch_challenge_detail(cid)
            desc = detail.get("description") or ch.get("description") or ""
            conn_info = detail.get("connection_info") or ""
            file_urls = detail.get("files") or ch.get("files") or []

            combined_briefing = desc
            if conn_info:
                combined_briefing += f"\nConnection: {conn_info}"

            local_files = []
            target = conn_info.strip() if conn_info else ""

            if download_files and file_urls:
                chall_dir = os.path.join(WORKSPACE, "challenges", f"{cat}_{cid}_{re.sub(r'[^a-zA-Z0-9]', '_', cname)}")
                for f_url in file_urls:
                    local_path = self.scoreboard.download_file(f_url, chall_dir)
                    if local_path:
                        local_files.append(local_path)
                        # Set primary target to the first downloaded challenge file
                        if not target or not os.path.isfile(target):
                            target = local_path

            self.enqueue(
                target=target,
                name=cname,
                category=cat,
                briefing=combined_briefing,
                points=pts,
                challenge_id=cid,
                files=local_files,
            )
            enqueued_count += 1

        self._emit("scoreboard_sync_complete", {"enqueued": enqueued_count, "already_solved": already_solved_count})
        return {"ok": True, "enqueued": enqueued_count, "already_solved": already_solved_count, "total": len(challs)}

    def _scan_inbox(self) -> None:
        """Scan inbox folders for new challenge files or archives."""
        for inbox in self.inbox_dirs:
            if not os.path.isdir(inbox):
                continue
            for item in os.listdir(inbox):
                full_path = os.path.join(inbox, item)
                if full_path in self._seen_inbox_files or item.startswith((".", "tmp_")):
                    continue

                # Wait for file write settling
                try:
                    s1 = os.path.getsize(full_path)
                    time.sleep(0.1)
                    s2 = os.path.getsize(full_path)
                    if s1 != s2:
                        continue
                except OSError:
                    continue

                self._seen_inbox_files.add(full_path)

                # Auto-unpack archives
                if zipfile.is_zipfile(full_path):
                    extract_dir = os.path.join(WORKSPACE, "extracted", os.path.splitext(item)[0])
                    os.makedirs(extract_dir, exist_ok=True)
                    try:
                        with zipfile.ZipFile(full_path, "r") as zf:
                            zf.extractall(extract_dir)
                        # Find primary file inside archive
                        candidates = [os.path.join(extract_dir, f) for f in os.listdir(extract_dir) if not f.startswith(".")]
                        for cand in candidates:
                            self.enqueue(target=cand, name=f"{item}::{os.path.basename(cand)}")
                    except Exception:
                        self.enqueue(target=full_path, name=item)
                else:
                    self.enqueue(target=full_path, name=item)

    # -------------------------------------------------------------------------
    # Active Solving Loop (Multi-Tier)
    # -------------------------------------------------------------------------
    def _execute_tier1_triage(self, task: CTFTask) -> List[dict]:
        """Tier 1: Instant deterministic triage and recursive magic BFS decoders."""
        task.stages_run.append("tier1_triage")
        from gui import server as gui_server

        res = gui_server.solve(
            target=task.target,
            description=task.briefing,
            use_ai=False,
            category=task.category,
            event=task.event,
            engine="triage",
            flag_format=task.flag_format,
        )
        task.report_md = res.get("markdown", "")
        return res.get("flags") or []

    def _execute_tier2_solvers(self, task: CTFTask) -> List[dict]:
        """Tier 2: Category-specific heuristic solvers (angr, RSA, hashcat/john, forensics)."""
        task.stages_run.append("tier2_solvers")
        found_flags: List[dict] = []
        target = task.target
        cat = task.category

        # REV & PWN: angr auto-exploration & pwn scaffolding
        if (cat in ("rev", "pwn", "binary", "auto")) and target and os.path.isfile(target):
            angr_script = os.path.join(SOLVERS_DIR, "angr_solve.py")
            if os.path.exists(angr_script):
                ar = tool_run([PYTHON_BIN, angr_script, target], timeout=90)
                if ar.ok() or ar.found:
                    body = ar.stdout or ar.stderr
                    scanned = flagmod.scan_text(body)
                    for f in scanned:
                        f["source"] = "angr_solver"
                        found_flags.append(f)

            if cat in ("pwn", "auto"):
                pwn_script = os.path.join(SOLVERS_DIR, "pwn_scaffold.py")
                if os.path.exists(pwn_script):
                    ps = tool_run([PYTHON_BIN, pwn_script, target, task.workdir], timeout=60)
                    if ps.ok() or ps.found:
                        scanned = flagmod.scan_text(ps.stdout)
                        for f in scanned:
                            f["source"] = "pwn_scaffold"
                            found_flags.append(f)

        # CRYPTO & REV: Z3 Constraint Solver for equation blocks
        if cat in ("crypto", "rev", "misc", "auto"):
            text_for_z3 = ""
            if target and os.path.isfile(target):
                try:
                    with open(target, "r", errors="replace") as fh:
                        text_for_z3 = fh.read(50000)
                except OSError:
                    pass
            elif task.briefing:
                text_for_z3 = task.briefing

            if text_for_z3:
                try:
                    from .solvers import z3_solve
                    z3_res = z3_solve.scan_and_solve(text_for_z3)
                    if z3_res.get("solved"):
                        for f in z3_res.get("flags", []):
                            f["source"] = "z3_constraint_solver"
                            found_flags.append(f)
                except Exception:
                    pass

        # CRYPTO: RSA attacks & Hash cracking
        if cat in ("crypto", "misc", "auto"):
            # Check RSA
            rsa_script = os.path.join(SOLVERS_DIR, "rsa_solve.py")
            content_to_check = ""
            if target and os.path.isfile(target):
                try:
                    with open(target, "r", errors="replace") as fh:
                        content_to_check = fh.read(100000)
                except OSError:
                    pass
            elif task.briefing:
                content_to_check = task.briefing

            if content_to_check and ("BEGIN" in content_to_check or any(k in content_to_check for k in ("n =", "e =", "c ="))):
                tmp_rsa = os.path.join(task.workdir, "rsa_input.txt")
                with open(tmp_rsa, "w", encoding="utf-8") as fh:
                    fh.write(content_to_check)
                rr = tool_run([PYTHON_BIN, rsa_script, tmp_rsa], timeout=100)
                if rr.ok() or rr.found:
                    for f in flagmod.scan_text(rr.stdout):
                        f["source"] = "rsa_solver"
                        found_flags.append(f)

                try:
                    from .solvers import sage_crypto
                    sage_res = sage_crypto.parse_and_attack(content_to_check)
                    for f in sage_res.get("flags", []):
                        f["source"] = "sage_crypto_solver"
                        found_flags.append(f)
                except Exception:
                    pass

        # FORENSICS & STEGO: QR codes, LSB planes, deep PCAP, deep audio
        if (cat in ("forensics", "image", "stego", "auto")) and target and os.path.isfile(target):
            lower_target = target.lower()
            if lower_target.endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")):
                try:
                    from .solvers import qr_visual
                    qr_res = qr_visual.solve(target, task.workdir)
                    for f in qr_res.get("flags", []):
                        f["source"] = "qr_visual_solver"
                        found_flags.append(f)
                except Exception:
                    pass
                if lower_target.endswith(".png"):
                    try:
                        from .solvers import png_forensics
                        png_res = png_forensics.solve(target, task.workdir)
                        for f in png_res.get("flags", []):
                            f["source"] = "png_forensics_solver"
                            found_flags.append(f)
                    except Exception:
                        pass
            elif lower_target.endswith((".wav", ".mp3", ".ogg", ".flac")):
                try:
                    from .solvers import audio_deep
                    a_res = audio_deep.solve(target, task.workdir)
                    for f in a_res.get("flags", []):
                        f["source"] = "audio_deep_solver"
                        found_flags.append(f)
                except Exception:
                    pass
            elif lower_target.endswith((".pcap", ".pcapng", ".cap")):
                try:
                    from .solvers import pcap_deep
                    pcap_res = pcap_deep.solve(target, task.workdir)
                    for f in pcap_res.get("flags", []):
                        f["source"] = "pcap_deep_solver"
                        found_flags.append(f)
                except Exception:
                    pass

            if have("exiftool"):
                ex = tool_run(["exiftool", target])
                if ex.ok():
                    for f in flagmod.scan_text(ex.stdout):
                        f["source"] = "exiftool_metadata"
                        found_flags.append(f)

            # Volatility 3 Memory Forensics
            try:
                from .solvers import volatility_solve
                if volatility_solve.is_memory_dump(target):
                    vol_res = volatility_solve.solve(target, task.workdir)
                    for f in vol_res.get("flags", []):
                        f["source"] = "volatility_memory_solver"
                        found_flags.append(f)
            except Exception:
                pass

            # Deep Document and PDF stream carving
            try:
                from .solvers import doc_carve
                if target.lower().endswith((".pdf", ".docx", ".pptx", ".xlsx")):
                    dc_res = doc_carve.solve(target, task.workdir)
                    for f in dc_res.get("flags", []):
                        f["source"] = "doc_carve_solver"
                        found_flags.append(f)
            except Exception:
                pass

        # CRYPTO: Esoteric & Classical ciphers (DNA, T9, NATO, Polybius, Rail fence)
        if cat in ("crypto", "misc", "auto"):
            content_for_eso = ""
            if target and os.path.isfile(target):
                try:
                    with open(target, "r", errors="replace") as fh:
                        content_for_eso = fh.read(20000)
                except OSError:
                    pass
            elif task.briefing:
                content_for_eso = task.briefing
            if content_for_eso:
                try:
                    from .solvers import esoteric_ciphers
                    for eso in esoteric_ciphers.solve(content_for_eso):
                        for f in eso.get("flags", []):
                            f["source"] = f"esoteric_cipher_{eso['method']}"
                            found_flags.append(f)
                except Exception:
                    pass

        # WEB: SSTI / SQLi automated probes and JWT attacks
        if (cat in ("web", "url", "auto")) and target and target.startswith(("http://", "https://")):
            try:
                from .solvers import jwt_web
                web_probe = jwt_web.probe_ssti_sqli(target)
                for f in web_probe.get("flags", []):
                    f["source"] = "web_vuln_prober"
                    found_flags.append(f)
            except Exception:
                pass

            try:
                from .solvers import web_arsenal
                lfi_probe = web_arsenal.probe_lfi(target)
                for f in lfi_probe.get("flags", []):
                    f["source"] = "lfi_prober"
                    found_flags.append(f)
            except Exception:
                pass

        return found_flags

    def _execute_tier3_agent_escalation(self, task: CTFTask) -> List[dict]:
        """Tier 3: Autonomous AI Agent Escalation (ALL.AUTO / Claude MCP / AGY)."""
        task.stages_run.append("tier3_agent_escalation")
        from gui import server as gui_server

        engine = self.escalate_engine
        if engine == "none":
            return []

        if engine == "swarm":
            from .swarm import get_swarm
            res = get_swarm(event=task.event, flag_format=task.flag_format).solve(
                target=task.target,
                briefing=task.briefing,
                category=task.category,
                flag_format=task.flag_format,
            )
        elif engine in ("pwn", "rev", "crypto", "web", "forensics", "osint"):
            from .specialists import get_specialist
            res = get_specialist(engine).solve(
                target=task.target,
                briefing=task.briefing,
                evidence=task.report_md,
                workdir=task.workdir,
                provider="all",
                flag_format=task.flag_format,
            )
        elif engine == "all":
            res = gui_server.escalate(
                target=task.target,
                description=task.briefing,
                category=task.category,
                event=task.event,
                flag_format=task.flag_format,
            )
        else:
            res = gui_server.deep(
                target=task.target,
                description=task.briefing,
                provider=engine,
                category=task.category,
                event=task.event,
                flag_format=task.flag_format,
            )

        task.report_md = res.get("markdown", "") or task.report_md
        return res.get("flags") or []

    def _validate_and_filter_flags(self, flags: List[dict], flag_format: str = "") -> List[dict]:
        """Strict validation: ensure format matches, exclude placeholders and noise."""
        valid: List[dict] = []
        fmt = flag_format or self.flag_format
        fmt_regex = re.compile(fmt) if fmt else None

        for f in flags:
            candidate = f.get("flag", "").strip()
            if not candidate:
                continue
            # Filter obvious placeholder junk
            if any(p in candidate.lower() for p in ("flag{here", "flag{test", "flag{password", "flag{your_flag")):
                continue
            if fmt_regex and not fmt_regex.search(candidate):
                continue
            valid.append(f)
        return valid

    def process_task(self, task: CTFTask) -> bool:
        """Execute active worker solving cycle on a single challenge."""
        task.started_at = time.time()
        task.status = "triage"
        os.makedirs(task.workdir, exist_ok=True)
        self._current_task = task
        self._emit("task_started", task.to_dict())

        try:
            # 1. Tier 1: Instant Triage
            flags = self._execute_tier1_triage(task)
            flags = self._validate_and_filter_flags(flags, task.flag_format)

            # 2. Tier 2: Heuristic Domain Solvers
            if not flags:
                task.status = "solving"
                self._emit("task_phase_change", {"task": task.id, "phase": "tier2_solvers"})
                t2_flags = self._execute_tier2_solvers(task)
                flags.extend(self._validate_and_filter_flags(t2_flags, task.flag_format))

            # 3. Tier 3: AI Agent Escalation
            if not flags and self.escalate_engine != "none":
                task.status = "escalating"
                self._emit("task_phase_change", {"task": task.id, "phase": "tier3_agent_escalation"})
                t3_flags = self._execute_tier3_agent_escalation(task)
                flags.extend(self._validate_and_filter_flags(t3_flags, task.flag_format))

            task.flags = flags

            # 4. Handle flag discovery & auto-submission
            if flags:
                top_flag = flags[0]["flag"]
                task.solved_flag = top_flag
                task.solved_by = flags[0].get("source", "worker")

                # Auto-submit if configured and linked to scoreboard
                if self.auto_submit and task.challenge_id:
                    task.status = "submitting"
                    self._emit("task_phase_change", {"task": task.id, "phase": "submitting_flag"})
                    verdict = self.scoreboard.submit_flag(top_flag, task.challenge_id)
                    task.submission_verdict = verdict
                    if verdict.get("status") == "correct":
                        self.total_points += task.points
                        self._emit("flag_submitted_correct", {"task": task.id, "flag": top_flag, "points": task.points})
                    elif verdict.get("status") == "already_solved":
                        self._emit("flag_already_solved", {"task": task.id, "flag": top_flag})
                    else:
                        self._emit("flag_submission_rejected", {"task": task.id, "verdict": verdict})

                # Vault save & writeup generation
                try:
                    ensure_event(task.event)
                    add_solve(
                        event_name=task.event,
                        triage_result={"target": {"raw": task.target or task.name}, "workdir": task.workdir, "steps": []},
                        flag=top_flag,
                        engine=task.solved_by,
                    )
                except Exception:
                    pass

                # Webhook alert (Discord / Slack / Telegram)
                webhook_url = os.environ.get("CTF_WEBHOOK_URL", "")
                if webhook_url:
                    try:
                        import urllib.request
                        msg = {
                            "content": f"🚩 **[KRYPT] FLAG CAPTURED!**\n> Challenge: `{task.name}` ({task.category})\n> Points: `+{task.points}`\n> Solved by: `{task.solved_by}`\n```\n{top_flag}\n```"
                        }
                        req = urllib.request.Request(
                            webhook_url,
                            data=json.dumps(msg).encode("utf-8"),
                            headers={"Content-Type": "application/json", "User-Agent": "KRYPT/2.2"}
                        )
                        urllib.request.urlopen(req, timeout=5)
                    except Exception:
                        pass

                task.status = "solved"
                self.solves_count += 1
                self._emit("task_solved", task.to_dict())
                return True
            else:
                task.status = "failed"
                task.error = "No flag captured within available solver budget"
                self.fails_count += 1
                self._emit("task_failed", task.to_dict())
                return False

        except Exception as e:
            task.status = "failed"
            task.error = f"Worker exception: {e}"
            self.fails_count += 1
            self._emit("task_error", {"task": task.id, "error": str(e)})
            return False
        finally:
            task.finished_at = time.time()
            task.duration_sec = round(task.finished_at - task.started_at, 2)
            self._current_task = None
            with self._lock:
                if task in self._queue:
                    self._queue.remove(task)
                self._completed.append(task)
            self._save_state()

    def process_next(self) -> Optional[CTFTask]:
        """Pops and executes the highest-priority queued challenge according to strategy."""
        with self._lock:
            if not self._queue:
                return None
            if self.strategy == "easy-first":
                self._queue.sort(key=lambda t: (t.points if t.points > 0 else 999999, t.created_at))
            elif self.strategy == "high-points":
                self._queue.sort(key=lambda t: (-t.points, t.created_at))
            task = self._queue[0]

        self.process_task(task)
        return task

    def start(self) -> None:
        """Start background worker thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self.state = "running"
            self._thread = threading.Thread(target=self._worker_loop, name="krypt-worker", daemon=True)
            self._thread.start()
        self._emit("worker_started")

    def stop(self) -> None:
        """Stop background worker thread."""
        self._stop_event.set()
        with self._lock:
            self.state = "stopped"
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._emit("worker_stopped")

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            self._scan_inbox()
            task = self.process_next()
            if not task:
                self.state = "idle"
                time.sleep(self.poll_interval)
            else:
                self.state = "running"

    def status(self) -> dict:
        """Return live health and statistics."""
        with self._lock:
            cur = self._current_task.to_dict() if self._current_task else None
            return {
                "ok": True,
                "state": self.state,
                "event": self.event,
                "queue_length": len(self._queue),
                "completed_count": len(self._completed),
                "solves_count": self.solves_count,
                "fails_count": self.fails_count,
                "total_points": self.total_points,
                "current_task": cur,
                "inbox_dirs": self.inbox_dirs,
                "auto_submit": self.auto_submit,
                "escalate_engine": self.escalate_engine,
            }


# Global singleton access
_WORKER_INSTANCE: Optional[CTFWorker] = None


def get_worker(event: str = "default") -> CTFWorker:
    global _WORKER_INSTANCE
    if _WORKER_INSTANCE is None:
        _WORKER_INSTANCE = CTFWorker(event=event)
    return _WORKER_INSTANCE


def run_cli(worker: CTFWorker, continuous: bool = True) -> int:
    """Run worker in the foreground with live ANSI terminal output."""
    _COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    _C = {
        "g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "m": "\033[95m",
        "r": "\033[91m", "d": "\033[90m", "b": "\033[1m", "x": "\033[0m"
    } if _COLOR else dict.fromkeys("gymrdcbx", "")

    def on_event(ev: str, data: Any):
        ts = dt.datetime.now().strftime("%H:%M:%S")
        if ev == "task_enqueued":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['c']}[+]{_C['x']} Enqueued: {_C['b']}{data.get('name')}{_C['x']} "
                  f"({data.get('category')}, {data.get('points')} pts)")
        elif ev == "task_started":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['b']}[*] Solving:{_C['x']} {data.get('name')} "
                  f"{_C['d']}[{data.get('target') or data.get('briefing')[:40]}]{_C['x']}")
        elif ev == "task_phase_change":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['y']}[~]{_C['x']} Phase: {_C['b']}{data.get('phase')}{_C['x']}")
        elif ev == "task_solved":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['g']}[✓] SOLVED:{_C['x']} {_C['b']}{data.get('name')}{_C['x']} "
                  f"in {data.get('duration_sec')}s! Flag: {_C['g']}{_C['b']}{data.get('solved_flag')}{_C['x']}")
        elif ev == "task_failed":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['r']}[✗] FAILED:{_C['x']} {data.get('name')} — {data.get('error')}")
        elif ev == "flag_submitted_correct":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['m']}[★] SCOREBOARD:{_C['x']} {_C['g']}{_C['b']}FLAG ACCEPTED!{_C['x']} "
                  f"(+{data.get('points')} pts) | Total: {_C['b']}{worker.total_points} pts{_C['x']}")
        elif ev == "flag_already_solved":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['y']}[-] SCOREBOARD:{_C['x']} Already solved on platform.")
        elif ev == "flag_submission_rejected":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['r']}[!] SCOREBOARD REJECTED:{_C['x']} {data.get('verdict', {}).get('message')}")
        elif ev == "scoreboard_sync_complete":
            print(f"{_C['d']}[{ts}]{_C['x']} {_C['c']}[i]{_C['x']} Scoreboard synced: "
                  f"{_C['b']}{data.get('enqueued')}{_C['x']} challenge(s) enqueued.")

    worker.on_event = on_event

    print(f"\n{_C['b']}========================================================================{_C['x']}")
    print(f"                 {_C['c']}◆ KRYPT · ACTIVE CTF WORKER DAEMON ◆{_C['x']}")
    print(f"{_C['b']}========================================================================{_C['x']}")
    print(f"Event: {_C['b']}{worker.event}{_C['x']} | Engine: {_C['b']}{worker.escalate_engine}{_C['x']} | Auto-Submit: {_C['g'] if worker.auto_submit else _C['d']}{worker.auto_submit}{_C['x']}")
    print(f"Inboxes: {', '.join(worker.inbox_dirs)}")
    print(f"Scoreboard: {_C['b']}{worker.scoreboard.url or 'None'}{_C['x']} ({worker.scoreboard.platform})")
    print(f"{_C['d']}Press Ctrl+C to stop worker.{_C['x']}\n")

    try:
        if not continuous:
            worker._scan_inbox()
            while worker.process_next():
                pass
            print(f"\n{_C['g']}[*] Queue empty. Worker finished single pass.{_C['x']}")
            return 0

        while True:
            worker._scan_inbox()
            task = worker.process_next()
            if not task:
                time.sleep(worker.poll_interval)
    except KeyboardInterrupt:
        print(f"\n{_C['y']}[!] Worker interrupted by operator. Cleaning up...{_C['x']}")
        return 0

