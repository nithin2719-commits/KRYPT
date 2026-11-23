"""GOD-TIER CTF SOLVER: The apex autonomous multi-engine flag hunter.
Orchestrates every heuristic, symbolic, lattice, exploit, and swarm specialist concurrently.
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from . import detect
from .categories import toolset
from .flags import scan_bytes, scan_file, scan_text, scan_encoded
from .scoreboard import get_scoreboard
from .swarm import get_swarm
from .vault import add_solve, ensure_event


class GodSolver:
    """The Apex Autonomous CTF Solving Engine."""

    def __init__(
        self,
        event: str = "god-tier",
        flag_format: str = "",
        auto_submit: bool = True,
        on_progress: Optional[Callable[[str, Any], None]] = None,
    ):
        self.event = event or "god-tier"
        self.flag_format = flag_format or os.environ.get("CTF_FLAG_FORMAT", "")
        self.auto_submit = auto_submit
        self.on_progress = on_progress
        self.scoreboard = get_scoreboard()
        self.start_time = 0.0

    def _log(self, stage: str, message: str) -> None:
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        timestamp = f"[{elapsed:6.2f}s]"
        msg = f"⚡ [GOD-SOLVER] {timestamp} [{stage.upper()}] {message}"
        print(msg, file=sys.stderr)
        if self.on_progress:
            self.on_progress(stage, {"message": message, "elapsed": elapsed})

    def solve(
        self,
        target: str = "",
        briefing: str = "",
        category: str = "auto",
        flag_format: str = "",
        workdir: str = "",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Execute the apex god-tier solving pipeline on target/briefing."""
        self.start_time = time.time()
        fmt = flag_format or self.flag_format
        resolved_category = category

        # Generate isolated workspace
        target_name = os.path.basename(target) if target else "briefing"
        ts_id = int(time.time() * 1000) % 1000000
        safe_workdir = workdir or os.path.abspath(f"workspace/god-{target_name}-{ts_id}")
        os.makedirs(safe_workdir, exist_ok=True)

        self._log("INIT", f"Target: {target or '(fileless briefing)'} | Category: {category} | Workdir: {safe_workdir}")

        all_flags: list[dict[str, Any]] = []
        phases_run: list[str] = []
        findings_log: list[str] = []

        # =====================================================================
        # PHASE 0: TARGET ACQUISITION & DETECTION
        # =====================================================================
        target_info = None
        if target:
            target_info = detect.classify(target)
            if resolved_category == "auto":
                resolved_category = target_info.subkind if target_info.kind == "file" else target_info.kind
        self._log("DETECT", f"Identified category: {resolved_category}")
        phases_run.append("detection")

        # =====================================================================
        # PHASE 1: INSTANT MAGIC & HEURISTIC DECODERS (TIER 1)
        # =====================================================================
        self._log("TIER1", "Launching Instant Magic BFS decoders and text sweeps...")
        phases_run.append("tier1_magic")

        # Briefing sweep
        if briefing:
            b_flags = scan_text(briefing)
            if b_flags:
                all_flags.extend(b_flags)
                findings_log.append(f"Briefing scan recovered {len(b_flags)} candidate(s)")

        # Target file sweep
        if target and os.path.isfile(target):
            try:
                raw_flags = scan_file(target)
                all_flags.extend(raw_flags)
                with open(target, "rb") as fh:
                    f_bytes = fh.read(16 * 1024 * 1024)
                enc_flags = scan_encoded(f_bytes)
                all_flags.extend(enc_flags)

                # Magic BFS decoder
                from .decoders import magic
                m = magic(f_bytes)
                if m.get("found"):
                    all_flags.extend(m.get("flags", []))
                    findings_log.append(f"Magic BFS decoder recovered flag: {m.get('flags', [])}")
            except Exception as e:
                self._log("TIER1", f"Instant triage error: {e}")

        # Check if Tier 1 captured the flag
        valid_t1 = self._validate_flags(all_flags, fmt)
        if valid_t1:
            return self._finalize_solve(valid_t1[0], "tier1_magic", target, briefing, safe_workdir, findings_log, phases_run)

        # =====================================================================
        # PHASE 2: ADVANCED DOMAIN & SYMBOLIC SOLVERS (TIER 2 PARALLEL)
        # =====================================================================
        self._log("TIER2", "Spawning parallel deep domain solvers (Z3, SageMath, QR, Audio, PCAP, Scaffolder)...")
        phases_run.append("tier2_advanced")

        solver_tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            # 1. Z3 Constraint Solver
            text_for_z3 = briefing
            if target and os.path.isfile(target):
                try:
                    with open(target, "r", errors="replace") as fh:
                        text_for_z3 += "\n" + fh.read(40000)
                except OSError:
                    pass
            if text_for_z3:
                def run_z3():
                    from .solvers import z3_solve
                    return ("z3", z3_solve.scan_and_solve(text_for_z3))
                solver_tasks.append(executor.submit(run_z3))

            # 2. SageMath Lattice & RSA Solver
            if text_for_z3 and ("BEGIN" in text_for_z3 or any(k in text_for_z3 for k in ("n =", "e =", "c ="))):
                def run_sage():
                    from .solvers import sage_crypto
                    return ("sage", sage_crypto.parse_and_attack(text_for_z3))
                solver_tasks.append(executor.submit(run_sage))

            # 3. Visual & QR Stego (if image)
            if target and target.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")):
                def run_qr():
                    from .solvers import qr_visual
                    return ("qr", qr_visual.solve(target, safe_workdir))
                solver_tasks.append(executor.submit(run_qr))

            # 4. Audio Deep & DTMF (if audio)
            if target and target.lower().endswith((".wav", ".mp3", ".ogg", ".flac")):
                def run_audio():
                    from .solvers import audio_deep
                    return ("audio", audio_deep.solve(target, safe_workdir))
                solver_tasks.append(executor.submit(run_audio))

            # 5. PCAP Deep & ICMP tunnels (if pcap)
            if target and target.lower().endswith((".pcap", ".pcapng", ".cap")):
                def run_pcap():
                    from .solvers import pcap_deep
                    return ("pcap", pcap_deep.solve(target, safe_workdir))
                solver_tasks.append(executor.submit(run_pcap))

            # 6. Document & PDF Stream Carving (if PDF / Office document)
            if target and target.lower().endswith((".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods")):
                def run_doc():
                    from .solvers import doc_carve
                    return ("doc", doc_carve.solve(target, safe_workdir))
                solver_tasks.append(executor.submit(run_doc))

            # 7. Memory Dump Forensics (if memory image)
            if target and os.path.isfile(target):
                from .solvers import volatility_solve
                if volatility_solve.is_memory_dump(target):
                    def run_vol():
                        return ("volatility", volatility_solve.run_volatility_plugins(target, safe_workdir))
                    solver_tasks.append(executor.submit(run_vol))

            # 8. Esoteric Ciphers (DNA, T9, NATO, Polybius, Rail Fence)
            if text_for_z3:
                def run_esoteric():
                    from .solvers import esoteric_ciphers
                    res = esoteric_ciphers.solve(text_for_z3)
                    e_flags = []
                    for r in res:
                        e_flags.extend(r.get("flags", []))
                    return ("esoteric", {"flags": e_flags})
                solver_tasks.append(executor.submit(run_esoteric))

            # 9. Side-channel crackme analysis (if binary)
            if target and os.path.isfile(target) and os.access(target, os.X_OK):
                def run_sidechannel():
                    from .solvers import sidechannel_solve
                    return ("sidechannel", sidechannel_solve.solve(target, safe_workdir))
                solver_tasks.append(executor.submit(run_sidechannel))

            # Gather results
            for future in concurrent.futures.as_completed(solver_tasks, timeout=90):
                try:
                    s_name, s_res = future.result()
                    s_flags = s_res.get("flags", [])
                    if s_flags:
                        for f in s_flags:
                            f["source"] = f"god_tier_{s_name}"
                        all_flags.extend(s_flags)
                        findings_log.append(f"Solver [{s_name}] found {len(s_flags)} flag candidate(s)")
                        self._log("HIT", f"Solver [{s_name}] captured candidate flag!")
                except Exception as ex:
                    self._log("TIER2", f"Solver exception: {ex}")

        valid_t2 = self._validate_flags(all_flags, fmt)
        if valid_t2:
            return self._finalize_solve(valid_t2[0], valid_t2[0].get("source", "tier2_solvers"), target, briefing, safe_workdir, findings_log, phases_run)

        # =====================================================================
        # PHASE 3: MULTI-AGENT SWARM & SPECIALIST COOPERATION (TIER 3)
        # =====================================================================
        if time.time() - self.start_time >= timeout:
            self._log("TIMEOUT", f"Time budget ({timeout}s) reached; skipping Swarm escalation.")
        else:
            self._log("SWARM", "Escalating to multi-agent Swarm Coordinator across cross-domain specialists...")
            phases_run.append("tier3_swarm")

            try:
                swarm = get_swarm(event=self.event, flag_format=fmt)
                swarm_res = swarm.solve(
                    target=target,
                    briefing=briefing,
                    category=resolved_category,
                    flag_format=fmt,
                )
                swarm_flags = swarm_res.get("flags", [])
                if swarm_flags:
                    all_flags.extend(swarm_flags)
                    findings_log.append(f"Swarm coordinator recovered {len(swarm_flags)} flag(s)")
            except Exception as ex:
                self._log("SWARM", f"Swarm escalation error: {ex}")

        valid_t3 = self._validate_flags(all_flags, fmt)
        if valid_t3:
            return self._finalize_solve(valid_t3[0], "god_swarm_coordinator", target, briefing, safe_workdir, findings_log, phases_run)

        # If no flags found
        self._log("COMPLETE", "Search exhausted across all tiers without definitive flag candidate.")
        return {
            "solved": False,
            "flag": "",
            "category": resolved_category,
            "phases_run": phases_run,
            "workdir": safe_workdir,
            "duration": round(time.time() - self.start_time, 2),
            "findings": findings_log,
            "all_candidates": all_flags,
        }

    def _validate_flags(self, flags: List[dict[str, Any]], flag_format: str = "") -> List[dict[str, Any]]:
        """Filter out placeholder noise and ensure format compatibility."""
        valid = []
        import re
        pat = re.compile(flag_format) if flag_format else None

        for f in flags:
            candidate = f.get("flag", "").strip()
            if not candidate:
                continue
            if any(p in candidate.lower() for p in ("flag{here", "flag{test", "flag{password", "flag{your_flag", "flag{placeholder")):
                continue
            if pat and not pat.search(candidate):
                continue
            valid.append(f)
        return valid

    def _finalize_solve(
        self,
        flag_dict: dict[str, Any],
        engine_name: str,
        target: str,
        briefing: str,
        workdir: str,
        findings: list[str],
        phases: list[str],
    ) -> dict[str, Any]:
        """Record capture, submit to scoreboard if active, notify webhook, and write Vault entry."""
        flag_str = flag_dict["flag"]
        duration = round(time.time() - self.start_time, 2)
        self._log("SOLVED", f"FLAG CAPTURED: {flag_str} (via {engine_name} in {duration}s)")

        # Auto-submit if configured
        submission_verdict = None
        if self.auto_submit and self.scoreboard and self.scoreboard.is_configured:
            self._log("SUBMIT", "Auto-submitting flag to scoreboard...")
            submission_verdict = self.scoreboard.submit_flag(flag_str)

        # Vault save
        try:
            ensure_event(self.event)
            add_solve(
                event_name=self.event,
                triage_result={"target": {"raw": target or "briefing"}, "workdir": workdir, "steps": []},
                flag=flag_str,
                engine=engine_name,
            )
        except Exception:
            pass

        # Webhook alert
        webhook_url = os.environ.get("CTF_WEBHOOK_URL", "")
        if webhook_url:
            try:
                import urllib.request
                msg = {
                    "content": f"⚡ **[GOD-TIER SOLVER] FLAG CAPTURED!**\n> Engine: `{engine_name}` ({duration}s)\n> Target: `{target or 'briefing'}`\n```\n{flag_str}\n```"
                }
                req = urllib.request.Request(
                    webhook_url,
                    data=json.dumps(msg).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "KRYPT/2.3"}
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

        return {
            "solved": True,
            "flag": flag_str,
            "engine": engine_name,
            "duration": duration,
            "workdir": workdir,
            "phases_run": phases,
            "findings": findings,
            "submission": submission_verdict,
        }


def solve(target: str = "", briefing: str = "", category: str = "auto", flag_format: str = "", event: str = "god-tier", timeout: int = 300) -> dict[str, Any]:
    """Top-level invocation for GodSolver."""
    gs = GodSolver(event=event, flag_format=flag_format)
    return gs.solve(target=target, briefing=briefing, category=category, flag_format=flag_format, timeout=timeout)
