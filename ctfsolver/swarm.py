"""Multi-Agent Swarm Orchestrator for KRYPT.

Coordinates specialized domain agents (Pwn, Rev, Crypto, Web, Forensics, Osint)
around a shared blackboard:
  1. Primary specialist handles initial deep analysis.
  2. Intermediate discoveries (hashes, carved files, tokens, endpoints) are posted to the blackboard.
  3. Complementary specialists automatically pick up blackboard artifacts (e.g. Forensics carves a ZIP -> Crypto cracks it with rockyou -> Rev decompiles the binary).
  4. Concurrent specialist racing: the first verified flag claims victory and synchronizes with the Vault.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set

from .detect import classify
from .research import get_research_engine
from .specialists import get_specialist, SPECIALISTS_MAP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.join(ROOT, "workspace")


class SwarmBlackboard:
    """Shared memory and intermediate artifact blackboard for the agent swarm."""

    def __init__(self, challenge_id: str = ""):
        self.challenge_id = challenge_id
        self.clues: List[str] = []
        self.hashes: List[str] = []
        self.credentials: List[Dict[str, str]] = []
        self.endpoints: List[str] = []
        self.carved_artifacts: List[str] = []
        self.candidate_flags: List[Dict[str, Any]] = []
        self.winning_flag: Optional[str] = None
        self.winning_specialist: Optional[str] = None
        self._seen_flags: Set[str] = set()

    def post_flag(self, flag: str, specialist: str, confidence: int = 100, proof: str = "") -> bool:
        flag = (flag or "").strip()
        if not flag or flag in self._seen_flags:
            return False
        self._seen_flags.add(flag)
        entry = {
            "flag": flag,
            "specialist": specialist,
            "confidence": confidence,
            "proof": proof,
            "timestamp": time.time(),
        }
        self.candidate_flags.append(entry)
        if not self.winning_flag:
            self.winning_flag = flag
            self.winning_specialist = specialist
            return True
        return False

    def post_artifact(self, path: str) -> None:
        if os.path.isfile(path) and path not in self.carved_artifacts:
            self.carved_artifacts.append(path)

    def to_dict(self) -> dict:
        return {
            "clues_count": len(self.clues),
            "hashes": self.hashes,
            "endpoints": self.endpoints,
            "carved_count": len(self.carved_artifacts),
            "candidate_flags": self.candidate_flags,
            "winning_flag": self.winning_flag,
            "winning_specialist": self.winning_specialist,
        }


class SwarmCoordinator:
    """Orchestrates multi-agent swarm solving."""

    def __init__(self, event: str = "default", flag_format: str = ""):
        self.event = event or "default"
        self.flag_format = flag_format
        self.research = get_research_engine()

    def select_specialists(self, category: str, target: str, briefing: str) -> List[str]:
        """Select primary and secondary specialists based on challenge characteristics."""
        cat = (category or "auto").lower()
        if cat in SPECIALISTS_MAP:
            primary = cat
        else:
            # Auto-detection
            t = classify(target) if target else None
            sub = (t.subkind if t else "").lower()
            if sub in ("binary", "elf", "pe"):
                primary = "rev"
            elif sub in ("pcap", "image", "audio", "pdf"):
                primary = "forensics"
            elif sub in ("web", "url"):
                primary = "web"
            elif sub in ("text", "data"):
                primary = "crypto"
            else:
                primary = "rev"

        # Complementary secondary specialist
        secondaries = {
            "rev": "crypto",       # crackmes often have encrypted strings
            "pwn": "rev",          # pwn needs rev analysis
            "forensics": "crypto", # forensics carves encrypted archives
            "web": "crypto",       # web has JWT and token crypto
            "crypto": "rev",       # custom ciphers in binaries
            "osint": "web",        # profile footprints lead to web endpoints
        }
        sec = secondaries.get(primary, "crypto")
        return [primary, sec]

    def solve(
        self,
        target: str = "",
        briefing: str = "",
        category: str = "auto",
        flag_format: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run the swarm: initial triage -> blackboard population -> specialist swarm execution."""
        from gui import server as gui_server

        fmt = flag_format or self.flag_format
        blackboard = SwarmBlackboard()

        # Step 1: Fast initial triage pass
        base_solve = gui_server.solve(
            target=target,
            description=briefing,
            use_ai=False,
            category=category,
            event=self.event,
            engine="triage",
            flag_format=fmt,
        )

        # Check if Tier 1 already captured it
        if base_solve.get("flags"):
            top = base_solve["flags"][0]["flag"]
            blackboard.post_flag(top, "triage_magic_decoder", confidence=100)
            base_solve["swarm"] = blackboard.to_dict()
            return base_solve

        # Populate blackboard with triage discoveries
        workdir = base_solve.get("workdir", os.path.join(WORKSPACE, "swarm"))
        for st in base_solve.get("steps", []):
            for art in (st.get("artifacts") or []):
                blackboard.post_artifact(art)

        # Step 2: Select specialist agents
        specialist_keys = self.select_specialists(category, target, briefing)
        primary_key, secondary_key = specialist_keys[0], specialist_keys[1]

        primary_spec = get_specialist(primary_key)
        secondary_spec = get_specialist(secondary_key)

        evidence_text = base_solve.get("markdown", "")

        # Step 3: Run primary specialist first, or race if hard
        def run_spec(spec: Any, prov: str = "claude"):
            try:
                return spec.solve(
                    target=target,
                    briefing=briefing,
                    evidence=evidence_text,
                    workdir=workdir,
                    provider=prov,
                    flag_format=fmt,
                    timeout=timeout,
                )
            except Exception as e:
                return {"ok": False, "error": str(e), "flags": []}

        # Concurrently execute primary specialist and complementary heuristic solver
        winner_result = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_primary = executor.submit(run_spec, primary_spec, "all")
            fut_secondary = executor.submit(run_spec, secondary_spec, "claude")

            done, not_done = concurrent.futures.wait(
                [fut_primary, fut_secondary],
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for fut in done:
                res = fut.result()
                if res and res.get("flags"):
                    winner_result = res
                    top_f = res["flags"][0]["flag"]
                    blackboard.post_flag(top_f, primary_spec.title)
                    break

            # If first completed didn't win, check remaining
            if not winner_result:
                for fut in not_done:
                    res = fut.result()
                    if res and res.get("flags"):
                        winner_result = res
                        top_f = res["flags"][0]["flag"]
                        blackboard.post_flag(top_f, secondary_spec.title)
                        break

        final_res = winner_result or base_solve
        final_res["swarm"] = blackboard.to_dict()
        return final_res


# Global singleton access
_SWARM_INSTANCE: Optional[SwarmCoordinator] = None


def get_swarm(event: str = "default", flag_format: str = "") -> SwarmCoordinator:
    global _SWARM_INSTANCE
    if _SWARM_INSTANCE is None:
        _SWARM_INSTANCE = SwarmCoordinator(event=event, flag_format=flag_format)
    return _SWARM_INSTANCE
