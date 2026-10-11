"""Tests for parallel engine racing in the GUI backend's escalate()."""
import importlib.util
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_spec = importlib.util.spec_from_file_location(
    "krypt_server", os.path.join(ROOT, "gui", "server.py"))
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)

import ctfsolver.ai_api as ai_api  # the module escalate() imports  # noqa: E402


def _res(flags=None):
    return {"markdown": "md", "workdir": "/tmp", "steps": [], "flags": flags or []}


class TestRacing(unittest.TestCase):
    def setUp(self):
        os.environ.pop("KRYPT_AGY_YOLO", None)
        self._orig = {k: getattr(server, k) for k in ("solve", "_run_provider")}
        self._ai_avail = server.ai.available
        self._agents_avail = server.agents.available
        self._apiavail = ai_api.available
        server.ai.available = lambda: False            # skip the local GPU gate
        server.agents.available = lambda: {"claude": True, "agy": True}
        ai_api.available = lambda: True
        self.calls = []

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(server, k, v)
        server.ai.available = self._ai_avail
        server.agents.available = self._agents_avail
        ai_api.available = self._apiavail

    def _fake_provider(self, plan):
        def rp(provider, *a, **k):
            self.calls.append(provider)
            delay, flag = plan.get(provider, (0, ""))
            time.sleep(delay)
            flags = [{"flag": flag, "kind": "agent", "confidence": 90}] if flag else []
            return {"provider": provider,
                    "ag": {"ok": True, "provider": provider, "output": flag or "none"},
                    "flags": flags,
                    "step": {"step": f"deep-agent({provider})", "summary": "x",
                             "output": flag or "", "flags": flags}}
        return rp

    def test_first_flag_wins_the_race(self):
        server.solve = lambda *a, **k: _res()           # free gate finds nothing
        server._run_provider = self._fake_provider(
            {"claude": (0.40, "FLAG{slow}"), "api": (0.02, "FLAG{fast}")})
        res = server.escalate("t", "d")
        self.assertEqual(res["escalation"]["solved_by"], "claude-api")
        self.assertEqual(res["flags"][0]["flag"], "FLAG{fast}")
        self.assertIn("api", self.calls)                # the race actually ran

    def test_free_gate_short_circuits(self):
        server.solve = lambda *a, **k: _res([{"flag": "flag{free}", "confidence": 90,
                                              "kind": "named"}])
        server._run_provider = self._fake_provider({"claude": (0, "x")})
        res = server.escalate("t", "d")
        self.assertEqual(res["escalation"]["solved_by"], "triage")
        self.assertEqual(self.calls, [])                # no paid engine was touched

    def test_no_winner_falls_back_to_agy_handoff(self):
        server.solve = lambda *a, **k: _res()
        server._run_provider = self._fake_provider(
            {"claude": (0.02, ""), "api": (0.02, ""), "agy": (0, "")})
        res = server.escalate("t", "d")
        self.assertIsNone(res["escalation"]["solved_by"])
        self.assertIn("agy", res["escalation"]["tried"])
        steps = [s["step"] for s in res["steps"]]
        self.assertIn("deep-agent(agy)", steps)         # hand-off step attached


if __name__ == "__main__":
    unittest.main()
