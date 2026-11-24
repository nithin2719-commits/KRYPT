"""Unit tests for the KRYPT solver plugin registry and auto-discovery system."""
from __future__ import annotations

import os
import tempfile
import unittest

from ctfsolver.solvers import (
    RegisteredSolver,
    SolverContext,
    auto_discover,
    clear_registry,
    get_matching_solvers,
    get_registry,
    register,
    register_solver,
)


class TestSolverRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        # Save registry state
        self._saved_registry = get_registry()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        # Restore registry
        clear_registry()
        for s in self._saved_registry.values():
            register(s)

    def test_manual_register_and_query(self):
        clear_registry()
        spec = RegisteredSolver(
            name="dummy_solver",
            fn=lambda ctx: {"step": "dummy", "flags": [{"flag": "flag{manual_reg_pass}"}]},
            category="crypto",
            priority=60,
            match_ext=(".dummy",),
        )
        register(spec)
        self.assertIn("dummy_solver", get_registry())

        # Test match
        ctx_match = SolverContext(target="sample.dummy", category="auto")
        matched = get_matching_solvers(ctx_match)
        self.assertTrue(any(s.name == "dummy_solver" for s in matched))

        # Test non-match
        ctx_no_match = SolverContext(target="sample.txt", category="web")
        matched_no = get_matching_solvers(ctx_no_match)
        self.assertFalse(any(s.name == "dummy_solver" for s in matched_no))

    def test_decorator_with_context_signature(self):
        clear_registry()

        @register_solver(
            name="custom_ctx_solver",
            category="forensics",
            priority=75,
            match_ext=(".custom",),
        )
        def custom_solve(ctx: SolverContext):
            return {"step": "custom", "flags": [{"flag": f"flag{{{ctx.target}}}"}]}

        self.assertIn("custom_ctx_solver", get_registry())
        ctx = SolverContext(target="flag_file.custom", workdir=self.tmp_dir)
        matched = get_matching_solvers(ctx)
        self.assertEqual(len(matched), 1)
        res = matched[0].fn(ctx)
        self.assertEqual(res["flags"][0]["flag"], "flag{flag_file.custom}")

    def test_decorator_adapted_signatures(self):
        clear_registry()

        # (target, workdir) adapter
        @register_solver(name="adapted_two_args", match_ext=(".two",))
        def solve_two(target: str, workdir: str):
            return {"step": "two", "flags": [{"flag": f"flag{{{os.path.basename(target)}_{os.path.basename(workdir)}}}"}]}

        # (text) adapter
        @register_solver(name="adapted_text_arg", match_fn=lambda ctx: "KEYWORD_TEST" in ctx.combined_text)
        def solve_text(text: str):
            return {"step": "text", "flags": [{"flag": "flag{keyword_matched}"}]}

        ctx1 = SolverContext(target="/path/to/test.two", workdir="/tmp/work")
        m1 = get_matching_solvers(ctx1)
        self.assertTrue(any(s.name == "adapted_two_args" for s in m1))
        r1 = [s for s in m1 if s.name == "adapted_two_args"][0].fn(ctx1)
        self.assertEqual(r1["flags"][0]["flag"], "flag{test.two_work}")

        ctx2 = SolverContext(combined_text="some text with KEYWORD_TEST inside")
        m2 = get_matching_solvers(ctx2)
        self.assertTrue(any(s.name == "adapted_text_arg" for s in m2))
        r2 = [s for s in m2 if s.name == "adapted_text_arg"][0].fn(ctx2)
        self.assertEqual(r2["flags"][0]["flag"], "flag{keyword_matched}")

    def test_priority_ordering(self):
        clear_registry()

        @register_solver(name="low_prio", priority=10, match_ext=(".multi",))
        def solve_low(ctx: SolverContext):
            return {"step": "low"}

        @register_solver(name="high_prio", priority=99, match_ext=(".multi",))
        def solve_high(ctx: SolverContext):
            return {"step": "high"}

        @register_solver(name="mid_prio", priority=50, match_ext=(".multi",))
        def solve_mid(ctx: SolverContext):
            return {"step": "mid"}

        ctx = SolverContext(target="chal.multi")
        matched = get_matching_solvers(ctx)
        names = [s.name for s in matched]
        self.assertEqual(names, ["high_prio", "mid_prio", "low_prio"])

    def test_auto_discover_builtins(self):
        clear_registry()
        auto_discover()
        reg = get_registry()

        expected = [
            "z3",
            "rsa_attacks",
            "sage",
            "xor_solver",
            "qr",
            "png_forensics",
            "audio",
            "pcap",
            "doc",
            "zip_forensics",
            "volatility",
            "esoteric",
            "sidechannel",
        ]
        for name in expected:
            self.assertIn(name, reg, f"Expected built-in solver '{name}' to be auto-discovered")

    def test_god_solver_executes_dynamically_registered_plugin(self):
        from ctfsolver import god

        # Register a unique custom plugin
        @register_solver(
            name="test_apex_dynamic_plugin",
            priority=100,
            match_fn=lambda ctx: "SPECIAL_CHALLENGE_TOKEN_XYZ" in ctx.combined_text,
        )
        def dynamic_solver(ctx: SolverContext):
            return {
                "step": "dynamic-test",
                "flags": [{"flag": "flag{apex_plugin_auto_discovered_and_solved}", "kind": "named", "confidence": 100}],
            }

        res = god.solve(
            briefing="Challenge description containing SPECIAL_CHALLENGE_TOKEN_XYZ for solver testing",
            event="test-plugin",
            timeout=10,
        )
        self.assertTrue(res.get("solved"))
        self.assertEqual(res.get("flag"), "flag{apex_plugin_auto_discovered_and_solved}")


if __name__ == "__main__":
    unittest.main()
