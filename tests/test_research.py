"""Tests for dynamic tools research and specialist agents."""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.research import ToolsResearchEngine, get_research_engine
from ctfsolver.specialists import SpecialistAgent, get_specialist, SPECIALISTS_MAP
from ctfsolver.swarm import SwarmBlackboard, SwarmCoordinator


class TestToolsResearchEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ToolsResearchEngine()

    def test_known_tool_availability_check(self):
        # 'strings' and 'file' are standard unix tools on Linux
        self.assertTrue(self.engine.is_available("strings"))
        self.assertTrue(self.engine.is_available("file"))

    def test_inventory_returns_categories(self):
        inv = self.engine.inventory()
        self.assertIn("pwn", inv)
        self.assertIn("rev", inv)
        self.assertIn("crypto", inv)
        self.assertIn("web", inv)
        self.assertIn("forensics", inv)

    def test_recommend_pipeline(self):
        pipe = self.engine.recommend_pipeline("rev")
        self.assertIsInstance(pipe, list)
        self.assertIn("strings", pipe)


class TestSpecialistAgents(unittest.TestCase):
    def test_specialists_definitions(self):
        for cat in ("pwn", "rev", "crypto", "web", "forensics", "osint"):
            spec = get_specialist(cat)
            self.assertEqual(spec.category, cat)
            prompt = spec.build_specialist_prompt(target="test.bin", briefing="Briefing text", evidence="Triage evidence")
            self.assertIn(cat.upper(), prompt)
            self.assertIn("FLAG:", prompt)


class TestSwarmBlackboard(unittest.TestCase):
    def test_blackboard_post_flag(self):
        bb = SwarmBlackboard()
        posted = bb.post_flag("flag{swarm_first}", "RevSpecialist", confidence=100)
        self.assertTrue(posted)
        self.assertEqual(bb.winning_flag, "flag{swarm_first}")
        self.assertEqual(bb.winning_specialist, "RevSpecialist")

        # Second flag does not overwrite winning flag
        posted2 = bb.post_flag("flag{swarm_second}", "PwnSpecialist", confidence=90)
        self.assertFalse(posted2)
        self.assertEqual(bb.winning_flag, "flag{swarm_first}")

    def test_blackboard_artifacts(self):
        bb = SwarmBlackboard()
        bb.post_artifact(__file__)
        self.assertIn(__file__, bb.carved_artifacts)


if __name__ == "__main__":
    unittest.main()
