"""Tests for the KRYPT Active CTF Worker engine."""
import base64
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.scoreboard import Scoreboard
from ctfsolver.worker import CTFTask, CTFWorker


class TestCTFTask(unittest.TestCase):
    def test_task_serialization(self):
        t = CTFTask(
            target="/tmp/test.bin",
            name="TestChall",
            category="rev",
            briefing="Reverse this binary",
            points=150,
            challenge_id="42",
            event="testctf",
            flag_format=r"flag\{[a-z0-9_]+\}",
        )
        d = t.to_dict()
        self.assertEqual(d["name"], "TestChall")
        self.assertEqual(d["category"], "rev")
        self.assertEqual(d["points"], 150)
        self.assertEqual(d["challenge_id"], "42")
        self.assertEqual(d["status"], "pending")

        t2 = CTFTask.from_dict(d)
        self.assertEqual(t2.id, t.id)
        self.assertEqual(t2.name, t.name)
        self.assertEqual(t2.points, 150)


class TestCTFWorker(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.inbox_dir = os.path.join(self.tmp_dir, "inbox")
        os.makedirs(self.inbox_dir, exist_ok=True)
        self.mock_sb = MagicMock(spec=Scoreboard)
        self.mock_sb.url = "https://mock.ctf"
        self.mock_sb.platform = "ctfd"

        self.worker = CTFWorker(
            event="test_event",
            inbox_dirs=[self.inbox_dir],
            scoreboard=self.mock_sb,
            auto_submit=True,
            escalate_engine="none",  # keep tests offline and fast
            workdir=self.tmp_dir,
        )

    def tearDown(self):
        self.worker.stop()
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_enqueue_and_queue_management(self):
        self.worker.clear_queue()
        t1 = self.worker.enqueue(target="/tmp/a.txt", name="ChallA", category="crypto", points=50)
        t2 = self.worker.enqueue(target="/tmp/b.txt", name="ChallB", category="pwn", points=100)

        q = self.worker.get_queue()
        self.assertEqual(len(q), 2)
        self.assertEqual(q[0]["name"], "ChallA")
        self.assertEqual(q[1]["name"], "ChallB")

        self.worker.clear_queue()
        self.assertEqual(len(self.worker.get_queue()), 0)

    def test_flag_filtering(self):
        flags = [
            {"flag": "flag{password}"},  # placeholder
            {"flag": "flag{test_dummy}"},
            {"flag": "picoCTF{valid_flag_123}"},
            {"flag": "flag{real_solution_here}"},
        ]
        filtered = self.worker._validate_and_filter_flags(flags, flag_format=r"picoCTF\{[^}]+\}")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["flag"], "picoCTF{valid_flag_123}")

    def test_solve_task_with_instant_decode(self):
        # Create a challenge file containing a base64 encoded flag
        chall_file = os.path.join(self.tmp_dir, "chall.txt")
        b64_flag = base64.b64encode(b"flag{worker_instant_win_99}").decode()
        with open(chall_file, "w") as fh:
            fh.write(f"Decode this: {b64_flag}\n")

        self.mock_sb.submit_flag.return_value = {
            "status": "correct",
            "message": "Flag accepted!",
        }

        task = self.worker.enqueue(
            target=chall_file,
            name="Base64Chall",
            category="crypto",
            points=100,
            challenge_id="101",
        )

        solved = self.worker.process_task(task)
        self.assertTrue(solved)
        self.assertEqual(task.status, "solved")
        self.assertEqual(task.solved_flag, "flag{worker_instant_win_99}")
        self.assertEqual(self.worker.solves_count, 1)
        self.assertEqual(self.worker.total_points, 100)

        # Verify auto-submit was called
        self.mock_sb.submit_flag.assert_called_once_with("flag{worker_instant_win_99}", "101")

    def test_sync_scoreboard(self):
        self.mock_sb.fetch_challenges.return_value = [
            {"id": "1", "name": "Web1", "category": "web", "value": 50, "solved": False, "description": "Web task"},
            {"id": "2", "name": "Rev1", "category": "rev", "value": 150, "solved": True, "description": "Rev task"},
        ]
        self.mock_sb.fetch_challenge_detail.return_value = {
            "id": "1",
            "description": "SQL injection web task",
            "connection_info": "http://10.10.10.5:8000",
            "files": [],
        }

        self.worker.clear_queue()
        res = self.worker.sync_scoreboard()
        self.assertTrue(res["ok"])
        self.assertEqual(res["enqueued"], 1)
        self.assertEqual(res["already_solved"], 1)

        q = self.worker.get_queue()
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0]["name"], "Web1")
        self.assertEqual(q[0]["points"], 50)
        self.assertEqual(q[0]["challenge_id"], "1")


if __name__ == "__main__":
    unittest.main()
