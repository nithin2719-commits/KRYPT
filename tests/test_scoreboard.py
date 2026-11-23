"""Tests for CTFd, rCTF, and generic scoreboard API integration."""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.scoreboard import (
    Scoreboard,
    get_scoreboard_config,
    save_scoreboard_config,
)


class TestScoreboardConfig(unittest.TestCase):
    def test_save_and_get_config(self):
        with patch("ctfsolver.scoreboard._read_cfg", return_value={}), \
             patch("ctfsolver.scoreboard._write_cfg") as mock_write:
            save_scoreboard_config(
                platform="ctfd",
                url="https://ctf.example.com",
                token="test_token_123",
                challenge_id="42",
                field="flag",
                auto_submit=True,
            )
            mock_write.assert_called_once()
            cfg_written = mock_write.call_args[0][0]
            self.assertEqual(cfg_written["scoreboard"]["platform"], "ctfd")
            self.assertEqual(cfg_written["scoreboard"]["url"], "https://ctf.example.com")
            self.assertEqual(cfg_written["scoreboard"]["token"], "test_token_123")
            self.assertTrue(cfg_written["scoreboard"]["auto_submit"])


class TestScoreboardCTFd(unittest.TestCase):
    def setUp(self):
        self.sb = Scoreboard(url="https://ctf.test", token="sec_tok", platform="ctfd")

    @patch("ctfsolver.scoreboard._http_request")
    def test_ctfd_connection_success(self, mock_http):
        mock_http.return_value = (200, {
            "success": True,
            "data": {
                "name": "hacker1337",
                "email": "hacker@test.com",
                "score": 500,
                "place": 3,
            }
        })
        res = self.sb.test_connection()
        self.assertTrue(res["ok"])
        self.assertEqual(res["user"], "hacker1337")
        self.assertEqual(res["score"], 500)

    @patch("ctfsolver.scoreboard._http_request")
    def test_ctfd_fetch_challenges(self, mock_http):
        mock_http.return_value = (200, {
            "success": True,
            "data": [
                {"id": 1, "name": "Crypto1", "category": "Crypto", "value": 100, "solves": 12, "solved_by_me": False},
                {"id": 2, "name": "Rev1", "category": "Rev", "value": 200, "solves": 4, "solved_by_me": True},
            ]
        })
        challs = self.sb.fetch_challenges()
        self.assertEqual(len(challs), 2)
        self.assertEqual(challs[0]["name"], "Crypto1")
        self.assertEqual(challs[0]["category"], "crypto")
        self.assertFalse(challs[0]["solved"])
        self.assertTrue(challs[1]["solved"])

    @patch("ctfsolver.scoreboard._http_request")
    def test_ctfd_submit_flag_correct(self, mock_http):
        mock_http.return_value = (200, {
            "success": True,
            "data": {"status": "correct", "message": "Flag is correct!"}
        })
        res = self.sb.submit_flag("flag{win}", challenge_id="1")
        self.assertEqual(res["status"], "correct")
        self.assertIn("correct", res["message"].lower())

    @patch("ctfsolver.scoreboard._http_request")
    def test_ctfd_submit_flag_already_solved(self, mock_http):
        mock_http.return_value = (200, {
            "success": True,
            "data": {"status": "already_solved", "message": "You already solved this!"}
        })
        res = self.sb.submit_flag("flag{win}", challenge_id="1")
        self.assertEqual(res["status"], "already_solved")

    @patch("ctfsolver.scoreboard._http_request")
    def test_ctfd_submit_flag_incorrect(self, mock_http):
        mock_http.return_value = (200, {
            "success": True,
            "data": {"status": "incorrect", "message": "Incorrect flag."}
        })
        res = self.sb.submit_flag("flag{bad}", challenge_id="1")
        self.assertEqual(res["status"], "incorrect")


class TestScoreboardRCTF(unittest.TestCase):
    def setUp(self):
        self.sb = Scoreboard(url="https://rctf.test", token="r_token", platform="rctf")

    @patch("ctfsolver.scoreboard._http_request")
    def test_rctf_submit_good_flag(self, mock_http):
        mock_http.return_value = (200, {
            "kind": "goodFlag",
            "message": "The flag is correct!"
        })
        res = self.sb.submit_flag("flag{rctf_correct}", challenge_id="chall-slug")
        self.assertEqual(res["status"], "correct")


class TestScoreboardGeneric(unittest.TestCase):
    def setUp(self):
        self.sb = Scoreboard(url="https://generic.test/submit", platform="generic", field="answer")

    @patch("ctfsolver.scoreboard._http_request")
    def test_generic_submit_success(self, mock_http):
        mock_http.return_value = (200, "Congratulations! Your flag was correct.")
        res = self.sb.submit_flag("flag{gen_win}")
        self.assertEqual(res["status"], "correct")


if __name__ == "__main__":
    unittest.main()
