"""Tests for flag submission — verdict mapping for CTFd / rCTF / generic.

Spins up a tiny local HTTP server that imitates each platform's response shape,
so the classification logic is exercised without a real scoreboard.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ctfsolver import submit  # noqa: E402

WIN = "flag{win}"


class _Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        if self.path.startswith("/api/v1/challenges/attempt"):      # CTFd
            if "Token " not in auth:
                return self._json(403, {})
            st = "correct" if body.get("submission") == WIN else "incorrect"
            return self._json(200, {"success": True, "data": {"status": st, "message": st}})
        if "/submit" in self.path:                                   # rCTF
            kind = "goodFlag" if body.get("flag") == WIN else "badFlag"
            return self._json(200, {"kind": kind, "message": kind})
        return self._json(200, {"msg": "Correct!" if body.get("flag") == WIN   # generic
                                else "incorrect, wrong"})

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_ctfd_correct_incorrect_and_auth():
    srv, url = _server()
    try:
        assert submit.submit_flag(WIN, "ctfd", url, "tok", "1")["status"] == "correct"
        assert submit.submit_flag("flag{no}", "ctfd", url, "tok", "1")["status"] == "incorrect"
        assert submit.submit_flag(WIN, "ctfd", url, "", "1")["status"] == "auth_error"
        assert submit.submit_flag(WIN, "ctfd", url, "tok", "")["status"] == "error"  # no chal id
    finally:
        srv.shutdown()


def test_rctf_good_and_bad():
    srv, url = _server()
    try:
        assert submit.submit_flag(WIN, "rctf", url, "tok", "web")["status"] == "correct"
        assert submit.submit_flag("flag{no}", "rctf", url, "tok", "web")["status"] == "incorrect"
    finally:
        srv.shutdown()


def test_generic_marker_matching():
    srv, url = _server()
    try:
        assert submit.submit_flag(WIN, "generic", url + "/x", "", "")["status"] == "correct"
        assert submit.submit_flag("flag{no}", "generic", url + "/x", "", "")["status"] == "incorrect"
    finally:
        srv.shutdown()


def test_guards():
    assert submit.submit_flag("", "ctfd", "http://x")["status"] == "error"
    assert submit.submit_flag("flag{x}", "bogus", "http://x")["status"] == "error"
    assert submit.submit_flag("flag{x}", "ctfd", "")["status"] == "error"
