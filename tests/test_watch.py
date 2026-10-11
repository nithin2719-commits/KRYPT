"""Tests for the encoded-flag sweep and the real-time WATCH engine."""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver.flags import instant_scan, scan_encoded, scan_magic  # noqa: E402
from ctfsolver.watch import FlagWatcher  # noqa: E402


class TestScanEncoded(unittest.TestCase):
    def _flags(self, res):
        return {f["flag"] for f in res}

    def test_base64_flag(self):
        blob = base64.b64encode(b"here flag{b64_hidden}").decode()
        res = scan_encoded(("noise " + blob + " noise").encode())
        self.assertIn("flag{b64_hidden}", self._flags(res))
        self.assertEqual(res[0]["kind"], "base64")
        self.assertTrue(res[0]["encoded"])

    def test_urlsafe_base64(self):
        blob = base64.urlsafe_b64encode(b"picoCTF{urlsafe}").decode()
        self.assertIn("picoCTF{urlsafe}", self._flags(scan_encoded(blob.encode())))

    def test_hex_flag(self):
        hx = b"CTF{hex_me}".hex()
        res = scan_encoded(("x " + hx + " y").encode())
        self.assertIn("CTF{hex_me}", self._flags(res))
        self.assertEqual(res[0]["kind"], "hex")

    def test_random_base64_no_false_positive(self):
        rnd = base64.b64encode(os.urandom(64)).decode()
        self.assertEqual(scan_encoded(rnd.encode()), [])

    def test_instant_scan_plaintext_and_encoded(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("plain picoCTF{plain_one}\n")
            fh.write(base64.b64encode(b"flag{encoded_one}").decode())
            path = fh.name
        try:
            flags = self._flags(instant_scan(path))
            self.assertIn("picoCTF{plain_one}", flags)
            self.assertIn("flag{encoded_one}", flags)
        finally:
            os.unlink(path)


class TestScanMagic(unittest.TestCase):
    def _flags(self, res):
        return {f["flag"] for f in res}

    def test_chained_base64(self):
        # base64(base64(flag)) — the single-level sweep can't reach this
        inner = base64.b64encode(b"flag{double_wrapped}")
        blob = base64.b64encode(inner).decode()
        res = scan_magic(blob.encode())
        self.assertIn("flag{double_wrapped}", self._flags(res))
        self.assertTrue(res[0]["encoded"])

    def test_rot13_whole_file(self):
        rot = "".join(
            chr((ord(c) - 97 + 13) % 26 + 97) if "a" <= c <= "z" else
            chr((ord(c) - 65 + 13) % 26 + 65) if "A" <= c <= "Z" else c
            for c in "flag{rot_thirteen}")
        self.assertIn("flag{rot_thirteen}", self._flags(scan_magic(rot.encode())))

    def test_base32(self):
        blob = base64.b32encode(b"CTF{base32_me}")
        self.assertIn("CTF{base32_me}", self._flags(scan_magic(blob)))

    def test_reversed_flag(self):
        self.assertIn("flag{backwards}",
                      self._flags(scan_magic(b"flag{backwards}"[::-1])))

    def test_no_false_positive_on_prose(self):
        self.assertEqual(scan_magic(b"just some ordinary english text here"), [])

    def test_binary_input_skipped_fast(self):
        self.assertEqual(scan_magic(os.urandom(4096)), [])

    def test_instant_scan_catches_chained(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(base64.b64encode(base64.b64encode(b"flag{layered}")).decode())
            path = fh.name
        try:
            self.assertIn("flag{layered}", self._flags(instant_scan(path)))
        finally:
            os.unlink(path)


class TestFlagWatcher(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="krypt-watch-")
        self.finds = []
        self.w = FlagWatcher([self.d], interval=0.2, on_find=self.finds.append,
                             logdir=os.path.join(self.d, ".klog"))

    def _settle_scan(self):
        # first poll records size, second (stable) poll scans
        self.w.poll_once()
        self.w.poll_once()

    def test_detects_plaintext(self):
        with open(os.path.join(self.d, "a.txt"), "w") as fh:
            fh.write("the flag is picoCTF{watched}\n")
        self._settle_scan()
        flags = [f["flag"] for r in self.finds for f in r["flags"]]
        self.assertIn("picoCTF{watched}", flags)

    def test_detects_base64(self):
        with open(os.path.join(self.d, "b.b64"), "w") as fh:
            fh.write(base64.b64encode(b"flag{watched_b64}").decode())
        self._settle_scan()
        flags = [f["flag"] for r in self.finds for f in r["flags"]]
        self.assertIn("flag{watched_b64}", flags)

    def test_content_dedup(self):
        for name in ("one.txt", "two.txt"):
            with open(os.path.join(self.d, name), "w") as fh:
                fh.write("same picoCTF{dup}\n")
        for _ in range(4):
            self.w.poll_once()
        # identical content -> reported once despite two files
        self.assertEqual(len(self.finds), 1)

    def test_never_scans_own_log(self):
        with open(os.path.join(self.d, "c.txt"), "w") as fh:
            fh.write("picoCTF{loop_guard}\n")
        for _ in range(6):   # extra polls would re-detect a scanned log file
            self.w.poll_once()
        self.assertEqual(len(self.finds), 1)
        self.assertTrue(os.path.exists(self.w.logpath))


if __name__ == "__main__":
    unittest.main()
