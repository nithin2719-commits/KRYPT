"""Unit tests for ZIP forensics and pseudo-encryption bypass solver."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
import zipfile
import zlib

from ctfsolver.solvers import zip_forensics


class TestZipForensics(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_crc32_small_file_recovery(self):
        secret = b"FLAG"
        crc = zlib.crc32(secret) & 0xFFFFFFFF
        recovered = zip_forensics.crc32_brute_small_file(crc, max_len=4)
        self.assertEqual(recovered, secret)

    def test_zip_archive_comment_extraction(self):
        zip_path = os.path.join(self.tmp_dir, "comment_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.txt", "hello world")
            zf.comment = b"flag{zip_archive_comment_recovered}"

        res = zip_forensics.solve(zip_path, self.tmp_dir)
        flag_strs = [f["flag"] for f in res.get("flags", [])]
        self.assertIn("flag{zip_archive_comment_recovered}", flag_strs)

    def test_pseudo_encryption_bypass(self):
        # Create a valid zip with uncompressed/compressed file
        zip_path = os.path.join(self.tmp_dir, "normal.zip")
        flag_secret = "flag{zip_pseudo_encryption_bypassed}"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("secret.txt", flag_secret)

        with open(zip_path, "rb") as f:
            data = bytearray(f.read())

        # Corrupt the ZIP by setting the encryption bit in Central Directory (ZipCenOp trick)
        cd_sig = b"PK\x01\x02"
        pos = data.find(cd_sig)
        self.assertNotEqual(pos, -1)
        # Byte 8-9 in PK\x01\x02 is gp_flag
        gp_flag = struct.unpack("<H", data[pos + 8 : pos + 10])[0]
        data[pos + 8 : pos + 10] = struct.pack("<H", gp_flag | 0x0001)

        corrupted_zip = os.path.join(self.tmp_dir, "fake_encrypted.zip")
        with open(corrupted_zip, "wb") as f:
            f.write(data)

        # Standard python zipfile should fail to extract or complain about password
        # Our solver should fix the pseudo-encryption and recover the flag!
        res = zip_forensics.solve(corrupted_zip, self.tmp_dir)
        flag_strs = [f["flag"] for f in res.get("flags", [])]
        self.assertIn(flag_secret, flag_strs)


if __name__ == "__main__":
    unittest.main()
