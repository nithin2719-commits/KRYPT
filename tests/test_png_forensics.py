"""Unit tests for PNG forensics solver."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
import zlib

from ctfsolver.solvers import png_forensics


class TestPngForensics(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_parse_chunks(self):
        ihdr = struct.pack(">IIBBBBB", 10, 20, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF
        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13) + b"IHDR" + ihdr + struct.pack(">I", ihdr_crc)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        )
        chunks = png_forensics.parse_chunks(png)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0]["type"], "IHDR")
        self.assertTrue(chunks[0]["crc_valid"])
        self.assertEqual(chunks[1]["type"], "IEND")
        self.assertTrue(chunks[1]["crc_valid"])

    def test_extract_text_chunks(self):
        # tEXt
        txt_data = b"Comment\x00flag{text_chunk_flag}"
        tcrc = zlib.crc32(b"tEXt" + txt_data) & 0xFFFFFFFF
        # zTXt
        ztxt_data = b"Author\x00\x00" + zlib.compress(b"flag{ztxt_chunk_flag}")
        zcrc = zlib.crc32(b"zTXt" + ztxt_data) & 0xFFFFFFFF
        # iTXt
        itxt_data = b"Desc\x00\x01\x00\x00\x00" + zlib.compress(b"flag{itxt_chunk_flag}")
        icrc = zlib.crc32(b"iTXt" + itxt_data) & 0xFFFFFFFF

        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", len(txt_data)) + b"tEXt" + txt_data + struct.pack(">I", tcrc)
            + struct.pack(">I", len(ztxt_data)) + b"zTXt" + ztxt_data + struct.pack(">I", zcrc)
            + struct.pack(">I", len(itxt_data)) + b"iTXt" + itxt_data + struct.pack(">I", icrc)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        )
        entries = png_forensics.extract_text_chunks(png)
        found_flags = [f["flag"] for e in entries for f in e["flags"]]
        self.assertIn("flag{text_chunk_flag}", found_flags)
        self.assertIn("flag{ztxt_chunk_flag}", found_flags)
        self.assertIn("flag{itxt_chunk_flag}", found_flags)

    def test_check_ihdr_and_crc_recovery(self):
        orig_w, orig_h = 150, 300
        ihdr_orig = struct.pack(">IIBBBBB", orig_w, orig_h, 8, 2, 0, 0, 0)
        orig_crc = zlib.crc32(b"IHDR" + ihdr_orig) & 0xFFFFFFFF

        # Tampered height in file (e.g. 50 instead of 300) with untouched original CRC
        ihdr_tampered = struct.pack(">IIBBBBB", orig_w, 50, 8, 2, 0, 0, 0)
        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13) + b"IHDR" + ihdr_tampered + struct.pack(">I", orig_crc)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        )

        res = png_forensics.check_ihdr(png)
        self.assertFalse(res["crc_valid"])
        self.assertEqual(res["crc_recovered_height"], 300)
        self.assertEqual(res["suggested_height"], 300)

        # Fix height
        fixed = png_forensics.fix_ihdr_height(png, 300)
        fixed_res = png_forensics.check_ihdr(fixed)
        self.assertTrue(fixed_res["crc_valid"])
        self.assertEqual(fixed_res["height"], 300)

    def test_check_ihdr_trailing_idat_and_brute(self):
        # 8x12 RGB: 12 rows of (1 + 8*3) = 25 bytes per row -> 300 bytes total
        w, true_h = 8, 12
        raw_scanlines = b"".join(b"\x00" + (b"\x10\x20\x30" * w) for _ in range(true_h))
        idat_comp = zlib.compress(raw_scanlines)
        idat_crc = zlib.crc32(b"IDAT" + idat_comp) & 0xFFFFFFFF

        # Tamper height to 4 and recompute CRC
        ihdr_tampered = struct.pack(">IIBBBBB", w, 4, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_tampered) & 0xFFFFFFFF

        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13) + b"IHDR" + ihdr_tampered + struct.pack(">I", ihdr_crc)
            + struct.pack(">I", len(idat_comp)) + b"IDAT" + idat_comp + struct.pack(">I", idat_crc)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        )

        ihdr_res = png_forensics.check_ihdr(png)
        self.assertTrue(ihdr_res["has_trailing_idat"])
        self.assertEqual(ihdr_res["calculated_height"], 12)
        self.assertEqual(ihdr_res["suggested_height"], 12)

        brute_res = png_forensics.brute_ihdr_dimensions(png, self.tmp_dir)
        pairs = [(b["width"], b["height"]) for b in brute_res]
        self.assertIn((8, 12), pairs)

    def test_extract_trailing_data(self):
        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
            + b"flag{appended_overlay_data}"
        )
        trailing = png_forensics.extract_trailing_data(png)
        self.assertEqual(trailing, b"flag{appended_overlay_data}")

    def test_check_palette_stego(self):
        secret = b"flag{palette_stego_flag}"
        plte_data = secret + b"\x00" * ((3 - len(secret) % 3) % 3)
        plte_crc = zlib.crc32(b"PLTE" + plte_data) & 0xFFFFFFFF
        ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 3, 0, 0, 0)

        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF)
            + struct.pack(">I", len(plte_data)) + b"PLTE" + plte_data + struct.pack(">I", plte_crc)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        )
        msgs = png_forensics.check_palette_stego(png)
        self.assertTrue(any("flag{palette_stego_flag}" in m for m in msgs))

    def test_detect_lsb_indicator(self):
        msg = b"flag{lsb_embedded_flag}\x00"
        bits = []
        for byte in msg:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        raw = bytearray(b"\x80" * 300)
        for idx, bit in enumerate(bits):
            raw[idx] = (raw[idx] & 0xFE) | bit

        row = b"\x00" + bytes(raw)
        idat = zlib.compress(row)
        ihdr = struct.pack(">IIBBBBB", 100, 1, 8, 2, 0, 0, 0)
        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF)
            + struct.pack(">I", len(idat)) + b"IDAT" + idat + struct.pack(">I", zlib.crc32(b"IDAT" + idat) & 0xFFFFFFFF)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        )

        res = png_forensics.detect_lsb_indicator(png)
        self.assertTrue(res["detected"])
        flags = [f["flag"] for f in res["flags"]]
        self.assertIn("flag{lsb_embedded_flag}", flags)

    def test_solve_end_to_end(self):
        # Image with text chunk, trailing data, and LSB flag
        msg = b"flag{lsb_full_solve}\x00"
        bits = []
        for b in msg:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)

        raw = bytearray(b"\x90" * 300)
        for idx, bit in enumerate(bits):
            raw[idx] = (raw[idx] & 0xFE) | bit

        row = b"\x00" + bytes(raw)
        idat = zlib.compress(row)
        ihdr = struct.pack(">IIBBBBB", 100, 1, 8, 2, 0, 0, 0)
        txt = b"Comment\x00flag{text_full_solve}"

        png = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF)
            + struct.pack(">I", len(txt)) + b"tEXt" + txt + struct.pack(">I", zlib.crc32(b"tEXt" + txt) & 0xFFFFFFFF)
            + struct.pack(">I", len(idat)) + b"IDAT" + idat + struct.pack(">I", zlib.crc32(b"IDAT" + idat) & 0xFFFFFFFF)
            + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
            + b"flag{tail_full_solve}"
        )

        target_file = os.path.join(self.tmp_dir, "test.png")
        with open(target_file, "wb") as f:
            f.write(png)

        res = png_forensics.solve(target_file, self.tmp_dir)
        self.assertEqual(res["step"], "png-forensics")
        found = [f["flag"] for f in res["flags"]]
        self.assertIn("flag{text_full_solve}", found)
        self.assertIn("flag{lsb_full_solve}", found)
        self.assertIn("flag{tail_full_solve}", found)
        self.assertTrue(len(res["artifacts"]) > 0)
