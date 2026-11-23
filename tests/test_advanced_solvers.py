"""Unit tests for advanced CTF solvers: Z3, QR/Visual, Audio, JWT/Web, and PCAP."""
import os
import tempfile
import unittest
import wave

from ctfsolver.solvers import z3_solve, jwt_web, audio_deep, pcap_deep, qr_visual


class TestAdvancedSolvers(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_z3_linear_equations_solve(self):
        eqs = [
            "flag[0] ^ 0x5a == 0x3c",
            "flag[1] + 15 == 123",
            "flag[2] == 0x41",
            "flag[3] - 5 == 115",
        ]
        res = z3_solve.parse_and_solve(eqs)
        self.assertTrue(res.get("solved"))
        self.assertIn("flag{", res.get("flag", ""))
        self.assertEqual(res.get("raw")[:4], "flAx")

    def test_z3_scan_and_solve_from_text(self):
        code_block = """
        if (input[0] ^ 0x33 == 0x57) {
            if (input[1] + 10 == 85) {
                if (input[2] == 0x41) {
                    puts("Correct!");
                }
            }
        }
        """
        res = z3_solve.scan_and_solve(code_block)
        self.assertTrue(res.get("solved"))
        self.assertIn("flag{", res.get("flag", ""))

    def test_jwt_forge_none_and_crack_secret(self):
        # Create HS256 token with secret 'secret'
        token = jwt_web.forge_jwt_hmac("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiaGFja2VyIn0.c2ln", "secret")
        self.assertTrue(token.startswith("eyJ"))

        # Test secret cracking
        cracked = jwt_web.crack_jwt_secret(token)
        self.assertEqual(cracked, "secret")

        # Test alg:none forge
        none_tokens = jwt_web.forge_jwt_none(token)
        self.assertTrue(len(none_tokens) > 0)
        self.assertIn("eyJhbGciOiJub25lIn0", none_tokens[0])

        # Test attack_jwt claim sweep
        attack = jwt_web.attack_jwt(token)
        self.assertEqual(attack.get("step"), "jwt-exploit")

    def test_audio_deep_lsb_extraction(self):
        # Generate a small test WAV file with LSB embedded message
        wav_path = os.path.join(self.tmp_dir, "test_stego.wav")
        secret_bytes = b"flag{audio_lsb_win}\x00"

        # Expand secret_bytes to bit array
        secret_bits = []
        for b in secret_bytes:
            for i in range(7, -1, -1):
                secret_bits.append((b >> i) & 1)

        # Pad with dummy bits
        while len(secret_bits) < 200:
            secret_bits.append(0)

        # Generate 16-bit PCM samples with LSB matching secret_bits
        with wave.open(wav_path, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(8000)
            sample_frames = bytearray()
            for bit in secret_bits:
                val = (1000 & ~1) | bit
                sample_frames.extend(val.to_bytes(2, byteorder="little", signed=True))
            wf.writeframes(bytes(sample_frames))

        res = audio_deep.solve(wav_path, self.tmp_dir)
        self.assertEqual(res.get("step"), "audio-deep")
        flag_strs = [f["flag"] for f in res.get("flags", [])]
        self.assertIn("flag{audio_lsb_win}", flag_strs)

    def test_qr_visual_clean_fallback(self):
        # Test on dummy non-image file returns empty flags gracefully
        dummy_txt = os.path.join(self.tmp_dir, "not_image.png")
        with open(dummy_txt, "w") as fh:
            fh.write("not an image")
        res = qr_visual.solve(dummy_txt, self.tmp_dir)
        self.assertEqual(res.get("step"), "visual-stego-qr")
        self.assertEqual(res.get("flags"), [])

    def test_pcap_deep_clean_fallback(self):
        # Test on non-pcap file returns empty without throwing exception
        dummy_pcap = os.path.join(self.tmp_dir, "empty.pcap")
        with open(dummy_pcap, "w") as fh:
            fh.write("dummy pcap")
        res = pcap_deep.solve(dummy_pcap, self.tmp_dir)
        self.assertEqual(res.get("step"), "pcap-deep")

    def test_esoteric_ciphers(self):
        from ctfsolver.solvers import esoteric_ciphers
        # Test T9
        self.assertEqual(esoteric_ciphers.decode_t9("333 555 2 4"), "FLAG")
        # Test NATO
        self.assertEqual(esoteric_ciphers.decode_nato("Foxtrot Lima Alfa Golf"), "FLAG")
        # Test Polybius
        self.assertEqual(esoteric_ciphers.decode_polybius("21 31 11 22"), "FLAG")
        # Test Rail fence
        rf_plain = "FLAG{RAIL_FENCE_WIN}"
        # depth 3
        rf_cipher = esoteric_ciphers.decode_rail_fence(rf_plain, 3)
        # Should solve via solve()
        res = esoteric_ciphers.solve("Foxtrot Lima Alfa Golf { T9 }")
        self.assertTrue(len(res) > 0)

    def test_web_arsenal(self):
        from ctfsolver.solvers import web_arsenal
        pin = web_arsenal.calculate_werkzeug_pin("app", node="02:42:ac:11:00:02", machine_id="3fa85f64")
        self.assertRegex(pin, r"^\d{3}-\d{3}-\d{3}$")
        self.assertTrue(len(web_arsenal.PHP_MAGIC_HASHES["md5"]) > 0)

    def test_volatility_memory_detection(self):
        from ctfsolver.solvers import volatility_solve
        self.assertTrue(volatility_solve.is_memory_dump("dump.raw"))
        self.assertTrue(volatility_solve.is_memory_dump("test.vmem"))
        self.assertFalse(volatility_solve.is_memory_dump("chal.txt"))

    def test_bin_patch_fallback(self):
        from ctfsolver.solvers import bin_patch
        # Non-ELF text file should report failure gracefully
        dummy_f = os.path.join(self.tmp_dir, "test.elf")
        with open(dummy_f, "w") as fh:
            fh.write("not an elf")
        res = bin_patch.patch_anti_debug(dummy_f, self.tmp_dir)
        self.assertFalse(res.get("patched"))

    def test_doc_carve_office(self):
        from ctfsolver.solvers import doc_carve
        import zipfile
        # Create dummy docx with hidden XML comment
        docx_path = os.path.join(self.tmp_dir, "test.docx")
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("word/document.xml", "<xml><!-- flag{xml_office_comment} --></xml>")
        res = doc_carve.solve(docx_path, self.tmp_dir)
        self.assertEqual(res.get("step"), "doc-carve-office")
        flag_strs = [f["flag"] for f in res.get("flags", [])]
        self.assertIn("flag{xml_office_comment}", flag_strs)

    def test_sage_crypto_common_modulus(self):
        from ctfsolver.solvers import sage_crypto
        p, q = 1000000007, 1000000009
        n = p * q
        e1, e2 = 17, 65537
        m = 133742
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)
        res = sage_crypto.common_modulus_attack(n, e1, e2, c1, c2)
        self.assertEqual(res, m)

    def test_payload_forge_pickle_and_jinja(self):
        from ctfsolver.solvers import payload_forge
        pickle_p = payload_forge.generate_pickle_payload("cat /flag", encode_b64=True)
        self.assertTrue(len(pickle_p) > 20)
        jinja_p = payload_forge.generate_jinja2_ssti_escapes("cat /flag")
        self.assertTrue(len(jinja_p) >= 3)
        self.assertIn("lipsum", [j["payload"] for j in jinja_p if "lipsum" in j["payload"]][0])

    def test_sidechannel_fallback(self):
        from ctfsolver.solvers import sidechannel_solve
        res = sidechannel_solve.solve("/nonexistent/binary", self.tmp_dir)
        self.assertEqual(res.get("step"), "sidechannel-crackme")
        self.assertFalse(res.get("flags"))

    def test_god_solver_instant_and_fallback(self):
        from ctfsolver import god
        # Test 1: Instant flag in briefing
        res = god.solve(briefing="Here is your token: flag{god_apex_tier_solve}", event="test-god")
        self.assertTrue(res.get("solved"))
        self.assertEqual(res.get("flag"), "flag{god_apex_tier_solve}")
        self.assertEqual(res.get("engine"), "tier1_magic")

        # Test 2: Target without flag reaches fallback gracefully without crash
        dummy_f = os.path.join(self.tmp_dir, "empty.txt")
        with open(dummy_f, "w") as fh:
            fh.write("just simple text without flags")
        res2 = god.solve(target=dummy_f, briefing="nothing here", event="test-god", timeout=0)
        self.assertFalse(res2.get("solved"))
        self.assertEqual(res2.get("flag"), "")
        self.assertIn("tier1_magic", res2.get("phases_run", []))


if __name__ == "__main__":
    unittest.main()

