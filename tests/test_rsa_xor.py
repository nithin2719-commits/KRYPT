"""Unit tests for pure-Python RSA and XOR solver suites."""
from __future__ import annotations

import os
import tempfile
import unittest

import gmpy2
from ctfsolver.solvers import rsa_attacks, xor_solver


class TestRsaAndXorSolvers(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_xor_single_byte(self):
        msg = b"flag{single_byte_xor_victory}"
        key = 0x5a
        ct = bytes([b ^ key for b in msg])
        cands = xor_solver.single_byte_xor(ct)
        self.assertTrue(len(cands) > 0)
        self.assertEqual(cands[0]["key"], key)
        self.assertEqual(cands[0]["plaintext"], msg.decode())

    def test_xor_repeating_key(self):
        msg = b"The quick brown fox jumps over the lazy dog and this is a longer English text that should easily be decrypted by repeating key xor cryptanalysis in pure python!"
        key = b"KEY"
        ct = xor_solver.xor_with_key(msg, key)
        cands = xor_solver.repeating_key_xor(ct, max_keylen=10)
        self.assertTrue(len(cands) > 0)
        top_pt = cands[0]["plaintext"]
        self.assertIn("The quick brown fox", top_pt)

    def test_xor_known_plaintext(self):
        msg = b"flag{known_plaintext_crib_works}"
        key = b"SECRET"
        ct = xor_solver.xor_with_key(msg, key)
        rec_key = xor_solver.known_plaintext_xor(ct, b"flag{known_plaintext")
        self.assertEqual(rec_key, key)

    def test_xor_solver_solve_file(self):
        msg = b"flag{xor_file_solved_automagically}"
        key = 0x37
        ct = bytes([b ^ key for b in msg])
        path = os.path.join(self.tmp_dir, "test.xor")
        with open(path, "wb") as f:
            f.write(ct)
        res = xor_solver.solve(path, self.tmp_dir)
        flag_strs = [f["flag"] for f in res.get("flags", [])]
        self.assertIn("flag{xor_file_solved_automagically}", flag_strs)

    def test_rsa_small_e(self):
        m = int.from_bytes(b"flag{rsa_small_exponent}", "big")
        e = 3
        n = 10**100
        c = pow(m, e, n)
        res = rsa_attacks.small_exponent_attack(c, e, n)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("plaintext"), b"flag{rsa_small_exponent}")

    def test_rsa_wiener(self):
        p = int(gmpy2.next_prime(612852475143))
        q = int(gmpy2.next_prime(655864707949))
        n = p * q
        phi = (p - 1) * (q - 1)
        d = 1021
        e = pow(d, -1, phi)
        m = 133742
        c = pow(m, e, n)
        res = rsa_attacks.wiener_attack(e, n, c)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("m"), m)

    def test_rsa_fermat(self):
        p = 10000000000000000051
        q = 10000000000000000069
        n = p * q
        res = rsa_attacks.fermat_factorization(n)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("p") * res.get("q"), n)

    def test_rsa_pollard_p_minus_1(self):
        p = 2521  # 2520 = 2^3 * 3^2 * 5 * 7
        q = 7919
        n = p * q
        res = rsa_attacks.pollard_p_minus_1(n, b1=100)
        self.assertTrue(res.get("success"))
        self.assertIn(res.get("p"), (p, q))

    def test_rsa_solve_file(self):
        p = int(gmpy2.next_prime(10**35))
        q = int(gmpy2.next_prime(p))
        n = p * q
        e = 65537
        m = int.from_bytes(b"flag{rsa_fermat_auto_win}", "big")
        c = pow(m, e, n)
        path = os.path.join(self.tmp_dir, "rsa_chal.txt")
        with open(path, "w") as f:
            f.write(f"n = {n}\ne = {e}\nc = {c}\n")
        res = rsa_attacks.solve(path, self.tmp_dir)
        flag_strs = [f["flag"] for f in res.get("flags", [])]
        self.assertIn("flag{rsa_fermat_auto_win}", flag_strs)


if __name__ == "__main__":
    unittest.main()
