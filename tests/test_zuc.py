"""ZUC 序列密码测试（GM/T 0001.1-2021 测试向量）。"""
from __future__ import annotations

import unittest

from cryptotoolbox.core import zuc


class ZucTests(unittest.TestCase):
    def test_first_word_zero_key_iv(self):
        ks = zuc.keystream(bytes(16), bytes(16), 4)
        self.assertEqual(ks.hex().upper(), "27BEDE74")

    def test_known_keystream_prefix(self):
        # GM/T 0001.1-2021 附录 A：全零密钥/IV 的首个密钥流字为 27BEDE74
        ks = zuc.keystream(bytes(16), bytes(16), 4)
        self.assertEqual(ks.hex().upper(), "27BEDE74")
        # 后续密钥流字由 gmalg 生成；此处仅校验长度与可重复性
        self.assertEqual(len(zuc.keystream(bytes(16), bytes(16), 16)), 16)
        self.assertEqual(zuc.keystream(bytes(16), bytes(16), 16), zuc.keystream(bytes(16), bytes(16), 16))

    def test_crypt_roundtrip(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        data = b"ZUC stream cipher test data"
        ct = zuc.crypt(key, iv, data)
        self.assertNotEqual(ct, data)
        self.assertEqual(zuc.crypt(key, iv, ct), data)

    def test_invalid_lengths(self):
        with self.assertRaises(zuc.ZucError):
            zuc.keystream(bytes(15), bytes(16), 4)
        with self.assertRaises(zuc.ZucError):
            zuc.keystream(bytes(16), bytes(15), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
