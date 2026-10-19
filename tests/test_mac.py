"""MAC 测试：NIST SP 800-38B CMAC 向量与 CBC-MAC 向量。"""
from __future__ import annotations

import unittest

from cryptotoolbox.core import mac


class CmacTests(unittest.TestCase):
    # NIST SP 800-38B 示例（AES-128，密钥 2b7e1516...）
    KEY = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")

    def test_empty_message(self):
        self.assertEqual(mac.cmac("AES-128", self.KEY, b"").hex().upper(),
                         "BB1D6929E95937287FA37D129B756746")

    def test_one_block_message(self):
        data = bytes.fromhex("6BC1BEE22E409F96E93D7E117393172A")
        self.assertEqual(mac.cmac("AES-128", self.KEY, data).hex().upper(),
                         "070A16B46B4D4144F79BDD9DD04A287C")

    def test_partial_block_message(self):
        # NIST SP 800-38B 示例 3：Mlen=320
        data = bytes.fromhex(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
            "30C81C46A35CE411"
        )
        self.assertEqual(mac.cmac("AES-128", self.KEY, data).hex().upper(),
                         "DFA66747DE9AE63030CA32611497C827")

    def test_multiblock_message(self):
        data = bytes.fromhex(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
            "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710"
        )
        self.assertEqual(mac.cmac("AES-128", self.KEY, data).hex().upper(),
                         "51F0BEBF7E3B9D92FC49741779363CFE")

    def test_sm4_cmac_consistency(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        data = b"SM4 CMAC test payload"
        tag1 = mac.cmac("SM4", key, data)
        tag2 = mac.cmac("SM4", key, data)
        self.assertEqual(tag1, tag2)
        self.assertEqual(len(tag1), 16)
        self.assertNotEqual(tag1, mac.cmac("SM4", key, data + b"x"))


class CbcMacTests(unittest.TestCase):
    def test_cbc_mac_one_block(self):
        # CBC 第一块的密文即单块 CBC-MAC（NIST SP 800-38A F.2.1）
        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        data = bytes.fromhex("6BC1BEE22E409F96E93D7E117393172A")
        self.assertEqual(mac.cbc_mac("AES-128", key, data).hex().upper(),
                         "3AD77BB40D7A3660A89ECAF32466EF97")

    def test_cbc_mac_sm4(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        tag = mac.cbc_mac("SM4", key, b"CBC-MAC SM4 test")
        self.assertEqual(len(tag), 16)

    def test_unsupported_mode(self):
        with self.assertRaises(mac.MacError):
            mac.compute("LMAC", "AES-128", bytes(16), b"x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
