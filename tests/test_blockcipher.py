"""分组密码测试：SM4/AES/DES/3DES 官方向量与模式/填充回归。"""
from __future__ import annotations

import unittest

from cryptotoolbox.core import blockcipher as bc


class Sm4VectorTests(unittest.TestCase):
    def test_sm4_ecb_standard_vector(self):
        # GM/T 0002-2012 标准向量
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        plain = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        ct = bc.encrypt("SM4", "ECB", "无填充", plain, key)
        self.assertEqual(ct.hex().upper(), "681EDF34D206965E86B3E94F536E4246")
        self.assertEqual(bc.decrypt("SM4", "ECB", "无填充", ct, key)[0], plain)

    def test_sm4_modes_roundtrip(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        data = b"SM4 block cipher modes test 1234567"
        for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
            ct = bc.encrypt("SM4", mode, "PKCS7", data, key, b"" if mode == "ECB" else iv)
            pt, warn = bc.decrypt("SM4", mode, "PKCS7", ct, key, b"" if mode == "ECB" else iv)
            self.assertEqual(pt, data, f"SM4-{mode} 往返失败")
            if mode in ("CFB", "OFB", "CTR"):
                self.assertIn("流模式", warn)


class AesNistVectorTests(unittest.TestCase):
    # NIST SP 800-38A 附录 F
    KEY = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
    IV = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    PT = bytes.fromhex("6BC1BEE22E409F96E93D7E117393172A")

    def test_ecb_fips197(self):
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        pt = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        ct = bc.encrypt("AES-128", "ECB", "无填充", pt, key)
        self.assertEqual(ct.hex().upper(), "69C4E0D86A7B0430D8CDB78070B4C55A")

    def test_cbc_nist(self):
        ct = bc.encrypt("AES-128", "CBC", "无填充", self.PT, self.KEY, self.IV)
        self.assertEqual(ct.hex().upper(), "7649ABAC8119B246CEE98E9B12E9197D")

    def test_cfb128_nist(self):
        ct = bc.encrypt("AES-128", "CFB", "无填充", self.PT, self.KEY, self.IV)
        self.assertEqual(ct.hex().upper(), "3B3FD92EB72DAD20333449F8E83CFB4A")

    def test_ofb_nist(self):
        ct = bc.encrypt("AES-128", "OFB", "无填充", self.PT, self.KEY, self.IV)
        self.assertEqual(ct.hex().upper(), "3B3FD92EB72DAD20333449F8E83CFB4A")

    def test_ctr_nist_16_byte_iv(self):
        # 原项目缺陷回归：16 字节 IV 的 CTR 必须可用（NIST SP 800-38A F.5.1）
        iv = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
        ct = bc.encrypt("AES-128", "CTR", "无填充", self.PT, self.KEY, iv)
        self.assertEqual(ct.hex().upper(), "874D6191B620E3261BEF6864990DB6CE")

    def test_ctr_short_iv(self):
        ct = bc.encrypt("AES-128", "CTR", "无填充", self.PT, self.KEY, self.IV[:12])
        pt, _ = bc.decrypt("AES-128", "CTR", "无填充", ct, self.KEY, self.IV[:12])
        self.assertEqual(pt, self.PT)


class DesTests(unittest.TestCase):
    def test_des_ecb_fips(self):
        key = bytes.fromhex("133457799BBCDFF1")
        pt = bytes.fromhex("0123456789ABCDEF")
        ct = bc.encrypt("DES", "ECB", "无填充", pt, key)
        self.assertEqual(ct.hex().upper(), "85E813540F0AB405")

    def test_des3_roundtrip(self):
        key24 = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
        iv = bytes.fromhex("0001020304050607")
        data = b"Triple DES mode test data"
        ct = bc.encrypt("3DES", "CBC", "PKCS7", data, key24, iv)
        pt, warn = bc.decrypt("3DES", "CBC", "PKCS7", ct, key24, iv)
        self.assertEqual(pt, data)
        self.assertEqual(warn, "")

    def test_des3_16_byte_key(self):
        key16 = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01")
        data = b"16-byte 3DES key"
        ct = bc.encrypt("3DES", "CBC", "PKCS7", data, key16, b"12345678")
        pt, _ = bc.decrypt("3DES", "CBC", "PKCS7", ct, key16, b"12345678")
        self.assertEqual(pt, data)


class PaddingTests(unittest.TestCase):
    def test_pkcs7_padding(self):
        for size in (0, 1, 15, 16, 17, 32):
            data = bytes(range(size))
            padded, _ = bc.pad(data, 16, "PKCS7")
            self.assertEqual(len(padded) % 16, 0)
            plain, warn = bc.unpad(padded, 16, "PKCS7")
            self.assertEqual(plain, data)
            self.assertEqual(warn, "")

    def test_pkcs7_rejects_bad_padding(self):
        with self.assertRaises(bc.PaddingError):
            bc.unpad(b"\x00" * 16, 16, "PKCS7")

    def test_other_padding_roundtrip(self):
        data = b"padding scheme test!"
        for scheme in ("ISO10126", "ISO7816-4", "ANSI X9.23", "Zero"):
            padded, _ = bc.pad(data, 16, scheme)
            plain, _ = bc.unpad(padded, 16, scheme)
            self.assertEqual(plain, data, scheme)

    def test_no_padding_requires_alignment(self):
        with self.assertRaises(bc.PaddingError):
            bc.pad(b"abc", 16, "无填充")

    def test_stream_mode_ignores_padding(self):
        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        data = b"not aligned"
        ct = bc.encrypt("AES-128", "CTR", "PKCS7", data, key, b"12345678")
        pt, warn = bc.decrypt("AES-128", "CTR", "PKCS7", ct, key, b"12345678")
        self.assertEqual(pt, data)
        self.assertIn("流模式", warn)


class XtsVectorTests(unittest.TestCase):
    # IEEE P1619/D16 Annex B 官方测试向量
    def test_vector0_zero_key_sector0(self):
        key = bytes(32)
        iv = bytes(16)
        pt = bytes(32)
        ct = bc.encrypt("AES-128", "XTS", "无填充", pt, key, iv)
        self.assertEqual(ct.hex(), "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e")

    def test_vector1(self):
        key = bytes.fromhex("11111111111111111111111111111111" "22222222222222222222222222222222")
        sector = 0x3333333333
        iv = sector.to_bytes(8, "little") + bytes(8)
        pt = bytes.fromhex("44" * 32)
        ct = bc.encrypt("AES-128", "XTS", "无填充", pt, key, iv)
        self.assertEqual(ct.hex(), "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0")
        self.assertEqual(bc.decrypt("AES-128", "XTS", "无填充", ct, key, iv)[0], pt)

    def test_vector2(self):
        key = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" "22222222222222222222222222222222")
        sector = 0x3333333333
        iv = sector.to_bytes(8, "little") + bytes(8)
        pt = bytes.fromhex("44" * 32)
        ct = bc.encrypt("AES-128", "XTS", "无填充", pt, key, iv)
        self.assertEqual(ct.hex(), "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89")


class ModeNoteTests(unittest.TestCase):
    def test_mode_note(self):
        self.assertIn("流模式", bc.mode_note("CTR", "PKCS7"))
        self.assertEqual(bc.mode_note("CBC", "PKCS7"), "")

    def test_xts_roundtrip(self):
        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C" "000102030405060708090A0B0C0D0E0F")
        iv = bytes.fromhex("00000000000000000000000000000000")
        data = b"XTS mode test data 16 bytes!!!!!"[:32]
        ct = bc.encrypt("AES-128", "XTS", "无填充", data, key, iv)
        pt, _ = bc.decrypt("AES-128", "XTS", "无填充", ct, key, iv)
        self.assertEqual(pt, data)

    def test_key_validation(self):
        with self.assertRaises(bc.CipherError):
            bc.encrypt("AES-128", "CBC", "PKCS7", b"x" * 16, b"short", b"0" * 16)
        with self.assertRaises(bc.CipherError):
            bc.encrypt("SM4", "CBC", "PKCS7", b"x" * 16, b"0" * 16, b"0" * 15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
