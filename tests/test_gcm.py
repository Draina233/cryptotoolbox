"""GCM 测试：NIST GCM 规范测试向量（AES-128/192/256）与 SM4-GCM 往返。"""
from __future__ import annotations

import unittest

from cryptotoolbox.core import gcm


class AesGcmNistTests(unittest.TestCase):
    # 来源：NIST GCM specification 测试向量（Test case 1/2/3/4/7/8/9/14/16）
    def test_case1_empty(self):
        ct, tag = gcm.encrypt("AES-128-GCM", b"", bytes(16), bytes(12))
        self.assertEqual(ct, b"")
        self.assertEqual(tag.hex(), "58e2fccefa7e3061367f1d57a4e7455a")

    def test_case2_zero_block(self):
        ct, tag = gcm.encrypt("AES-128-GCM", bytes(16), bytes(16), bytes(12))
        self.assertEqual(ct.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")

    def test_case3_aes128_512bit(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        )
        ct, tag = gcm.encrypt("AES-128-GCM", pt, key, iv)
        self.assertEqual(ct.hex(),
                         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
        self.assertEqual(tag.hex(), "4d5c2af327cd64a62cf35abd2ba6fab4")

    def test_case4_aes128_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        ct, tag = gcm.encrypt("AES-128-GCM", pt, key, iv, aad)
        self.assertEqual(ct.hex(),
                         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
        self.assertEqual(tag.hex(), "5bc94fbc3221a5db94fae95ae7121a47")
        self.assertEqual(gcm.decrypt("AES-128-GCM", ct, tag, key, iv, aad), pt)

    def test_case7_aes192_empty(self):
        ct, tag = gcm.encrypt("AES-192-GCM", b"", bytes(24), bytes(12))
        self.assertEqual(tag.hex(), "cd33b28ac773f74ba00ed1f312572435")

    def test_case8_aes192_block(self):
        ct, tag = gcm.encrypt("AES-192-GCM", bytes(16), bytes(24), bytes(12))
        self.assertEqual(ct.hex(), "98e7247c07f0fe411c267e4384b0f600")
        self.assertEqual(tag.hex(), "2ff58d80033927ab8ef4d4587514f0fb")

    def test_case9_aes192_512bit(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        )
        ct, tag = gcm.encrypt("AES-192-GCM", pt, key, iv)
        self.assertEqual(tag.hex(), "9924a7c8587336bfb118024db8674a14")

    def test_case14_aes256_block(self):
        ct, tag = gcm.encrypt("AES-256-GCM", bytes(16), bytes(32), bytes(12))
        self.assertEqual(ct.hex(), "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(tag.hex(), "d0d1c8a799996bf0265b98b5d48ab919")

    def test_case16_aes256_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        ct, tag = gcm.encrypt("AES-256-GCM", pt, key, iv, aad)
        self.assertEqual(tag.hex(), "76fc6ece0f4e1768cddf8853bb2d551b")
        self.assertEqual(gcm.decrypt("AES-256-GCM", ct, tag, key, iv, aad), pt)

    def test_tamper_rejected(self):
        key = bytes(16)
        iv = bytes(12)
        ct, tag = gcm.encrypt("AES-128-GCM", b"hello", key, iv)
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        with self.assertRaises(gcm.GcmAuthError):
            gcm.decrypt("AES-128-GCM", ct, bad_tag, key, iv)
        bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
        with self.assertRaises(gcm.GcmAuthError):
            gcm.decrypt("AES-128-GCM", bad_ct, tag, key, iv)


class Sm4GcmTests(unittest.TestCase):
    def test_roundtrip(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("000102030405060708090A0B")
        data = b"SM4-GCM test payload"
        aad = b"header"
        ct, tag = gcm.encrypt("SM4-GCM", data, key, iv, aad)
        self.assertEqual(gcm.decrypt("SM4-GCM", ct, tag, key, iv, aad), data)

    def test_tamper_rejected(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("000102030405060708090A0B")
        ct, tag = gcm.encrypt("SM4-GCM", b"tamper", key, iv)
        bad = bytes([ct[0] ^ 1]) + ct[1:]
        with self.assertRaises(gcm.GcmAuthError):
            gcm.decrypt("SM4-GCM", bad, tag, key, iv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
