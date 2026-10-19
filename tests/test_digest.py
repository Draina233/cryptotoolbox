"""核心算法测试：SM3 / 哈希 / HMAC。"""
from __future__ import annotations

import hashlib
import hmac
import unittest

from cryptotoolbox.core import digest


class Sm3VectorTests(unittest.TestCase):
    # GB/T 32905-2016 附录 A 示例
    def test_abc_vector(self):
        expected = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
        self.assertEqual(digest.sm3(b"abc").hex().upper(), expected)
        self.assertEqual(digest.digest_hex("SM3", b"abc"), expected)

    def test_abcd_vector(self):
        expected = "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732"
        self.assertEqual(digest.sm3(b"abcd" * 16).hex().upper(), expected)

    def test_pure_and_native_agree_on_vectors(self):
        self.assertEqual(digest.sm3_pure(b"abc"), digest.SM3Hash().digest() if False else digest.sm3(b"abc"))
        for data in (b"", b"abc", b"abcd" * 16, bytes(range(256)) * 4):
            self.assertEqual(digest.sm3_pure(data), digest.sm3(data), f"SM3 实现不一致: {len(data)} 字节")

    def test_streaming_hash(self):
        hasher = digest.SM3Hash()
        hasher.update(b"ab")
        hasher.update(b"c")
        self.assertEqual(hasher.digest().hex().upper(), "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")
        cloned = hasher.copy()
        self.assertEqual(cloned.hexdigest(), hasher.hexdigest())


class HmacTests(unittest.TestCase):
    # RFC 2202 / RFC 4231 向量
    def test_hmac_sha1_rfc2202(self):
        key = bytes([0x0B]) * 20
        data = b"Hi There"
        self.assertEqual(
            digest.hmac_digest("SHA-1", key, data).hex().upper(),
            "B617318655057264E28BC0B6FB378C8EF146BE00",
        )

    def test_hmac_sha256_rfc4231(self):
        key = bytes([0x0B]) * 20
        data = b"Hi There"
        self.assertEqual(
            digest.hmac_digest("SHA-256", key, data).hex().upper(),
            "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7",
        )

    def test_hmac_sm3_uses_standard_structure(self):
        """HMAC-SM3 必须是 H((K^opad)||H((K^ipad)||M))，而不是 H(K||M)。"""
        key = bytes(range(16))
        data = b"mesaj"
        key0 = key.ljust(digest.SM3Hash.block_size, b"\x00")
        expected = digest.sm3(
            bytes(b ^ 0x5C for b in key0) + digest.sm3(bytes(b ^ 0x36 for b in key0) + data)
        )
        self.assertEqual(digest.hmac_sm3(key, data), expected)
        # 前缀 MAC 不应与标准 HMAC 相同（回归原项目错误）
        self.assertNotEqual(digest.hmac_sm3(key, data), digest.sm3(key + data))

    def test_hmac_sm3_cross_check_with_tongsuopy(self):
        """用 tongsuopy 的 C 端 SM3 独立计算 HMAC-SM3 结构，验证结果一致。"""
        try:
            from tongsuopy.crypto import hashes as tsh
            from tongsuopy.crypto.hashes import SM3
        except Exception:  # noqa: BLE001
            self.skipTest("tongsuopy 不可用")

        class TongsuoSM3:
            block_size = 64
            digest_size = 32

            def __init__(self, data=b""):
                self._h = tsh.Hash(SM3())
                if data:
                    self.update(data)

            def update(self, data):
                self._h.update(data)

            def digest(self):
                h = self._h.copy()
                return h.finalize()

            def copy(self):
                new = TongsuoSM3()
                new._h = self._h.copy()
                return new

        key = b"secret key"
        data = b"hello hmac sm3"
        std = hmac.new(key, data, digestmod=TongsuoSM3).digest()
        self.assertEqual(digest.hmac_sm3(key, data), std)


class HashlibTests(unittest.TestCase):
    def test_standard_algorithms(self):
        data = b"hello"
        for algo in ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                     "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "MD5"):
            expected = hashlib.new(algo.lower().replace("sha3-", "sha3_").replace("sha-", "sha"),
                                   data).hexdigest().upper()
            self.assertEqual(digest.digest_hex(algo, data), expected, algo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
