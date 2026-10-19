"""SM2 官方向量测试（GM/T 0003.5 / Botan 测试数据）与功能回归。"""
from __future__ import annotations

import unittest

from cryptotoolbox.core import sm2


class Sm2OfficialCurveVectorTests(unittest.TestCase):
    """官方推荐曲线向量（Botan 测试数据，GmSSL 生成）。"""

    SK = bytes.fromhex("110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC")
    NONCE = int("3174C6FFC3C279D2422F3FC0A9F3E574674A4490FE45A5325CAF7D3EC4C8F96C", 16)
    UID = b"sm2test@example.com"
    MESSAGE = bytes.fromhex("686920636861707079")  # "hi chappy"
    R = bytes.fromhex("05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA")
    S = bytes.fromhex("E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993")

    def test_sign_with_fixed_nonce(self):
        r, s = sm2.sign(self.MESSAGE, self.SK, self.UID, k=self.NONCE)
        self.assertEqual(r.to_bytes(32, "big"), self.R)
        self.assertEqual(s.to_bytes(32, "big"), self.S)

    def test_verify_official_signature(self):
        pk = sm2.derive_public_key(self.SK)
        self.assertTrue(sm2.verify(self.MESSAGE, (int.from_bytes(self.R, "big"), int.from_bytes(self.S, "big")),
                                   pk, self.UID))
        self.assertFalse(sm2.verify(self.MESSAGE + b"x",
                                    (int.from_bytes(self.R, "big"), int.from_bytes(self.S, "big")),
                                    pk, self.UID))
        # UID 不同必须验签失败（原项目缺陷回归：UID 不生效时这里会“通过”）
        self.assertFalse(sm2.verify(self.MESSAGE, (int.from_bytes(self.R, "big"), int.from_bytes(self.S, "big")),
                                    pk, b"other-uid"))


class Sm2ExampleCurveVectorTests(unittest.TestCase):
    """GM/T 0003.5-2012 附录 A 示例曲线向量。"""

    SK = bytes.fromhex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
    NONCE = int("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16)
    UID = b"ALICE123@YAHOO.COM"
    MESSAGE = bytes.fromhex("6D65737361676520646967657374")  # "message digest"
    R = bytes.fromhex("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1")
    S = bytes.fromhex("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7")
    E = "B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76"

    def test_e_value(self):
        pk = sm2.derive_public_key(self.SK, sm2.EXAMPLE_CURVE)
        e = sm2.e_value(self.MESSAGE, self.UID, pk, sm2.EXAMPLE_CURVE)
        self.assertEqual(e.hex().upper(), self.E)

    def test_sign_with_fixed_nonce(self):
        r, s = sm2.sign(self.MESSAGE, self.SK, self.UID, sm2.EXAMPLE_CURVE, k=self.NONCE)
        self.assertEqual(r.to_bytes(32, "big"), self.R)
        self.assertEqual(s.to_bytes(32, "big"), self.S)

    def test_verify_official_signature(self):
        pk = sm2.derive_public_key(self.SK, sm2.EXAMPLE_CURVE)
        self.assertTrue(sm2.verify(self.MESSAGE, (int.from_bytes(self.R, "big"), int.from_bytes(self.S, "big")),
                                   pk, self.UID, sm2.EXAMPLE_CURVE))
        self.assertFalse(sm2.verify(self.MESSAGE, (int.from_bytes(self.R, "big"), int.from_bytes(self.S, "big")),
                                    pk, b"other-uid", sm2.EXAMPLE_CURVE))


class Sm2RoundTripTests(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        sk, pk = sm2.generate_keypair()
        message = b"sm2 sign verify roundtrip"
        uid = b"1234567812345678"
        r, s = sm2.sign(message, sk, uid)
        self.assertTrue(sm2.verify(message, (r, s), pk, uid))
        self.assertFalse(sm2.verify(message + b"!", (r, s), pk, uid))

    def test_encrypt_decrypt_roundtrip(self):
        sk, pk = sm2.generate_keypair()
        message = b"encryption standard"
        for mode in ("C1C3C2", "C1C2C3"):
            cipher = sm2.encrypt(message, pk, mode)
            self.assertEqual(sm2.decrypt(cipher, sk, mode), message)

    def test_encrypt_tamper_detected(self):
        sk, pk = sm2.generate_keypair()
        cipher = sm2.encrypt(b"tamper test", pk, "C1C3C2")
        tampered = cipher[:-1] + bytes([cipher[-1] ^ 1])
        with self.assertRaises(sm2.SM2Error):
            sm2.decrypt(tampered, sk, "C1C3C2")

    def test_der_roundtrip(self):
        r = int.from_bytes(bytes.fromhex("05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA"), "big")
        s = int.from_bytes(bytes.fromhex("E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993"), "big")
        der = sm2.rs_to_der(r, s)
        self.assertEqual(sm2.der_to_rs(der), (r, s))
        self.assertEqual(sm2.signature_from_der(der), sm2._bytes32(r) + sm2._bytes32(s))

    def test_public_key_validation(self):
        sk, pk = sm2.generate_keypair()
        self.assertEqual(sm2.normalize_public_key(pk[1:]), pk)
        bad = bytearray(pk)
        bad[-1] ^= 1
        with self.assertRaises(sm2.SM2Error):
            sm2.decode_point(bytes(bad))

    def test_gmalg_cross_check(self):
        """用 gmalg 对同一消息独立签名，双方互相验签。"""
        try:
            from gmalg import SM2
        except Exception:  # noqa: BLE001
            self.skipTest("gmalg 不可用")
        sk, pk = sm2.generate_keypair()
        uid = b"1234567812345678"
        message = b"cross check with gmalg"
        r, s = sm2.sign(message, sk, uid)
        self.assertTrue(SM2(pk=pk, uid=uid).verify(message, sm2._bytes32(r), sm2._bytes32(s)))
        r2, s2 = SM2(sk=sk, uid=uid).sign(message)
        self.assertTrue(sm2.verify(message, (int.from_bytes(r2, "big"), int.from_bytes(s2, "big")), pk, uid))


if __name__ == "__main__":
    unittest.main(verbosity=2)
