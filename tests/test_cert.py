"""X.509 / CMS / CRL 测试（使用 scripts/make_cert_fixtures.ps1 生成的样本）。"""
from __future__ import annotations

import base64
import re
import unittest
from pathlib import Path

from cryptotoolbox.core import cert as certmod
from cryptotoolbox.core import pkcs7
from cryptotoolbox.core.crl import parse_crl
from cryptotoolbox.core.keys import parse_certificates_text

FIXTURES = Path(__file__).resolve().parent / "vectors" / "certs"


def load_cert(name: str):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    entries = parse_certificates_text(text, "PEM/DER")
    if not entries or entries[0][1] is None:
        raise AssertionError(f"无法加载 {name}: {entries}")
    return entries[0][1]


class X509ParseTests(unittest.TestCase):
    def test_rsa_cert_fields(self):
        root = load_cert("rsa-root.crt")
        self.assertEqual(root.version, 3)
        self.assertGreater(root.serial, 0)
        self.assertEqual(root.signature_alg_oid, "1.2.840.113549.1.1.11")
        self.assertIn("rsa Root CA", root.subject.text())
        self.assertTrue(root.is_ca)
        self.assertIn("keyCertSign", root.key_usage)
        self.assertTrue(root.is_self_signed)

    def test_ec_cert_curve(self):
        leaf = load_cert("ec-leaf.crt")
        self.assertEqual(leaf.spki.algorithm_oid, "1.2.840.10045.2.1")
        self.assertEqual(leaf.spki.curve_label, "P-256 (prime256v1)")
        self.assertEqual(leaf.signature_alg_oid, "1.2.840.10045.4.3.2")
        self.assertIn("ecdsa.example.com", leaf.subject_alt_names)
        self.assertFalse(leaf.is_ca)

    def test_sm2_cert(self):
        leaf = load_cert("sm2-leaf.crt")
        self.assertTrue(leaf.spki.is_sm2)
        self.assertEqual(leaf.signature_alg_oid, "1.2.156.10197.1.501")
        self.assertIn("sm2.example.com", leaf.subject_alt_names)
        self.assertEqual(len(leaf.spki.key_bits), 65)
        self.assertEqual(leaf.spki.key_bits[0], 0x04)

    def test_cert_summary_renders(self):
        text = load_cert("rsa-leaf.crt").summary_text()
        self.assertIn("版本: v3", text)
        self.assertIn("颁发者:", text)


class ChainVerificationTests(unittest.TestCase):
    def test_rsa_chain(self):
        leaf, inter, root = load_cert("rsa-leaf.crt"), load_cert("rsa-int.crt"), load_cert("rsa-root.crt")
        self.assertTrue(certmod.verify_certificate(leaf, inter)[0])
        self.assertTrue(certmod.verify_certificate(inter, root)[0])
        self.assertTrue(certmod.verify_certificate(root, root)[0])
        report = certmod.validate_chain(leaf, [root, inter])
        self.assertEqual(report.verdict(), "pass")
        self.assertFalse(any(r.status == "fail" for r in report.rows))

    def test_ecdsa_chain_uses_der_signature(self):
        # 原项目缺陷回归：ECDSA 使用 P1363 编码导致真实证书验签失败
        leaf, inter = load_cert("ec-leaf.crt"), load_cert("ec-int.crt")
        ok, message = certmod.verify_certificate(leaf, inter)
        self.assertTrue(ok, message)

    def test_sm2_chain(self):
        leaf, root = load_cert("sm2-leaf.crt"), load_cert("sm2-root.crt")
        ok, message = certmod.verify_certificate(leaf, root)
        self.assertTrue(ok, message)
        self.assertIn("SM2 验签通过", message)

    def test_wrong_issuer_rejected(self):
        leaf, ec_inter = load_cert("rsa-leaf.crt"), load_cert("ec-int.crt")
        ok, _ = certmod.verify_certificate(leaf, ec_inter)
        self.assertFalse(ok)

    def test_missing_intermediate_truncates(self):
        leaf, root = load_cert("rsa-leaf.crt"), load_cert("rsa-root.crt")
        report = certmod.validate_chain(leaf, [root])
        self.assertTrue(any("缺少中间 CA" in n for n in report.notes))

    def test_non_ca_intermediate_rejected(self):
        leaf, ec_leaf = load_cert("nonca-leaf.crt"), load_cert("ec-leaf.crt")
        report = certmod.validate_chain(leaf, [ec_leaf])
        self.assertTrue(any(r.status == "fail" and "CA" in r.label for r in report.rows),
                        [f"{r.status}:{r.label}" for r in report.rows])


class CmsVerifyTests(unittest.TestCase):
    def test_attached_rsa(self):
        report = pkcs7.verify_p7((FIXTURES / "cms-rsa-attached.p7s").read_bytes())
        self.assertEqual(report.verdict(), "pass")

    def test_detached_rsa(self):
        content = (FIXTURES / "cms-data.txt").read_bytes()
        report = pkcs7.verify_p7((FIXTURES / "cms-rsa-detached.p7s").read_bytes(), detached_content=content)
        self.assertEqual(report.verdict(), "pass")

    def test_sm2_cms(self):
        report = pkcs7.verify_p7((FIXTURES / "cms-sm2-attached.p7s").read_bytes())
        self.assertEqual(report.verdict(), "pass")
        self.assertTrue(any("SM2 验签通过" in r.detail for r in report.rows))

    def test_ec_cms(self):
        report = pkcs7.verify_p7((FIXTURES / "cms-ec-attached.p7s").read_bytes())
        self.assertEqual(report.verdict(), "pass")

    def test_tampered_content_fails(self):
        from cryptotoolbox.core.cms import parse_content_info

        der = bytearray((FIXTURES / "cms-rsa-attached.p7s").read_bytes())
        ci = parse_content_info(bytes(der))
        sd = ci.signed_data
        # 篡改 eContent 的一个字节
        from cryptotoolbox.core.der import build_tlv

        tampered = bytes(der).replace(sd.econtent, sd.econtent[:-1] + bytes([sd.econtent[-1] ^ 1]))
        report = pkcs7.verify_p7(tampered)
        self.assertEqual(report.verdict(), "fail")


class CrlTests(unittest.TestCase):
    def _load_crl(self):
        pem = (FIXTURES / "rsa-root.crl").read_text(encoding="utf-8")
        body = re.sub(r"\s+", "", pem.split("-----BEGIN X509 CRL-----")[1].split("-----END X509 CRL-----")[0])
        return parse_crl(base64.b64decode(body))

    def test_parse_and_verify(self):
        crl = self._load_crl()
        self.assertGreater(crl.this_update.year, 2000)
        root = load_cert("rsa-root.crt")
        ok, message = certmod.verify_signature(
            spki=root.spki,
            signature_algorithm_oid=crl.signature_algorithm_oid,
            signature_algorithm_params=crl.signature_algorithm_params,
            data=crl.tbs,
            signature=crl.signature,
            signer_uid=[root.subject.raw, b"", b"1234567812345678"],
        )
        self.assertTrue(ok, message)
        self.assertEqual(crl.issuer.raw, root.subject.raw)
        self.assertEqual(crl.find_serial(123456), None)

    def test_der_crl(self):
        crl = parse_crl((FIXTURES / "rsa-root.crl.der").read_bytes())
        self.assertEqual(crl.version, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
