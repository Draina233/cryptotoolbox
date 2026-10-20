"""P7 / CMS 解析与国密签章容器测试。"""
from __future__ import annotations

import base64
import unittest
from pathlib import Path

from cryptotoolbox.core import pkcs7

VECTORS = Path(__file__).resolve().parent / "vectors"


class GmSignedContainerTests(unittest.TestCase):
    """OID 1.2.156.10197.6.1.4.2.2 国密电子签章结构（detached，无 signedAttrs）。"""

    @classmethod
    def setUpClass(cls):
        cls.der = base64.b64decode((VECTORS / "p7" / "gm-signed-container.b64").read_text().strip())

    def test_detected_as_gm_container(self):
        self.assertTrue(pkcs7._is_gm_signed_container(self.der))

    def test_parse_extracts_certificate(self):
        info = pkcs7.parse_p7(self.der)
        self.assertEqual(info.content_type, "1.2.156.10197.6.1.4.2.2")
        self.assertEqual(len(info.certificates), 1)
        self.assertIn("契", info.certificates[0].subject.text())
        self.assertTrue(info.gm)
        self.assertEqual(info.gm["signature_oid"], "1.2.156.10197.1.301.1")

    def test_verify_without_content_skips(self):
        report = pkcs7.verify_p7(self.der)
        statuses = {row.key: row.status for row in report.rows}
        self.assertEqual(statuses.get("content"), "pass")
        self.assertEqual(statuses.get("signer-cert"), "pass")
        self.assertEqual(statuses.get("signer-sig"), "skip")

    def test_verify_with_correct_content(self):
        # 用错误原文验签必须失败而不是异常
        report = pkcs7.verify_p7(self.der, detached_content=b"not-the-signed-data")
        statuses = {row.key: row.status for row in report.rows}
        self.assertEqual(statuses.get("signer-sig"), "fail")
        self.assertEqual(report.verdict(), "fail")


if __name__ == "__main__":
    unittest.main()
