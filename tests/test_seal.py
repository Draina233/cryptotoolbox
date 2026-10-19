"""电子签章测试：合成 PDF（RSA/SM2 CMS）与 OFD（SM2 SignedValue）。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptotoolbox.core import seal
from cryptotoolbox.core.der import build_sequence, build_tlv

from .support import seal_build

FIXTURES = Path(__file__).resolve().parent / "vectors" / "certs"


def make_signed_pdf(fixtures: Path, cert_name: str, key_name: str, sm2_sm3: bool) -> bytes:
    """两遍构造：先用占位 CMS 取得 ByteRange 覆盖的原文，再构造真实 CMS。"""
    cert_der = seal_build.load_cert_der(fixtures, cert_name)
    if sm2_sm3:
        key = seal_build.load_sm2_private(fixtures, key_name)
    else:
        key = seal_build.load_key_pem(fixtures, key_name)
    placeholder = build_signed_pdf_placeholder()
    sig = seal._find_pdf_signatures(placeholder)[0]
    signed = seal._reconstruct_ranges(placeholder, sig["byte_range"])
    cms = seal_build.build_cms(cert_der, key, signed, sm2_sm3=sm2_sm3)
    return seal_build.build_signed_pdf(cms)


def build_signed_pdf_placeholder() -> bytes:
    return seal_build.build_signed_pdf(build_tlv(0x30, b""))


class PdfSealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.rsa_pdf = cls.dir / "rsa-sealed.pdf"
        cls.rsa_pdf.write_bytes(make_signed_pdf(FIXTURES, "rsa-leaf.crt", "rsa-leaf.key", sm2_sm3=False))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_rsa_pdf_pass(self):
        reports = seal.verify_pdf(str(self.rsa_pdf))
        self.assertEqual(len(reports), 1)
        report = reports[0]
        statuses = {row.key: row.status for row in report.rows}
        self.assertEqual(statuses.get("fmt"), "pass")
        self.assertEqual(statuses.get("bytrange"), "pass")
        self.assertEqual(statuses.get("sigval"), "pass", [r.detail for r in report.rows])
        self.assertEqual(statuses.get("digest"), "pass")

    def test_tampered_pdf_fails(self):
        data = bytearray(self.rsa_pdf.read_bytes())
        # 修改签名覆盖区域中的一个字节（对象 4 的 stream 附近）
        pos = data.find(b"4 0 obj")
        data[pos + 8] ^= 0x01
        path = self.dir / "tampered.pdf"
        path.write_bytes(bytes(data))
        report = seal.verify_pdf(str(path))[0]
        statuses = {row.key: row.status for row in report.rows}
        # CMS 签名覆盖 signedAttrs；原文完整性由 messageDigest 体现
        self.assertEqual(statuses.get("digest"), "fail")
        self.assertEqual(report.verdict(), "fail")

    def test_no_signature_pdf(self):
        path = self.dir / "plain.pdf"
        path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
        report = seal.verify_pdf(str(path))[0]
        self.assertEqual(report.verdict(), "fail")

    def test_unknown_extension(self):
        with self.assertRaises(seal.SealError):
            seal.verify_seal_file(str(self.dir / "x.txt"))


class Sm2PdfSealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.pdf = cls.dir / "sm2-sealed.pdf"
        cls.pdf.write_bytes(make_signed_pdf(FIXTURES, "sm2-leaf.crt", "sm2-leaf.key", sm2_sm3=True))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_sm2_pdf_pass(self):
        report = seal.verify_pdf(str(self.pdf))[0]
        statuses = {row.key: row.status for row in report.rows}
        self.assertEqual(statuses.get("sigval"), "pass", [r.detail for r in report.rows])
        self.assertIn("SM2", " ".join(r.detail for r in report.rows))


class OfdSealTests(unittest.TestCase):
    def test_ofd_pass(self):
        cert_der = seal_build.load_cert_der(FIXTURES, "sm2-leaf.crt")
        key = seal_build.load_sm2_private(FIXTURES, "sm2-leaf.key")
        data = seal_build.build_signed_ofd(cert_der, key)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sealed.ofd"
            path.write_bytes(data)
            reports = seal.verify_ofd(str(path))
        self.assertEqual(len(reports), 1)
        report = reports[0]
        self.assertEqual(report.verdict(), "pass", [(r.key, r.status, r.detail) for r in report.rows])
        statuses = {row.key: row.status for row in report.rows}
        self.assertEqual(statuses.get("fmt"), "pass")
        self.assertEqual(statuses.get("seal_sig"), "pass")
        self.assertEqual(statuses.get("sign_sig"), "pass")
        self.assertEqual(statuses.get("files"), "pass")

    def test_ofd_tampered_fails(self):
        cert_der = seal_build.load_cert_der(FIXTURES, "sm2-leaf.crt")
        key = seal_build.load_sm2_private(FIXTURES, "sm2-leaf.key")
        data = seal_build.build_signed_ofd(cert_der, key, tamper=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.ofd"
            path.write_bytes(data)
            report = seal.verify_ofd(str(path))[0]
        self.assertEqual(report.verdict(), "fail")
        statuses = {r.key: r.status for r in report.rows}
        self.assertIn("fail", (statuses.get("seal_sig"), statuses.get("sign_sig"), statuses.get("files")))

    def test_ofd_without_signs(self):
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("OFD.xml", "<OFD/>")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unsigned.ofd"
            path.write_bytes(buffer.getvalue())
            report = seal.verify_ofd(str(path))[0]
        self.assertEqual(report.verdict(), "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ContainerPdfTests(unittest.TestCase):
    """国密电子印章容器（PDF 内嵌）测试。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _make(self, cert: str, key: str, sm2_mode: bool) -> bytes:
        cert_der = seal_build.load_cert_der(FIXTURES, cert)
        signer_key = seal_build.load_sm2_private(FIXTURES, key) if sm2_mode else seal_build.load_key_pem(FIXTURES, key)
        placeholder = seal_build.build_signed_pdf(build_tlv(0x30, b""))
        sig = seal._find_pdf_signatures(placeholder)[0]
        signed = seal._reconstruct_ranges(placeholder, sig["byte_range"])
        container = seal_build.build_seal_container(cert_der, signer_key, signed, sm2_mode)
        return seal_build.build_signed_pdf(container)

    def test_rsa_container_pass(self):
        path = self.dir / "rsa-container.pdf"
        path.write_bytes(self._make("rsa-leaf.crt", "rsa-leaf.key", False))
        report = seal.verify_pdf(str(path))[0]
        self.assertEqual(report.verdict(), "pass", [(r.label, r.detail) for r in report.rows])

    def test_sm2_container_pass(self):
        path = self.dir / "sm2-container.pdf"
        path.write_bytes(self._make("sm2-leaf.crt", "sm2-leaf.key", True))
        report = seal.verify_pdf(str(path))[0]
        self.assertEqual(report.verdict(), "pass", [(r.label, r.detail) for r in report.rows])
        self.assertTrue(any("SM2" in r.detail for r in report.rows))

    def test_container_tamper_fails(self):
        data = bytearray(self._make("sm2-leaf.crt", "sm2-leaf.key", True))
        pos = data.find(b"4 0 obj")
        data[pos + 8] ^= 0x01
        path = self.dir / "sm2-container-tampered.pdf"
        path.write_bytes(bytes(data))
        report = seal.verify_pdf(str(path))[0]
        statuses = {r.key: r.status for r in report.rows}
        self.assertEqual(statuses.get("digest"), "fail")
        self.assertEqual(report.verdict(), "fail")


class RealSampleTests(unittest.TestCase):
    SAMPLES = Path(r"D:\密评工具箱\测试样例\签章文件")

    def test_user_samples(self):
        if not self.SAMPLES.is_dir():
            self.skipTest("用户测试样例目录不存在")
        files = [p for p in self.SAMPLES.iterdir() if p.suffix.lower() in (".pdf", ".ofd")]
        if not files:
            self.skipTest("测试样例目录为空")
        for path in files:
            with self.subTest(file=path.name):
                reports = seal.verify_seal_file(str(path))
                self.assertTrue(reports)
                self.assertEqual(reports[0].verdict(), "pass",
                                 [(r.label, r.detail) for r in reports[0].rows])
