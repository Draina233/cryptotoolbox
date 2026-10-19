"""PCAP 解析测试：合成抓包（pcap / pcapng / TLS / ESP / IKE）。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptotoolbox.core import pcap

from .support import pcap_build

FIXTURES = Path(__file__).resolve().parent / "vectors" / "certs"


class PcapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls.tmp.name)
        cls.cert_der = pcap_build.load_cert_der(FIXTURES, "rsa-leaf.crt")
        frames = pcap_build.make_tls_flow()
        frames.append(pcap_build.make_certificate_flow(cls.cert_der))
        frames.append(pcap_build.make_esp_packet())
        frames.append(pcap_build.make_ike_packet(cls.cert_der))
        cls.frames = frames
        cls.pcap_path = str(cls.tmpdir / "sample.pcap")
        cls.pcapng_path = str(cls.tmpdir / "sample.pcapng")
        pcap_build.write_pcap(cls.pcap_path, frames)
        pcap_build.write_pcapng(cls.pcapng_path, frames)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_read_packets(self):
        packets, warnings = pcap.read_packets(Path(self.pcap_path).read_bytes())
        self.assertEqual(len(packets), len(self.frames))
        self.assertEqual(warnings, [])

    def test_analyze_tls_flow(self):
        result = pcap.analyze_capture(self.pcap_path)
        # ClientHello / ServerHello
        kinds = {hs.kind for hs in result.handshakes}
        self.assertIn("ClientHello", kinds)
        self.assertIn("ServerHello", kinds)
        client = next(hs for hs in result.handshakes if hs.kind == "ClientHello")
        self.assertIn("leaf.example.com", client.details["sni"])
        suites = result.cipher_suites()
        self.assertTrue(any("0xE051" in s for s in suites), suites)
        # 记录边界：两条 app_data 必须分开
        app = [r for r in result.encrypted if r.protocol == "TLS"]
        self.assertTrue(len(app) >= 2)
        payloads = {r.payload for r in app}
        self.assertIn(b"ENCRYPTED-RECORD-ONE", payloads)
        self.assertIn(b"ENCRYPTED-RECORD-TWO", payloads)

    def test_certificate_extracted(self):
        result = pcap.analyze_capture(self.pcap_path)
        subjects = [c.subject for c in result.certificates if c.subject]
        self.assertTrue(any("rsa leaf.example.com" in s for s in subjects), subjects)
        # TLS Certificate 消息与 IKE 内嵌证书应分别提取到（≥2 张）
        self.assertGreaterEqual(len(subjects), 2, result.warnings)

    def test_esp_extracted(self):
        result = pcap.analyze_capture(self.pcap_path)
        esp = [r for r in result.encrypted if r.protocol == "ESP"]
        self.assertEqual(len(esp), 1)
        self.assertEqual(esp[0].payload, b"ESP-ENCRYPTED-PAYLOAD")

    def test_ip_filter(self):
        result = pcap.analyze_capture(self.pcap_path, ip_filter=("10.0.0.1", "10.0.0.2"))
        self.assertTrue(result.handshakes)
        for hs in result.handshakes:
            self.assertIn({hs.source, hs.destination}, [{"10.0.0.1", "10.0.0.2"}])
        result_none = pcap.analyze_capture(self.pcap_path, ip_filter=("192.168.1.1", "192.168.1.2"))
        self.assertEqual(result_none.handshakes, [])

    def test_pcapng(self):
        result = pcap.analyze_capture(self.pcapng_path)
        self.assertTrue(result.handshakes)

    def test_invalid_file(self):
        with self.assertRaises(pcap.PcapError):
            pcap.read_packets(b"\x00\x01")


if __name__ == "__main__":
    unittest.main(verbosity=2)


