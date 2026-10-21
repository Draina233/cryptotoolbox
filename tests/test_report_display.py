"""大文本显示/导出的性能与安全边界测试。"""
from __future__ import annotations

import unittest

from cryptotoolbox.core.result import Report


class ReportDisplayTests(unittest.TestCase):
    def test_display_text_excludes_full_raw(self):
        report = Report("大文本测试")
        report.add("row", "检查项", "pass", "ok")
        report.full_raw["签名原文(HEX)"] = "AB" * 500_000
        text = report.to_display_text(max_chars=20_000)
        self.assertLessEqual(len(text), 20_100)
        self.assertNotIn("AB" * 100, text)
        self.assertIn("完整签名数据", report.to_text())

    def test_full_export_keeps_everything(self):
        report = Report("完整导出测试")
        payload = "CD" * 300_000
        report.full_raw["签名值(HEX)"] = payload
        self.assertIn(payload, report.to_text())
        self.assertIn(payload, report.to_dict()["full_raw"]["签名值(HEX)"])
        self.assertIn(payload, report.to_html())


if __name__ == "__main__":
    unittest.main()
