"""界面冒烟测试：离屏构造主窗口与全部页面（无显示器环境可运行）。"""
from __future__ import annotations

import os
import unittest

from PySide6.QtCore import Qt


class UiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        os.environ.setdefault("QT_QPA_FONTDIR", os.environ.get("SystemRoot", r"C:\Windows") + r"\Fonts")
        try:
            from PySide6.QtWidgets import QApplication
        except Exception:  # noqa: BLE001
            raise unittest.SkipTest("PySide6 不可用")

        from cryptotoolbox.ui.main_window import MainWindow

        cls.app = QApplication.instance() or QApplication([])
        cls.window = MainWindow()
        cls.window.show()
        cls.app.processEvents()

    @classmethod
    def tearDownClass(cls):
        cls.window.close()

    def test_home_page(self):
        from cryptotoolbox.ui.pages.home import HomePage

        self.window.open_page("home")
        self.app.processEvents()
        self.assertIsInstance(self.window.stack.currentWidget(), HomePage)

    def test_all_pages_construct(self):
        from cryptotoolbox.ui.pages import GROUPS

        for group in GROUPS:
            for spec in group.items:
                with self.subTest(page=spec.id):
                    self.window.open_page(spec.id)
                    self.app.processEvents()
                    page = self.window.stack.currentWidget()
                    self.assertEqual(getattr(page, "page_id", ""), spec.id,
                                     f"{spec.id} 打开的不是对应页面（可能是加载失败占位页）")

    def test_huge_output_capped(self):
        from cryptotoolbox.core.result import Report
        from cryptotoolbox.ui.widgets import MonoText, ResultPanel

        box = MonoText()
        box.setPlainText("X" * 1_000_000)
        self.assertLessEqual(len(box.toPlainText()), MonoText.MAX_DISPLAY_CHARS + 200)

        report = Report("大文本")
        report.add("row", "检查项", "pass", "ok")
        report.full_raw["签名值(HEX)"] = "AB" * 500_000
        panel = ResultPanel("大文本")
        panel.render(report)
        self.assertLessEqual(len(panel.detail.toPlainText()), 31_000)
        self.assertIn("完整签名数据", report.to_text())

    def test_long_output_wraps(self):
        from PySide6.QtWidgets import QPlainTextEdit

        from cryptotoolbox.ui.widgets import MonoText

        box = MonoText()
        self.assertEqual(box.lineWrapMode(), QPlainTextEdit.WidgetWidth)
        self.assertEqual(box.horizontalScrollBarPolicy(), Qt.ScrollBarAlwaysOff)

    def test_app_icon(self):
        self.assertFalse(self.window.windowIcon().isNull())

    def test_theme_toggle(self):
        self.window.toggle_theme()
        self.app.processEvents()
        self.window.toggle_theme()
        self.app.processEvents()


if __name__ == "__main__":
    unittest.main(verbosity=2)

