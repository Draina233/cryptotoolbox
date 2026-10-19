"""离屏渲染全部页面截图（用于视觉回归与 README 配图）。

用法：python scripts/screenshots.py
输出：build/screenshots/<theme>/<page>.png
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", os.environ.get("SystemRoot", r"C:\Windows") + r"\Fonts")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from cryptotoolbox.ui.main_window import MainWindow  # noqa: E402
from cryptotoolbox.ui.pages import GROUPS  # noqa: E402
from cryptotoolbox.ui.state import set_theme  # noqa: E402
from cryptotoolbox.theme import DEFAULT_ACCENT, qss  # noqa: E402


def main() -> int:
    app = QApplication([])
    window = MainWindow()
    window.resize(1400, 900)
    window.show()
    out = ROOT / "build" / "screenshots"
    out.mkdir(parents=True, exist_ok=True)
    for theme in ("light", "dark"):
        window._settings.setValue("theme", theme)
        set_theme(theme, 1.0, DEFAULT_ACCENT)
        app.setStyleSheet(qss(window._state_palette() if False else __import__("cryptotoolbox.ui.state", fromlist=["palette"]).palette(), 1.0))
        window._apply_theme()
        for page_id in ["home"] + [spec.id for group in GROUPS for spec in group.items]:
            window.open_page(page_id)
            app.processEvents()
            window.repaint()
            app.processEvents()
            path = out / theme / f"{page_id}.png"
            path.parent.mkdir(parents=True, exist_ok=True)
            window.grab().save(str(path))
            print(theme, page_id, "saved")
    print("done:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
