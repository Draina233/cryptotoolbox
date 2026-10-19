"""应用引导：日志、异常处理、主题与主窗口。"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from PySide6.QtCore import QStandardPaths
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from . import __app_name__, __version__
from .ui.assets import app_icon_path
from .ui.main_window import MainWindow


def _log_path() -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.AppLocalDataLocation)
    if not base:
        base = str(Path.home() / ".cryptotoolbox")
    folder = Path(base) / "logs"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "app.log"


def _setup_logging() -> None:
    try:
        logging.basicConfig(
            filename=str(_log_path()),
            level=logging.INFO,
            encoding="utf-8",
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
    except Exception:  # noqa: BLE001 - 日志失败不应阻断启动
        pass


def _install_excepthook() -> None:
    def hook(exc_type, exc, tb):  # noqa: ANN001
        logging.error("uncaught exception", exc_info=(exc_type, exc, tb))
        try:
            box = QMessageBox()
            box.setWindowTitle("程序异常")
            box.setIcon(QMessageBox.Critical)
            box.setText(f"{exc_type.__name__}: {exc}")
            box.setInformativeText("详细信息已写入日志。可继续使用其他功能，或重启程序。")
            box.setDetailedText("".join(__import__("traceback").format_exception(exc_type, exc, tb)))
            box.exec()
        except Exception:  # noqa: BLE001
            pass

    sys.excepthook = hook


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv)
    app.setApplicationName(__app_name__)
    app.setOrganizationName("CryptoEval")
    app.setApplicationVersion(__version__)
    app.setWindowIcon(QIcon(app_icon_path()))
    if sys.platform == "win32":
        # 让 Windows 任务栏使用本程序图标，而不是 python.exe 的图标
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("CryptoEval.Toolbox.2")
        except Exception:  # noqa: BLE001
            pass
    _setup_logging()
    _install_excepthook()

    font = QFont("Microsoft YaHei UI")
    font.setPointSize(10)
    app.setFont(font)

    window = MainWindow()
    if "--smoke-test" in argv:
        # 打包后自检：逐个打开所有页面，验证资源与动态导入是否完整
        from .ui.pages import GROUPS

        for group in GROUPS:
            for spec in group.items:
                window.open_page(spec.id)
        window.close()
        return 0
    window.show()

    # 支持 --page <id> 直接打开指定页面（便于演示与截图）
    if "--page" in argv:
        try:
            idx = argv.index("--page")
            page_id = argv[idx + 1]
            window.open_page(page_id)
        except (IndexError, ValueError):
            pass

    return app.exec()
