"""页面基类：统一页头、滚动内容区、后台任务与错误处理。"""
from __future__ import annotations

import traceback

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QMessageBox,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..widgets import Card, HintLabel


class PageBase(QWidget):
    """所有功能页的基类。

    子类约定：
    - 覆写 build_ui() 构建界面（使用 self.body / self.card()）
    - 需要重跑示例数据或主题切换后重绘结果时可覆写 refresh_theme()
    """

    page_id = ""
    title = ""
    subtitle = ""

    def __init__(self, window=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.window_ref = window
        self._cards: list[Card] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.header = self._build_header()
        outer.addWidget(self.header)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.content = QWidget()
        self.content.setObjectName("pageContent")
        self.body = QVBoxLayout(self.content)
        self.body.setContentsMargins(22, 18, 22, 24)
        self.body.setSpacing(14)
        self.body.setAlignment(Qt.AlignTop)
        self.scroll.setWidget(self.content)
        outer.addWidget(self.scroll, 1)

        self.build_ui()
        self.body.addStretch(1)

    # ------------------------------------------------------------ 页头
    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("pageHeader")
        header.setStyleSheet("background: transparent;")
        v = QVBoxLayout(header)
        v.setContentsMargins(22, 18, 22, 6)
        v.setSpacing(4)
        row = QWidget()
        row.setStyleSheet("background: transparent;")
        h = QVBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(4)
        self.title_label = QLabel(self.title)
        self.title_label.setObjectName("pageTitle")
        h.addWidget(self.title_label)
        if self.subtitle:
            sub = QLabel(self.subtitle)
            sub.setObjectName("pageSubtitle")
            sub.setWordWrap(True)
            h.addWidget(sub)
        v.addWidget(row)
        return header

    # ------------------------------------------------------------ 工具方法
    def card(self, title: str = "", subtitle: str = "") -> Card:
        c = Card(title, subtitle)
        self._cards.append(c)
        self.body.addWidget(c)
        return c

    def add_widget(self, widget: QWidget) -> QWidget:
        self.body.addWidget(widget)
        return widget

    def notify(self, message: str) -> None:
        if self.window_ref is not None and hasattr(self.window_ref, "notify"):
            self.window_ref.notify(message)

    def show_error(self, exc: BaseException | str, title: str = "操作失败") -> None:
        detail = str(exc) if isinstance(exc, str) else "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setIcon(QMessageBox.Warning)
        box.setText(str(exc) if isinstance(exc, str) else str(exc))
        box.setDetailedText(detail)
        box.exec()

    def run_background(self, fn, on_result, on_error=None, busy_text: str = "正在处理…",
                       cancellable: bool = False, on_progress=None, on_cancel=None):
        if self.window_ref is not None:
            return self.window_ref.run_task(
                fn, on_result=on_result, on_error=on_error, busy_text=busy_text,
                cancellable=cancellable, on_progress=on_progress, on_cancel=on_cancel,
            )
        # 没有主窗口时退化为同步执行（便于测试）
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            if on_error:
                on_error(exc)
            else:
                self.show_error(exc)
            return None
        on_result(result)
        return None

    # ------------------------------------------------------------ 主题
    def refresh_theme(self) -> None:
        """主题切换后由主窗口调用；需要重绘结果的页面覆写。"""
