"""通用界面控件：卡片、表单行、状态徽章、结果表格、结果面板、文件选择等。

所有页面共享这些控件，保证视觉与交互一致。
"""
from __future__ import annotations

from typing import Callable, Iterable, Optional

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import state
from .icons import make_icon


# ---------------------------------------------------------------- 基础控件
class Card(QFrame):
    """白色卡片容器，带可选标题与说明。"""

    def __init__(self, title: str = "", subtitle: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 14, 16, 16)
        self._layout.setSpacing(10)
        if title:
            head = QHBoxLayout()
            head.setSpacing(8)
            label = QLabel(title)
            label.setObjectName("sectionTitle")
            head.addWidget(label)
            if subtitle:
                sub = QLabel(subtitle)
                sub.setObjectName("hintText")
                head.addWidget(sub)
            head.addStretch(1)
            self._layout.addLayout(head)
            self.header = head
        else:
            self.header = None
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        self._layout.addLayout(self.body)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        if isinstance(layout, QWidget):
            self.body.addWidget(layout)
        else:
            self.body.addLayout(layout)

    def add_row(self, label: str, *controls: QWidget, hint: str = "", stretch_last: bool = True) -> QWidget:
        """一行表单：左侧标签 + 若干控件 + 可选提示。"""
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        lab = QLabel(label)
        lab.setObjectName("fieldLabel")
        lab.setMinimumWidth(96)
        lab.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        h.addWidget(lab)
        for i, control in enumerate(controls):
            if isinstance(control, QWidget):
                h.addWidget(control, 1 if (stretch_last and i == len(controls) - 1) else 0)
        if hint:
            h.addWidget(HintLabel(hint))
        self.body.addWidget(row)
        return row

    def add_grid(self, specs: list[list[tuple[str, QWidget, str]]]) -> None:
        """多列表单：specs 为行列表，每行 [(标签, 控件, 提示), ...]。"""
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        for r, row_spec in enumerate(specs):
            for c, (label, control, hint) in enumerate(row_spec):
                box = QWidget()
                v = QVBoxLayout(box)
                v.setContentsMargins(0, 0, 0, 0)
                v.setSpacing(4)
                lab = QLabel(label)
                lab.setObjectName("fieldLabel")
                v.addWidget(lab)
                v.addWidget(control)
                if hint:
                    v.addWidget(HintLabel(hint))
                grid.addWidget(box, r, c)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.body.addLayout(grid)

    def add_note(self, text: str) -> QLabel:
        lab = HintLabel(text)
        lab.setWordWrap(True)
        self.body.addWidget(lab)
        return lab


def HintLabel(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("hintText")
    lab.setWordWrap(True)
    return lab


class SectionTitle(QLabel):
    def __init__(self, text: str):
        super().__init__(text)
        self.setObjectName("sectionTitle")


class StatusChip(QLabel):
    """状态徽章：通过/未通过/未知/不适用。"""

    def __init__(self, status: str = "unknown", text: str | None = None):
        super().__init__()
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumWidth(64)
        self.set_status(status, text)

    def set_status(self, status: str, text: str | None = None) -> None:
        self._status = status
        color = state.status_color(status)
        bg = state.status_bg(status)
        self.setText(text if text is not None else state.status_text(status))
        self.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {color}; border-radius: 9px;"
            f" padding: 2px 10px; font-weight: 600; }}"
        )


class MonoText(QPlainTextEdit):
    """只读等宽文本区，用于十六进制/结构化结果。"""

    def __init__(self, placeholder: str = "", min_height: int = 120):
        super().__init__()
        self.setObjectName("mono")
        self.setReadOnly(True)
        self.setPlaceholderText(placeholder)
        self.setMinimumHeight(min_height)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        f = QFont("Cascadia Mono")
        f.setStyleHint(QFont.Monospace)
        self.setFont(f)


class TextInput(QPlainTextEdit):
    def __init__(self, placeholder: str = "", min_height: int = 90, mono: bool = False):
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setMinimumHeight(min_height)
        if mono:
            self.setObjectName("mono")
            # 十六进制/长文本按窗口宽度自动换行，避免内容超出输入框
            self.setLineWrapMode(QPlainTextEdit.WidgetWidth)


class CopyButton(QPushButton):
    """复制按钮，复制成功后短暂显示“已复制”。"""

    def __init__(self, provider: Callable[[], str], label: str = "复制", parent=None):
        super().__init__(label, parent)
        self.setObjectName("secondary")
        self.setIcon(make_icon("copy", state.palette()["text_secondary"], 14))
        self.setIconSize(QSize(14, 14))
        self._provider = provider
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._reset)
        self.clicked.connect(self._copy)

    def _copy(self) -> None:
        try:
            text = self._provider() or ""
        except Exception:
            text = ""
        QGuiApplication.clipboard().setText(text)
        self.setText("已复制")
        self._timer.start(1200)

    def _reset(self) -> None:
        self.setText("复制")


class FilePicker(QWidget):
    """文件选择行：只读路径 + 选择按钮 (+可选追加按钮)。"""

    file_selected = Signal(str)

    def __init__(self, title: str = "选择文件", filters: str = "所有文件 (*.*)",
                 placeholder: str = "尚未选择文件", append_text: str = ""):
        super().__init__()
        self._title = title
        self._filters = filters
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText(placeholder)
        h.addWidget(self.path_edit, 1)
        self.browse_btn = QPushButton("浏览…")
        self.browse_btn.setObjectName("secondary")
        self.browse_btn.clicked.connect(self._browse)
        h.addWidget(self.browse_btn)
        self.append_btn = None
        if append_text:
            self.append_btn = QPushButton(append_text)
            self.append_btn.setObjectName("secondary")
            self.append_btn.clicked.connect(self._browse)
            h.addWidget(self.append_btn)
        self.file = ""

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, self._title, "", self._filters)
        if path:
            self.file = path
            self.path_edit.setText(path)
            self.file_selected.emit(path)

    def path(self) -> str:
        return self.path_edit.text().strip()

    def set_file(self, path: str) -> None:
        self.file = path
        self.path_edit.setText(path)
        self.file_selected.emit(path)


class DropArea(QFrame):
    """拖拽文件区域。"""

    file_dropped = Signal(str)

    def __init__(self, text: str = "把文件拖到这里，或点击选择", hint: str = "", filters: str = "所有文件 (*.*)"):
        super().__init__()
        self.setObjectName("dropArea")
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self._filters = filters
        self._text = text
        v = QVBoxLayout(self)
        v.setContentsMargins(16, 16, 16, 16)
        v.setSpacing(6)
        self.title = QLabel(text)
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setWordWrap(True)
        v.addWidget(self.title)
        if hint:
            h = QLabel(hint)
            h.setObjectName("hintText")
            h.setAlignment(Qt.AlignCenter)
            h.setWordWrap(True)
            v.addWidget(h)
        self.setMinimumHeight(86)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", self._filters)
            if path:
                self.file_dropped.emit(path)
        super().mousePressEvent(event)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if local:
                self.file_dropped.emit(local)
                break


class ResultTable(QTableWidget):
    """通用只读结果表格。"""

    def __init__(self, headers: list[str], min_height: int = 160):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setMinimumHeight(min_height)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

    def set_checks(self, rows: Iterable) -> None:
        """rows: 具有 label/status/detail 属性的对象（CheckResult）。"""
        rows = list(rows)
        self.setRowCount(0)
        for r in rows:
            self._append_row([
                getattr(r, "label", ""),
                _status_item(getattr(r, "status", "unknown")),
                getattr(r, "detail", ""),
            ])

    def _append_row(self, values: list) -> None:
        row = self.rowCount()
        self.insertRow(row)
        for col, value in enumerate(values):
            if isinstance(value, QTableWidgetItem):
                item = value
            else:
                item = QTableWidgetItem(str(value))
                item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.setItem(row, col, item)
        self.resizeRowsToContents()

    def set_rows(self, rows: list[list]) -> None:
        self.setRowCount(0)
        for values in rows:
            self._append_row([_status_item(v) if v in ("pass", "fail", "unknown", "skip") else v
                              for v in values])


def _status_item(status: str) -> QTableWidgetItem:
    item = QTableWidgetItem(state.status_text(status))
    item.setForeground(QColor(state.status_color(status)))
    item.setTextAlignment(Qt.AlignCenter)
    return item


class ResultPanel(Card):
    """标准结果面板：状态徽章 + 汇总 + 检查表 + 详情 + 导出。"""

    def __init__(self, title: str = "检测结果", parent=None):
        super().__init__(title, parent=parent)
        self.summary = QLabel("尚未执行")
        self.summary.setObjectName("hintText")
        self.summary.setWordWrap(True)
        self.body.addWidget(self.summary)
        self.table = ResultTable(["检测项", "结果", "说明"], 150)
        self.body.addWidget(self.table)
        self.detail = MonoText("详细结果将显示在这里…", 110)
        self.body.addWidget(self.detail)
        self.action_row = QHBoxLayout()
        self.action_row.setSpacing(8)
        self.body.addLayout(self.action_row)
        self._last_report = None
        self.export_btn = QPushButton("导出报告…")
        self.export_btn.setObjectName("secondary")
        self.export_btn.setToolTip("导出为 JSON / TXT / HTML 报告")
        self.export_btn.clicked.connect(self._export)
        self.action_row.addWidget(self.export_btn)
        self.action_row.addStretch(1)

    def render(self, report) -> None:
        """report: core.result.Report"""
        self._last_report = report
        p = state.palette()
        self.table.set_checks(report.rows)
        counts = {"pass": 0, "fail": 0, "unknown": 0, "skip": 0}
        for row in report.rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        chips = []
        for key, label in (("pass", "通过"), ("fail", "未通过"), ("unknown", "未知"), ("skip", "不适用")):
            if counts.get(key):
                color = state.status_color(key)
                chips.append(f'<span style="color:{color};font-weight:600">{label} {counts[key]}</span>')
        summary_html = f"<b>{report.title}</b>　" + "　".join(chips)
        self.summary.setText(summary_html)
        self.summary.setTextFormat(Qt.RichText)
        self.detail.setPlainText(report.to_text())
        self.export_btn.setVisible(True)

    def _export(self) -> None:
        if self._last_report is None:
            return
        from pathlib import Path

        from PySide6.QtWidgets import QFileDialog, QMessageBox

        from ..core.result import export_report

        title = "".join(ch for ch in (self._last_report.title or "报告") if ch not in '\\/:*?"<>|').strip() or "报告"
        path, selected = QFileDialog.getSaveFileName(
            self, "导出报告", f"{title}.txt",
            "文本 (*.txt);;JSON (*.json);;HTML (*.html)",
        )
        if not path:
            return
        if not Path(path).suffix:
            path += ".json" if "JSON" in selected else (".html" if "HTML" in selected else ".txt")
        try:
            export_report(self._last_report, path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "导出失败", f"无法写入报告：{exc}")
            return
        win = self.window()
        if hasattr(win, "notify"):
            win.notify(f"报告已导出：{path}")


class ActionBar(QWidget):
    """页面动作条。"""

    def __init__(self, *buttons: QWidget):
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        for b in buttons:
            h.addWidget(b)
        h.addStretch(1)


def primary_button(text: str, icon: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if icon:
        btn.setIcon(make_icon(icon, state.palette()["primary_text"], 14))
        btn.setIconSize(QSize(14, 14))
    return btn


def secondary_button(text: str, icon: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    btn.setObjectName("secondary")
    if icon:
        btn.setIcon(make_icon(icon, state.palette()["text_secondary"], 14))
        btn.setIconSize(QSize(14, 14))
    return btn


def combo(items: Iterable[str], current: str | None = None) -> QComboBox:
    cb = QComboBox()
    cb.addItems(list(items))
    if current:
        cb.setCurrentText(current)
    return cb


def line_input(placeholder: str = "") -> QLineEdit:
    le = QLineEdit()
    le.setPlaceholderText(placeholder)
    return le


def fmt_combo(items, current: str | None = None) -> QComboBox:
    cb = QComboBox()
    cb.addItems(list(items))
    if current:
        cb.setCurrentText(current)
    return cb


def row_layout(*widgets: QWidget, spacing: int = 8, stretch_last: bool = True) -> QHBoxLayout:
    h = QHBoxLayout()
    h.setSpacing(spacing)
    for index, widget in enumerate(widgets):
        if isinstance(widget, QWidget):
            h.addWidget(widget, 1 if (stretch_last and index == len(widgets) - 1) else 0)
    return h


def labeled(text: str, control: QWidget) -> QWidget:
    """小字段组合：标签 + 控件（垂直）。"""
    box = QWidget()
    v = QVBoxLayout(box)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(4)
    lab = QLabel(text)
    lab.setObjectName("fieldLabel")
    v.addWidget(lab)
    v.addWidget(control)
    return box


