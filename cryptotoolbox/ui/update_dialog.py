"""发现新版本时的提示对话框。"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)

from ..update_check import ReleaseInfo
from .assets import app_icon_path


class UpdateDialog(QDialog):
    def __init__(self, info: ReleaseInfo, current_version: str, parent=None):
        super().__init__(parent)
        self.info = info
        self.setWindowTitle("发现新版本")
        self.setWindowIcon(QIcon(app_icon_path()))
        self.setMinimumWidth(540)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 16)
        layout.setSpacing(10)

        top = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QPixmap(app_icon_path("app_icon_128.png")).scaled(
            56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        icon.setFixedSize(56, 56)
        top.addWidget(icon)
        title_box = QVBoxLayout()
        title = QLabel(f"发现新版本 {info.version}" + ("（预发布）" if info.prerelease else ""))
        font = QFont()
        font.setPointSize(13)
        font.setBold(True)
        title.setFont(font)
        title_box.addWidget(title)
        subtitle = QLabel(f"当前版本 {current_version} → 最新版本 {info.version}")
        subtitle.setObjectName("hintText")
        title_box.addWidget(subtitle)
        if info.published_at:
            time_label = QLabel(f"发布时间：{info.published_at[:19].replace('T', ' ')}")
            time_label.setObjectName("hintText")
            title_box.addWidget(time_label)
        top.addLayout(title_box, 1)
        layout.addLayout(top)

        if info.prerelease:
            pre = QLabel("该版本为 Pre-release（预发布）版本，可能还不够稳定；如非必要请等待正式版。")
            pre.setObjectName("hintText")
            pre.setWordWrap(True)
            layout.addWidget(pre)

        notes = QTextBrowser()
        notes.setOpenExternalLinks(True)
        notes.setReadOnly(True)
        notes.setMinimumHeight(160)
        notes.setMaximumHeight(240)
        body = info.notes or "该版本没有填写更新说明。"
        if len(body) > 4000:
            body = body[:4000] + "\n…（更新说明过长已截断）"
        notes.setPlainText(body)
        layout.addWidget(notes)

        link = QLabel(f'<a href="{info.html_url}">{info.html_url}</a>')
        link.setOpenExternalLinks(False)
        link.setTextInteractionFlags(Qt.TextBrowserInteraction)
        link.setWordWrap(True)
        link.setToolTip("点击复制下载链接")
        link.linkActivated.connect(lambda _url: self._copy_link())
        layout.addWidget(link)
        tip = QLabel("点击“复制链接”后，用浏览器打开下载页。")
        tip.setObjectName("hintText")
        self._tip_label = tip
        layout.addWidget(tip)

        buttons = QDialogButtonBox()
        copy_link = QPushButton("复制链接")
        copy_link.setObjectName("primary")
        copy_link.clicked.connect(self._copy_link)
        later = QPushButton("稍后再说")
        later.setObjectName("secondary")
        later.clicked.connect(self.reject)
        buttons.addButton(copy_link, QDialogButtonBox.AcceptRole)
        buttons.addButton(later, QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self._on_copy)
        layout.addWidget(buttons)

    def _copy_link(self) -> None:
        QApplication.clipboard().setText(self.info.html_url)
        tip = getattr(self, "_tip_label", None)
        if tip is not None:
            tip.setText("链接已复制到剪贴板，请在浏览器中打开。")

    def _on_copy(self) -> None:
        self._copy_link()
        self.accept()
