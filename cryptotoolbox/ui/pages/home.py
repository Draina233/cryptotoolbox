"""首页：产品介绍、快捷入口与版本信息。"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ... import __version__, __app_name__
from ..icons import make_icon
from .. import state
from ..widgets import Card, HintLabel
from .base import PageBase


class _QuickCard(QFrame):
    clicked = Signal(str)

    def __init__(self, icon: str, title: str, desc: str, page_id: str):
        super().__init__()
        self._page_id = page_id
        self.setObjectName("card")
        self.setCursor(Qt.PointingHandCursor)
        v = QVBoxLayout(self)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(6)
        row = QHBoxLayout()
        row.setSpacing(8)
        self._icon_label = QLabel()
        self._icon_label.setPixmap(make_icon(icon, state.palette()["primary"], 20).pixmap(20, 20))
        self._icon_name = icon
        row.addWidget(self._icon_label)
        t = QLabel(title)
        t.setObjectName("sectionTitle")
        row.addWidget(t)
        row.addStretch(1)
        v.addLayout(row)
        d = HintLabel(desc)
        v.addWidget(d)
        self.setMinimumHeight(88)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self._page_id)
        super().mousePressEvent(event)


class HomePage(PageBase):
    page_id = "home"
    title = f"欢迎使用{__app_name__}"
    subtitle = "面向商用密码应用安全性评估的离线验证工具：算法校验、证书与签章核验、协议取证、随机性检测。"

    navigate = Signal(str)

    def build_ui(self) -> None:
        self._build_hero()
        self._build_quick()
        self._build_basics()

    def _build_hero(self) -> None:
        hero = QFrame()
        hero.setObjectName("heroCard")
        v = QVBoxLayout(hero)
        v.setContentsMargins(24, 20, 24, 20)
        v.setSpacing(8)
        title = QLabel(f"{__app_name__} · 离线密码评估与验证")
        title.setStyleSheet("color: #FFFFFF; font-size: 20px; font-weight: 700; background: transparent;")
        v.addWidget(title)
        desc = QLabel(
            "所有运算均在本机完成，算法实现以国家标准与官方向量为准，"
            "结果仅供参考，严肃生产场景请使用其他工具进行交叉验证。"
            "如有BUG或建议欢迎通过邮箱或Github Issues反馈。"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #E3EEFF; font-size: 13px; background: transparent;")
        v.addWidget(desc)
        chips = QHBoxLayout()
        chips.setSpacing(8)
        for text in ("离线运行", "国密算法", "官方标准", "结果可导出"):
            chip = QLabel(text)
            chip.setStyleSheet(
                "background: rgba(255,255,255,0.16); color: #FFFFFF; border-radius: 10px;"
                " padding: 3px 12px; font-size: 12px;"
            )
            chips.addWidget(chip)
        chips.addStretch(1)
        v.addLayout(chips)
        self.body.addWidget(hero)

    def refresh_theme(self) -> None:
        # 强调色变化后刷新快捷入口图标
        for child in self.findChildren(QWidget):
            if hasattr(child, "_icon_label") and hasattr(child, "_icon_name"):
                child._icon_label.setPixmap(
                    make_icon(child._icon_name, state.palette()["primary"], 20).pixmap(20, 20)
                )

    def _build_quick(self) -> None:
        card = self.card("快捷入口", "从常用功能开始")
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        entries = [
            ("check", "分数计算", "商用密码应用安全性评估量化评估规则(2023版)", "score"),
            ("tools", "常见编码转换", "HEX / Base64 / 文本互转与字节分析", "encodings"),
            ("lock", "SM2 签名验签", "支持自定义用户标识（UID）的国密签名", "sm2_sign"),
            ("cert", "证书链验证", "逐级验签、CA 与有效期检查", "certchain"),
            ("dice", "随机性检测", "GM/T 0005-2021 全套检测", "randomness"),
            ("seal", "电子签章校验", "PDF / OFD 签章验签与合规项", "seal"),
        ]
        for i, (icon, title, desc, pid) in enumerate(entries):
            c = _QuickCard(icon, title, desc, pid)
            c.clicked.connect(self.navigate.emit)
            grid.addWidget(c, i // 3, i % 3)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)
        card.add_layout(grid)

    def _build_basics(self) -> None:
        card = self.card("使用提示")
        tips = [
            "左侧按“常用工具 / 密码算法校验 / 协议分析 / 数字证书 / 随机数检测 / 电子签章”分组，点击即打开；Ctrl+F 可快速搜索。",
            "输入框支持粘贴十六进制、Base64、PEM 文本；支持宽松模式。",
            "耗时操作（证书链、大文件签章、批量随机性检测、抓包解析）在后台线程执行，可查看进度并取消。",
            "每个结果页都可以“复制结果”或“导出报告（JSON / TXT / HTML）”，便于评估记录留存。",
        ]
        for t in tips:
            lab = HintLabel("· " + t)
            card.add(lab)

        info = Card("版本与依赖")
        info.add(HintLabel(
            f"版本 {__version__} ｜ 核心算法：gmalg（SM2/SM3/SM4/SM9/ZUC）、tongsuopy（SM3/SM4 高速实现）、"
            "pycryptodome（AES/DES/RSA）、pypdf（PDF 解析）；ASN.1 解析自实现，支持国密 SM2 证书。"
        ))
        info.add(HintLabel(
            "开发者：Draina ｜ 联系方式：draina@qq.com ｜ "
            "https://github.com/Draina233"
        ))
        self.body.addWidget(info)
