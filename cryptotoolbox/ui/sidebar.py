"""左侧导航：品牌区 + 搜索 + 分组树 + 版本信息。"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from .pages import GROUPS
from .icons import make_icon
from . import state


class _BrandHeader(QFrame):
    clicked = Signal()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def eventFilter(self, watched, event):  # noqa: N802
        from PySide6.QtCore import QEvent

        if event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
            self.clicked.emit()
            return True
        return super().eventFilter(watched, event)


class _BrandLabel(QLabel):
    clicked = Signal()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class Sidebar(QFrame):
    page_selected = Signal(str)
    home_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(272)
        self._items: dict[str, QTreeWidgetItem] = {}
        self._group_items: dict[str, QTreeWidgetItem] = {}

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # 品牌区（可点击返回首页）
        self._brand = QFrame()
        self._brand.setObjectName("sidebarHeader")
        self._brand.setCursor(Qt.PointingHandCursor)
        self._brand.setToolTip("返回首页")
        header = self._brand
        for child in header.findChildren(QLabel):
            child.installEventFilter(header)
        hv = QVBoxLayout(header)
        hv.setContentsMargins(18, 16, 18, 14)
        hv.setSpacing(2)
        title = _BrandLabel(__app_name__)
        title.setObjectName("brandTitle")
        title.setCursor(Qt.PointingHandCursor)
        title.setToolTip("返回首页")
        title.clicked.connect(self.home_requested.emit)
        sub = _BrandLabel("离线密码评估与验证")
        sub.setObjectName("brandSub")
        sub.setCursor(Qt.PointingHandCursor)
        sub.clicked.connect(self.home_requested.emit)
        hv.addWidget(title)
        hv.addWidget(sub)
        v.addWidget(header)

        # 搜索
        search_box = QWidget()
        sv = QVBoxLayout(search_box)
        sv.setContentsMargins(12, 12, 12, 6)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索功能（Ctrl+F）")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.filter_items)
        sv.addWidget(self.search)
        v.addWidget(search_box)

        # 导航树
        self.tree = QTreeWidget()
        self.tree.setObjectName("navTree")
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(14)
        self.tree.setAnimated(True)
        self.tree.itemClicked.connect(self._on_click)
        v.addWidget(self.tree, 1)



        self._build()

    # ------------------------------------------------------------ 构建
    def _build(self) -> None:
        self.tree.clear()
        self._items.clear()
        self._group_items.clear()
        icon_color = "#8FA3BD"
        for group in GROUPS:
            top = QTreeWidgetItem(self.tree, [group.title])
            top.setIcon(0, make_icon(group.icon, icon_color, 16))
            top.setFlags(top.flags() & ~Qt.ItemIsSelectable)
            self._group_items[group.id] = top
            for spec in group.items:
                child = QTreeWidgetItem(top, [spec.title])
                child.setData(0, Qt.UserRole, spec.id)
                child.setToolTip(0, f"{group.title} / {spec.title}")
                self._items[spec.id] = child
                top.addChild(child)
            top.setExpanded(True)

    # ------------------------------------------------------------ 交互
    def _on_click(self, item: QTreeWidgetItem, _column: int) -> None:
        page_id = item.data(0, Qt.UserRole)
        if isinstance(page_id, str):
            self.page_selected.emit(page_id)

    def select(self, page_id: str) -> None:
        item = self._items.get(page_id)
        if item is None:
            return
        parent = item.parent()
        while parent is not None:
            parent.setExpanded(True)
            parent = parent.parent()
        self.tree.blockSignals(True)
        self.tree.setCurrentItem(item)
        self.tree.blockSignals(False)

    def filter_items(self, text: str) -> None:
        text = (text or "").strip().lower()
        any_match = False
        for group in GROUPS:
            top = self._group_items[group.id]
            child_match = False
            for spec in group.items:
                child = self._items[spec.id]
                haystack = f"{spec.title} {spec.keywords}".lower()
                visible = (not text) or text in haystack
                child.setHidden(not visible)
                if visible:
                    child_match = True
            top_visible = child_match or (bool(text) and text in group.title.lower())
            top.setHidden(not top_visible)
            top.setExpanded(True)
            if top_visible:
                any_match = True
        if text and not any_match:
            # 使用占位提示项
            if not hasattr(self, "_no_result"):
                self._no_result = QTreeWidgetItem(self.tree, ["未找到匹配的功能"])
                self._no_result.setFlags(self._no_result.flags() & ~Qt.ItemIsSelectable)
        elif hasattr(self, "_no_result"):
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(self._no_result))
            del self._no_result

