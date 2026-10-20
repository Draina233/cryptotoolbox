"""A 类页面：密评分数计算（UI 复刻 cacscore：左右两栏 8 个层面、逐项勾选+得分、右侧总分）。"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QDoubleValidator, QFont
from PySide6.QtWidgets import (
    QButtonGroup,
    QWidget,
    QCheckBox,
    QLineEdit,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QRadioButton,
    QVBoxLayout,
)

from ...core import score
from ..widgets import primary_button, secondary_button
from .base import PageBase

LEVEL_OPTIONS = [("2", "二级系统"), ("3", "三级系统"), ("4", "四级系统")]


class ScorePage(PageBase):
    page_id = "score"
    title = "分数计算"
    subtitle = "勾选适用项并填写 0~1 得分（1=符合，0=不符合，0~1=部分符合；未勾选为不适用），计算总分与符合项数统计。"

    def build_ui(self) -> None:
        header = QFrame()
        header.setObjectName("card")
        outer = QVBoxLayout(header)
        outer.setContentsMargins(14, 8, 14, 8)
        outer.setSpacing(4)
        row1 = QHBoxLayout()
        row1.setSpacing(10)
        row1.addWidget(QLabel("系统等级："))
        self._level_group = QButtonGroup(self)
        self._level_radios = []
        level_box = QHBoxLayout()
        level_box.setSpacing(6)
        for index, (_key, label) in enumerate(LEVEL_OPTIONS):
            radio = QRadioButton(label)
            radio.setFocusPolicy(Qt.NoFocus)
            self._level_group.addButton(radio, index)
            self._level_radios.append(radio)
            level_box.addWidget(radio)
            if index == 1:
                radio.setChecked(True)
        self._level_group.idToggled.connect(self._on_level_changed)
        row1.addLayout(level_box)
        row1.addStretch(1)
        self._total = QLabel("总分：—")
        font = QFont()
        font.setPointSize(15)
        font.setBold(True)
        self._total.setFont(font)
        row1.addWidget(self._total)
        calc_btn = primary_button("计算得分", "play")
        calc_btn.setFocusPolicy(Qt.NoFocus)
        calc_btn.clicked.connect(self.do_calculate)
        row1.addWidget(calc_btn)
        outer.addLayout(row1)
        row2 = QHBoxLayout()
        row2.setSpacing(10)
        self._stats = QLabel("符合 — · 部分符合 — · 不符合 — · 不适用 —")
        self._stats.setObjectName("hintText")
        self._stats.setStyleSheet("font-size: 9pt;")
        row2.addWidget(self._stats)
        row2.addStretch(1)
        all_btn = secondary_button("全选适用")
        all_btn.clicked.connect(lambda: self._set_all(True))
        none_btn = secondary_button("全部不适用")
        none_btn.clicked.connect(lambda: self._set_all(False))
        reset_btn = secondary_button("恢复默认")
        reset_btn.clicked.connect(self._rebuild)
        for btn in (all_btn, none_btn, reset_btn):
            btn.setFocusPolicy(Qt.NoFocus)
            row2.addWidget(btn)
        outer.addLayout(row2)
        self.body.addWidget(header)

        columns = QHBoxLayout()
        columns.setSpacing(8)
        self._left = QVBoxLayout()
        self._left.setSpacing(4)
        self._right = QVBoxLayout()
        self._right.setSpacing(4)
        columns.addLayout(self._left, 1)
        columns.addLayout(self._right, 1)
        self.body.addLayout(columns)
        self._layers: list[dict] = []
        self._rebuild()

    # ------------------------------------------------------------ 构建
    def _level_key(self) -> str:
        checked = self._level_group.checkedId()
        return LEVEL_OPTIONS[max(0, checked)][0]

    def _on_level_changed(self, _id: int, checked: bool) -> None:
        if checked:
            self._rebuild()

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _make_layer(self, layer_index: int, layer: dict, weight: float) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        box = QVBoxLayout(card)
        box.setContentsMargins(10, 6, 10, 6)
        box.setSpacing(1)
        head = QHBoxLayout()
        head.setSpacing(6)
        title = QLabel(score.LAYER_TITLES[layer_index])
        bold = QFont()
        bold.setBold(True)
        title.setFont(bold)
        head.addWidget(title)
        weight_label = QLabel(f"权重 {weight:g}")
        weight_label.setObjectName("hintText")
        head.addWidget(weight_label)
        head.addStretch(1)
        value = QLabel("—")
        value.setMinimumWidth(70)
        value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        value.setFont(bold)
        head.addWidget(value)
        box.addLayout(head)
        rows = []
        for item in layer["items"]:
            row = QHBoxLayout()
            row.setSpacing(6)
            checkbox = QCheckBox(item["name"])
            checkbox.setFocusPolicy(Qt.NoFocus)
            small = QFont()
            small.setPointSize(8)
            checkbox.setFont(small)
            checkbox.setMinimumHeight(16)
            checkbox.setChecked(bool(item["default"]))
            checkbox.setToolTip(f"{item['name']}（权重 {item['weight']:g}）")
            row.addWidget(checkbox, 1)
            spin = QLineEdit("")
            spin.setValidator(QDoubleValidator(0.0, 1.0, 3, spin))
            spin.setFixedWidth(56)
            spin.setFixedHeight(18)
            spin.setFont(small)
            spin.setStyleSheet("padding: 0px 3px;")
            spin.setAlignment(Qt.AlignCenter)
            spin.setToolTip("符合程度 0~1（1=符合，0=不符合）")
            spin.setEnabled(checkbox.isChecked())
            checkbox.toggled.connect(spin.setEnabled)
            row.addWidget(spin, 0)
            box.addLayout(row)
            rows.append((checkbox, spin))
        self._layers.append({"index": layer_index, "value": value, "rows": rows})
        return card

    def _rebuild(self) -> None:
        self._clear_layout(self._left)
        self._clear_layout(self._right)
        self._layers = []
        level = self._level_key()
        data = score.LEVELS[level]
        for layer_index, layer in enumerate(data["layers"]):
            weight = data["total"][layer_index]["weight"]
            card = self._make_layer(layer_index, layer, weight)
            (self._left if layer_index < 4 else self._right).addWidget(card)
        self._left.addStretch(1)
        self._right.addStretch(1)
        self._total.setText("总分：—")
        self._stats.setText("符合 — · 部分符合 — · 不符合 — · 不适用 —")
        self._apply_tab_order()

    def _apply_tab_order(self) -> None:
        """Tab 只在得分输入框之间切换（勾选框/按钮不参与 Tab 链）。"""
        edits = [spin for layer in self._layers for _checkbox, spin in layer["rows"]]
        for first, second in zip(edits, edits[1:]):
            QWidget.setTabOrder(first, second)

    def _set_all(self, checked: bool) -> None:
        for layer in self._layers:
            for checkbox, _spin in layer["rows"]:
                checkbox.setChecked(checked)

    # ------------------------------------------------------------ 计算
    def do_calculate(self) -> None:
        level = self._level_key()
        layers = score.layer_items(level)
        scores: list[dict[int, float]] = [dict() for _ in layers]
        invalid: list[str] = []
        counts = {"符合": 0, "部分符合": 0, "不符合": 0, "不适用": 0}
        for layer in self._layers:
            layer_index = layer["index"]
            layer_name = score.LAYER_TITLES[layer_index]
            for item_index, (checkbox, edit) in enumerate(layer["rows"]):
                if not checkbox.isChecked():
                    counts["不适用"] += 1
                    continue
                text = edit.text().strip()
                try:
                    value = float(text)
                except ValueError:
                    value = None
                if value is None or not (0.0 <= value <= 1.0):
                    invalid.append(f"{layer_name}：{checkbox.text()}")
                    continue
                scores[layer_index][item_index] = value
                if value >= 1.0:
                    counts["符合"] += 1
                elif value <= 0.0:
                    counts["不符合"] += 1
                else:
                    counts["部分符合"] += 1
        if invalid:
            preview = "\n".join("• " + name for name in invalid[:8])
            extra = f"\n……共 {len(invalid)} 项" if len(invalid) > 8 else ""
            QMessageBox.warning(
                self, "得分未填写或无效",
                "以下适用项尚未填写有效得分（须为 0~1）：\n" + preview + extra,
            )
            return
        result = score.compute(level, scores)
        self._stats.setText(
            f"符合 {counts['符合']} 项 · 部分符合 {counts['部分符合']} 项 · "
            f"不符合 {counts['不符合']} 项 · 不适用 {counts['不适用']} 项"
        )
        for layer in self._layers:
            row = result["layers"][layer["index"]]
            layer["value"].setText(
                "不适用" if row["status"] == "不适用"
                else ("参数错误" if row["status"] == "参数错误" else f"{row['score']:.4f}")
            )
        if result["status"] != "ok":
            self._total.setText("总分：无法计算")
            self._total.setToolTip(
                "存在参数错误：得分须在 0~1 之间" if result["status"] == "参数错误"
                else "技术层面或管理层面全部为“不适用”，无法按权重汇总"
            )
            return
        self._total.setText(f"总分：{result['total']:.2f}")
        self._total.setToolTip(
            f"技术 {result['technical']:.4f}×{result['coef'][0]:g} + 管理 {result['management']:.4f}×{result['coef'][1]:g}"
            f" = {result['total']:.4f}（百分制）"
        )
        self.notify("分数计算完成")
