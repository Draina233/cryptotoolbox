"""E 类页面：随机性检测（参照 GMT_Randomness_Test 的布局与结果展示）。"""
from __future__ import annotations

import os
import time

import numpy as np
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QCheckBox,
    QDoubleSpinBox,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import randomness
from ..widgets import (
    ActionBar,
    Card,
    FilePicker,
    MonoText,
    combo,
    primary_button,
    secondary_button,
)
from .base import PageBase

# (界面键, 显示名称, 核心检测键)
METHODS = [
    ("monobit", "单比特频数", "monobit"),
    ("fwb", "块内频数", "fwb"),
    ("poker", "扑克检测", "poker"),
    ("serial", "重叠子序列检测", "serial"),
    ("runs", "游程总数检测", "runs"),
    ("runs_dist", "游程分布检测", "runs_dist"),
    ("longest_1", "块内最大1游程", "longest"),
    ("longest_0", "块内最大0游程", "longest"),
    ("bin_der", "二元推导检测", "binary_derivative"),
    ("autocorr", "自相关检测", "autocorrelation"),
    ("matrix", "矩阵秩检测", "matrix"),
    ("csum_fwd", "前向累加和检测", "csum"),
    ("csum_bwd", "后向累加和检测", "csum"),
    ("ae", "近似熵检测", "approximate_entropy"),
    ("lc", "线性复杂度检测", "linear_complexity"),
    ("maurer", "Maurer 通用统计", "maurer"),
    ("dft", "离散傅里叶变换", "dft"),
]
CORE_KEYS = sorted({core for _key, _label, core in METHODS})
MODE_OPTIONS = [
    ("20000", "20,000 bit"),
    ("1000000", "1,000,000 bit"),
    ("100000000", "100,000,000 bit"),
    ("auto", "自动（按长度）"),
    ("custom", "自定义参数"),
]


class RandomnessPage(PageBase):
    page_id = "randomness"
    title = "随机性检测"
    subtitle = "参照 GMT_Randomness_Test：左侧选择检测方法，中间输入数据/参数，右侧展示汇总与逐项明细（P/Q 值与判定）。"

    def build_ui(self) -> None:
        columns = QHBoxLayout()
        columns.setSpacing(8)
        columns.setAlignment(Qt.AlignTop)
        self.body.addLayout(columns)
        columns.addWidget(self._build_methods(), 0, Qt.AlignTop)
        columns.addWidget(self._build_input(), 0, Qt.AlignTop)
        columns.addWidget(self._build_results(), 1, Qt.AlignTop)
        self._rows: list[dict] = []
        self._set_mode_visible(False)

    # ------------------------------------------------------------ 左：方法
    def _build_methods(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("card")
        frame.setFixedWidth(210)
        frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        box = QVBoxLayout(frame)
        box.setContentsMargins(12, 10, 12, 10)
        box.setSpacing(3)
        title = QLabel("检测方法")
        bold = QFont()
        bold.setBold(True)
        title.setFont(bold)
        box.addWidget(title)
        self._method_boxes: list[tuple[str, str, QCheckBox]] = []
        for key, label, core in METHODS:
            box.addWidget(self._checkbox(label, key, core))
        box.addStretch(1)
        all_btn = secondary_button("全选")
        all_btn.clicked.connect(lambda: self._set_all(True))
        none_btn = secondary_button("全不选")
        none_btn.clicked.connect(lambda: self._set_all(False))
        box.addWidget(ActionBar(all_btn, none_btn))
        return frame

    def _checkbox(self, label: str, key: str, core: str) -> QCheckBox:
        box = QCheckBox(label)
        box.setChecked(True)
        font = QFont()
        font.setPointSize(8)
        box.setFont(font)
        self._method_boxes.append((key, core, box))
        return box

    def _set_all(self, checked: bool) -> None:
        for _key, _core, box in self._method_boxes:
            box.setChecked(checked)

    # ------------------------------------------------------------ 中：输入
    def _build_input(self) -> Card:
        card = self.card("检测数据", "输入 01 串或文件；选择参数模式")
        card.setFixedWidth(430)
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        card.body.setAlignment(Qt.AlignTop)
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        grid.setColumnMinimumWidth(0, 86)
        grid.setColumnStretch(1, 1)
        self.input_mode = combo(["文本输入", "文件输入"])
        self.input_mode.setMinimumWidth(210)
        grid.addWidget(QLabel("输入方式"), 0, 0)
        grid.addWidget(self.input_mode, 0, 1)

        self.stack = QStackedWidget()
        self.stack.setObjectName("inputStack")
        self.stack.setFixedHeight(220)
        self.input_mode.currentIndexChanged.connect(self.stack.setCurrentIndex)
        text_page = QWidget()
        text_page.setObjectName("inputPage")
        tv = QVBoxLayout(text_page)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.setSpacing(6)
        self.text_input = QPlainTextEdit()
        self.text_input.setPlaceholderText("输入 01 串，例如 01001101…（勾选“十六进制”时输入 HEX）")
        self.text_input.setFixedHeight(150)
        self.text_input.setObjectName("mono")
        tv.addWidget(self.text_input)
        hex_row = QHBoxLayout()
        self.hex_input = QCheckBox("十六进制")
        self.hex_input.setFont(self._small_font())
        hex_row.addWidget(self.hex_input)
        hex_row.addStretch(1)
        tv.addLayout(hex_row)
        gen = QHBoxLayout()
        gen.setSpacing(6)
        gen.addWidget(QLabel("生成长度"))
        self.gen_length = QSpinBox()
        self.gen_length.setRange(8, 20000000)
        self.gen_length.setSingleStep(1000)
        self.gen_length.setValue(20000)
        self.gen_length.setFixedWidth(86)
        gen.addWidget(self.gen_length)
        gen_btn = secondary_button("生成样本")
        gen_btn.setFixedWidth(80)
        gen_btn.clicked.connect(self.generate_sample)
        gen.addWidget(gen_btn)
        clear_btn = secondary_button("清空")
        clear_btn.setFixedWidth(56)
        clear_btn.clicked.connect(self.text_input.clear)
        gen.addWidget(clear_btn)
        tv.addLayout(gen)
        self.stack.addWidget(text_page)
        file_page = QWidget()
        file_page.setObjectName("inputPage")
        fv = QVBoxLayout(file_page)
        fv.setContentsMargins(0, 0, 0, 0)
        fv.setSpacing(6)
        fv.addWidget(QLabel("解析方式"))
        self.file_mode = combo(["二进制（每字节 8 bit）", "01 文本"])
        fv.addWidget(self.file_mode)
        self.picker = FilePicker("选择样本文件", "所有文件 (*.*)")
        fv.addWidget(self.picker)
        note = QLabel("文件在点击“开始检测”时读取；二进制文件按每字节 8 bit 展开。")
        note.setObjectName("hintText")
        note.setWordWrap(True)
        fv.addWidget(note)
        fv.addStretch(1)
        self.stack.addWidget(file_page)
        grid.addWidget(self.stack, 1, 0, 1, 2)

        grid.addWidget(QLabel("显著性水平 α"), 2, 0)
        self.alpha = QDoubleSpinBox()
        self.alpha.setRange(0.000001, 0.999999)
        self.alpha.setDecimals(4)
        self.alpha.setSingleStep(0.001)
        self.alpha.setValue(0.01)
        self.alpha.setFixedWidth(104)
        grid.addWidget(self.alpha, 2, 1, Qt.AlignLeft)

        grid.addWidget(QLabel("检测模式"), 3, 0)
        self.mode = combo([label for _key, label in MODE_OPTIONS], "自动（按长度）")
        self.mode.setMinimumWidth(196)
        self.mode.currentIndexChanged.connect(lambda _i: self._set_mode_visible(self._mode_key() == "custom"))
        grid.addWidget(self.mode, 3, 1, Qt.AlignLeft)

        self.custom_box = QWidget()
        self.custom_box.setObjectName("inputPage")
        custom_grid = QGridLayout(self.custom_box)
        custom_grid.setContentsMargins(0, 0, 0, 0)
        custom_grid.setSpacing(4)
        self.custom_spins: dict[str, QSpinBox] = {}
        for col, (key, label) in enumerate([("m", "m"), ("k", "k"), ("d", "d"), ("L", "L"), ("Q", "Q")]):
            spin = QSpinBox()
            spin.setRange(0, 1000000)
            spin.setValue(0)
            spin.setSpecialValueText("默认")
            self.custom_spins[key] = spin
            custom_grid.addWidget(QLabel(label), 0, col)
            custom_grid.addWidget(spin, 1, col)
        grid.addWidget(self.custom_box, 4, 0, 1, 2)

        hint = QLabel("1,000,000 / 100,000,000 bit 模式全项检测耗时较长，可点击“取消”。")
        hint.setObjectName("hintText")
        hint.setWordWrap(True)
        grid.addWidget(hint, 5, 0, 1, 2)

        self.run_btn = primary_button("开始检测", "play")
        self.run_btn.clicked.connect(self.do_run)
        self.cancel_btn = secondary_button("取消")
        self.cancel_btn.clicked.connect(self._cancel)
        self.cancel_btn.setEnabled(False)
        grid.addWidget(ActionBar(self.run_btn, self.cancel_btn), 6, 0, 1, 2)
        grid.setRowStretch(5, 1)
        card.add_layout(grid)
        return card

    @staticmethod
    def _small_font() -> QFont:
        font = QFont()
        font.setPointSize(9)
        return font

    def _set_mode_visible(self, visible: bool) -> None:
        self.custom_box.setVisible(visible)

    def _mode_key(self) -> str:
        return MODE_OPTIONS[self.mode.currentIndex()][0]

    def _cancel(self) -> None:
        if self.window_ref is not None:
            self.window_ref._cancel_task()

    # ------------------------------------------------------------ 右：结果
    def _build_results(self) -> Card:
        card = self.card("检测结果", "汇总与逐项明细（选中行查看详情）")
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self.summary = MonoText("尚未检测。输入数据后点击“开始检测”。", 78)
        card.add(self.summary)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["序号", "检测项目", "结果", "P 值", "Q 值"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setWordWrap(False)
        for col, width in ((0, 40), (1, 160), (2, 52), (3, 90), (4, 90)):
            self.table.setColumnWidth(col, width)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setMinimumHeight(280)
        self.table.itemSelectionChanged.connect(self._show_detail)
        card.add(self.table)
        self.detail = MonoText("选择结果行查看参数、P/Q 值、判定阈值与说明。", 100)
        card.add(self.detail)
        copy_btn = secondary_button("复制结果", "copy")
        copy_btn.clicked.connect(self.copy_results)
        card.add_layout(ActionBar(copy_btn))
        return card

    # ------------------------------------------------------------ 输入解析
    def generate_sample(self) -> None:
        length = int(self.gen_length.value())
        rng = np.random.default_rng()
        bits = "".join(rng.integers(0, 2, size=length).astype(str).tolist())
        self.text_input.setPlainText(bits)
        self.notify(f"已生成 {length} bit 随机样本")

    def _read_bits(self) -> str:
        if self.input_mode.currentText() == "文本输入":
            text = self.text_input.toPlainText().strip()
            if not text:
                raise ValueError("输入不能为空。")
            if self.hex_input.isChecked():
                from ...core.encodings import hex_decode

                data = hex_decode(text)
                return "".join(f"{byte:08b}" for byte in data)
            text = "".join(text.split())
            if any(ch not in "01" for ch in text):
                raise ValueError("输入只能为 0/1 串（勾选十六进制时输入 HEX）。")
            return text
        path = self.picker.path()
        if not path or not os.path.isfile(path):
            raise ValueError("请选择有效的样本文件。")
        data = open(path, "rb").read()
        if self.file_mode.currentText().startswith("二进制"):
            return "".join(f"{byte:08b}" for byte in data)
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("文件不是 01 文本或 UTF-8 编码。") from exc
        text = "".join(text.split())
        if any(ch not in "01" for ch in text):
            raise ValueError("文件内容只能为 0/1 串。")
        return text

    def _custom_params(self) -> dict:
        if self._mode_key() != "custom":
            return {}
        return {key: spin.value() for key, spin in self.custom_spins.items() if spin.value() > 0}

    # ------------------------------------------------------------ 运行
    def do_run(self) -> None:
        try:
            bits = self._read_bits()
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "样本读取失败")
            return
        selected = [(key, core) for key, core, box in self._method_boxes if box.isChecked()]
        if not selected:
            self.show_error("请至少选择一种检测方法。")
            return
        alpha = float(self.alpha.value())
        if len(bits) >= 1000000:
            from PySide6.QtWidgets import QMessageBox

            answer = QMessageBox.question(
                self, "样本较大",
                f"当前样本 {len(bits):,} bit，全项检测可能耗时数分钟（1M/100M 模式下线性复杂度等项较慢）。\n是否继续？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            )
            if answer != QMessageBox.Yes:
                return
        mode = self._mode_key()
        custom = self._custom_params()
        n = len(bits)
        params = randomness.params_for_mode(mode, n, custom)
        arr = np.frombuffer(bits.encode("ascii"), dtype=np.uint8) - ord("0")
        core_keys = sorted({core for _key, core in selected})

        def work(progress=None, cancel=None):
            started = time.time()

            def report(index, total, key):
                if progress:
                    percent = int(index * 100 / max(1, total))
                    progress(percent, f"正在检测：{key}")

            items = randomness.run_all(arr, n, only=core_keys, progress=report,
                                       cancel=cancel, params=params)
            elapsed = time.time() - started
            rows = self._flatten(items, selected, params, alpha, mode)
            return {"rows": rows, "elapsed": elapsed, "length": n, "alpha": alpha,
                    "mode": mode, "cancelled": bool(cancel and cancel.is_set())}

        self.run_background(work, self._show_result,
                            lambda exc: self.show_error(exc, "随机性检测失败"),
                            busy_text="正在执行随机性检测…", cancellable=True,
                            on_progress=(lambda percent, msg: self.window_ref.status_label.setText(msg))
                            if self.window_ref else None)
        self.run_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

    def _show_result(self, result) -> None:
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        rows = result["rows"]
        self._rows = rows
        self.table.setRowCount(0)
        passed = failed = errors = skipped = 0
        for row in rows:
            index = self.table.rowCount()
            self.table.insertRow(index)
            status = row["status"]
            if status == "通过":
                passed += 1
            elif status == "失败":
                failed += 1
            elif status == "跳过":
                skipped += 1
            else:
                errors += 1
            values = [str(index + 1), row["name"], status, row["p"], row["q"]]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 2:
                    color = {"通过": "#15803D", "失败": "#B91C1C", "跳过": "#64748B"}.get(status, "#B45309")
                    item.setForeground(QColor(color))
                if col in (0, 2, 3, 4):
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(index, col, item)
        mode_label = dict(MODE_OPTIONS)[result["mode"]]
        note = ""
        if result["mode"] == "100000000":
            note = "\n100M 模式：线性复杂度与 Maurer 通用统计因耗时过长未启用。"
        self.table.scrollToTop()
        self.summary.setPlainText(
            f"输入长度：{result['length']} bit\n"
            f"花费时间：{result['elapsed']:.4f} 秒\n"
            f"检测模式：{mode_label}；显著性水平 α = {result['alpha']:g}\n"
            f"通过：{passed}    失败：{failed}    错误：{errors}    跳过：{skipped}"
            + ("\n已取消（结果为已完成部分）。" if result.get("cancelled") else "")
            + note
        )
        self.notify("随机性检测完成")

    def _flatten(self, items, selected: list[tuple[str, str]], params: dict,
                 alpha: float, mode: str) -> list[dict]:
        wanted_longest = {key for key, _core in selected if key in ("longest_1", "longest_0")}
        wanted_csum = {key for key, _core in selected if key in ("csum_fwd", "csum_bwd")}
        serial: dict[str, dict] = {}
        rows: list[dict] = []
        for item in items:
            key = item.key
            if key.startswith("serial_"):
                m = key.split("_")[1]
                entry = serial.setdefault(m, {"p": [], "q": [], "error": "", "skipped": False})
                entry["p"].extend(item.p_values)
                entry["q"].extend(item.q_values)
                entry["error"] = entry["error"] or item.error
                entry["skipped"] = entry["skipped"] or item.skipped
                continue
            if key in ("longest_1", "longest_0"):
                if key not in wanted_longest:
                    continue
                name = "块内最大1游程" if key.endswith("_1") else "块内最大0游程"
                rows.append(self._row(name, item.p_values, item.q_values,
                                      f"M={params.get('longest_m')}", item, alpha))
                continue
            if key in ("csum_fwd", "csum_bwd"):
                if key not in wanted_csum:
                    continue
                name = "前向累加和检测" if key.endswith("fwd") else "后向累加和检测"
                rows.append(self._row(name, item.p_values, item.q_values, "—", item, alpha))
                continue
            name, param_text = self._name_and_params(key, params)
            if name is None:
                continue
            rows.append(self._row(name, item.p_values, item.q_values, param_text, item, alpha))
        for m, entry in sorted(serial.items(), key=lambda kv: int(kv[0])):
            p = min(entry["p"]) if entry["p"] else None
            q = min(entry["q"]) if entry["q"] else None
            error = entry["error"]
            skipped = entry["skipped"] or not entry["p"]
            if error:
                status = "错误"
            elif skipped:
                status = "跳过"
            elif p is not None and p >= alpha:
                status = "通过"
            else:
                status = "失败"
            rows.append({
                "name": "重叠子序列检测", "status": status,
                "p": f"{p:.6f}" if p is not None else "—",
                "q": f"{q:.6f}" if q is not None else "—",
                "params": f"m={m}",
                "detail": error or "取 m、m-1、m-2 统计量对应的较小 P 值判定。",
            })
        names = {row["name"] for row in rows}
        for key, _core in selected:
            label = {"lc": "线性复杂度检测", "maurer": "Maurer 通用统计", "matrix": "矩阵秩检测"}.get(key)
            if label and label not in names:
                rows.append({
                    "name": label, "status": "跳过", "p": "—", "q": "—", "params": "—",
                    "detail": ("100M 模式未启用该检测项（纯 Python 实现耗时过长）。"
                               if mode == "100000000"
                               else "当前参数模式或样本长度下未启用该检测项。"),
                })
        return rows

    def _row(self, name: str, p_values: list[float], q_values: list[float],
             params_text: str, item, alpha: float) -> dict:
        p = min(p_values) if p_values else None
        q = min(q_values) if q_values else None
        if getattr(item, "skipped", False):
            status = "跳过"
        elif item.error:
            status = "错误"
        else:
            status = "通过" if (p is not None and p >= alpha) else "失败"
        detail = item.error or "P ≥ α 判定为通过；P < α 判定为失败。"
        return {
            "name": name, "status": status,
            "p": f"{p:.6f}" if p is not None else "—",
            "q": f"{q:.6f}" if q is not None else "—",
            "params": params_text, "detail": detail,
        }

    @staticmethod
    def _name_and_params(key: str, params: dict) -> tuple[str | None, str]:
        if key == "monobit":
            return "单比特频数", "—"
        if key == "fwb":
            return "块内频数", f"m={params.get('fwb_m')}"
        if key.startswith("poker_"):
            return "扑克检测", f"m={key.split('_')[1]}"
        if key.startswith("bin_der_"):
            return "二元推导检测", f"k={key.split('_')[-1]}"
        if key.startswith("autocorr_"):
            return "自相关检测", f"d={key.split('_')[-1]}"
        if key.startswith("ae_"):
            return "近似熵检测", f"m={key.split('_')[-1]}"
        if key.startswith("lc_"):
            return "线性复杂度检测", f"M={key.split('_')[-1]}"
        if key == "maurer":
            maurer = params.get("maurer") or (7, 1280)
            return "Maurer 通用统计", f"L={maurer[0]}, Q={maurer[1]}"
        if key == "matrix":
            return "矩阵秩检测", "32×32"
        if key == "runs":
            return "游程总数检测", "—"
        if key == "runs_dist":
            return "游程分布检测", "—"
        if key == "dft":
            return "离散傅里叶变换", "—"
        return None, ""

    def _show_detail(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected or not self._rows:
            return
        index = selected[0].row()
        if index >= len(self._rows):
            return
        row = self._rows[index]
        self.detail.setPlainText(
            f"检测项目：{row['name']}\n参数：{row['params']}\n"
            f"P 值：{row['p']}\nQ 值：{row['q']}\n结果：{row['status']}\n"
            f"说明：{row['detail']}"
        )

    def copy_results(self) -> None:
        if not self._rows:
            return
        lines = [self.summary.toPlainText(), "", "序号\t检测项目\t结果\tP值\tQ值\t参数"]
        for index, row in enumerate(self._rows, start=1):
            lines.append(f"{index}\t{row['name']}\t{row['status']}\t{row['p']}\t{row['q']}\t{row['params']}")
        QApplication.clipboard().setText("\n".join(lines))
        self.notify("结果已复制到剪贴板")
