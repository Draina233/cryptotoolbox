"""F 类页面：电子签章校验（PDF / OFD）。"""
from __future__ import annotations

import os
import zipfile

from PySide6.QtWidgets import QTabWidget

from ...core import seal
from ..widgets import (
    ActionBar,
    DropArea,
    FilePicker,
    HintLabel,
    ResultPanel,
    TextInput,
    primary_button,
)
from .base import PageBase


class SealPage(PageBase):
    page_id = "seal"
    title = "电子签章校验"
    subtitle = "PDF（CMS/PKCS#7 嵌入式签名）与 OFD（Seal.esl + SignedValue）；支持 RSA / ECDSA / SM2。"

    def build_ui(self) -> None:
        card = self.card("待校验文件")
        self.drop = DropArea("把 PDF / OFD 文件拖到这里，或点击选择",
                             "支持 .pdf 与 .ofd；文件大小上限 60MB", "签章文件 (*.pdf *.ofd);;所有文件 (*.*)")
        self.drop.file_dropped.connect(self._on_file)
        card.add(self.drop)
        self.picker = FilePicker("选择签章文件", "签章文件 (*.pdf *.ofd);;所有文件 (*.*)")
        self.picker.file_selected.connect(self._on_file)
        card.add(self.picker)
        verify = primary_button("开始校验", "play")
        verify.clicked.connect(self.do_verify)
        card.add_layout(ActionBar(verify))
        self.status = HintLabel("尚未校验")
        card.add(self.status)
        self.tabs = QTabWidget()
        self.tabs.setMinimumHeight(320)
        self.body.addWidget(self.tabs, 1)
        self._panels: list[ResultPanel] = []

    def _on_file(self, path: str) -> None:
        self.picker.path_edit.setText(path)
        self.picker.file = path
        self.status.setText(f"已选择：{path}")

    def do_verify(self) -> None:
        path = self.picker.path()
        if not path or not os.path.isfile(path):
            self.show_error("请先选择有效的 PDF / OFD 文件。")
            return
        if not path.lower().endswith((".pdf", ".ofd")):
            self.show_error("仅支持 .pdf 或 .ofd 文件。")
            return

        def work():
            return seal.verify_seal_file(path)

        self.run_background(work, self._show_reports, lambda exc: self.show_error(exc, "签章校验失败"),
                            busy_text="正在解析电子签章…")

    def _show_reports(self, reports) -> None:
        self.tabs.clear()
        self._panels = []
        for index, report in enumerate(reports):
            panel = ResultPanel(report.title)
            panel.render(report)
            self._panels.append(panel)
            self.tabs.addTab(panel, f"签章 {index + 1}")
        total_ok = sum(1 for report in reports if report.verdict() == "pass")
        self.status.setText(f"校验完成：{len(reports)} 个签章，{total_ok} 个通过。")
        self.notify("电子签章校验完成")
