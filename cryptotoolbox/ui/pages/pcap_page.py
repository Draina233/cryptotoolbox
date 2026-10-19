"""C 类页面：PCAP 加密数据提取（纯 Python 解析，不依赖 Wireshark）。"""
from __future__ import annotations

import os

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QWidget,
)

from ...core import pcap
from ..widgets import (
    ActionBar,
    CopyButton,
    FilePicker,
    HintLabel,
    MonoText,
    TextInput,
    primary_button,
    secondary_button,
)
from .base import PageBase


def _table(headers: list[str], min_height: int = 140) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.horizontalHeader().setStretchLastSection(True)
    table.setMinimumHeight(min_height)
    return table


def _add_row(table: QTableWidget, values: list[str]) -> None:
    row = table.rowCount()
    table.insertRow(row)
    for col, value in enumerate(values):
        table.setItem(row, col, QTableWidgetItem(str(value)))


class PcapPage(PageBase):
    page_id = "pcap"
    title = "PCAP 加密数据提取"
    subtitle = "解析 pcap/pcapng：TLS/TLCP 握手、套件、证书与加密记录（保留记录边界）、ESP、IKE 证书。"

    def build_ui(self) -> None:
        card = self.card("抓包文件")
        self.picker = FilePicker("选择抓包文件", "抓包文件 (*.pcap *.pcapng *.cap);;所有文件 (*.*)")
        card.add(self.picker)
        ip_row = QWidget()
        h = QHBoxLayout(ip_row)
        h.setContentsMargins(0, 0, 0, 0)
        self.ip_src = QLineEdit()
        self.ip_src.setPlaceholderText("源 IP（可选）")
        self.ip_dst = QLineEdit()
        self.ip_dst.setPlaceholderText("目的 IP（可选，必须与源 IP 同时填写）")
        h.addWidget(QLabel("IP 筛选："))
        h.addWidget(self.ip_src)
        h.addWidget(QLabel("→"))
        h.addWidget(self.ip_dst)
        card.add(ip_row)
        self.include_tls = QCheckBox("解析 TLS/TLCP")
        self.include_tls.setChecked(True)
        self.include_esp = QCheckBox("提取 IPsec ESP")
        self.include_esp.setChecked(True)
        card.add_layout(QHBoxLayout())
        card.body.itemAt(card.body.count() - 1).layout().addWidget(self.include_tls)
        card.body.itemAt(card.body.count() - 1).layout().addWidget(self.include_esp)
        self.include_tls.setToolTip("TLS/TLCP 应用数据记录、握手、证书")
        analyze = primary_button("开始解析", "play")
        analyze.clicked.connect(self.do_analyze)
        card.add_layout(ActionBar(analyze))
        self.status = HintLabel("尚未解析")
        card.add(self.status)

        tabs = QTabWidget()
        self.handshake_table = _table(["类型", "方向", "版本", "详情"])
        self.cert_table = _table(["方向", "主题", "颁发者", "签名算法", "SHA-256"])
        self.record_table = _table(["协议", "方向", "记录信息", "载荷长度"])
        tabs.addTab(self.handshake_table, "握手与套件")
        tabs.addTab(self.cert_table, "证书")
        tabs.addTab(self.record_table, "加密记录")
        self.body.addWidget(tabs, 1)
        self.result = None
        self.body.addWidget(self._summary_card())

    def _summary_card(self):
        card = self.card("摘要与导出")
        self.summary = MonoText("解析摘要将显示在这里…", 120)
        card.add(self.summary)
        export_summary = secondary_button("导出摘要…", "export")
        export_summary.clicked.connect(self.export_summary)
        export_certs = secondary_button("导出证书…", "export")
        export_certs.clicked.connect(self.export_certs)
        export_payload = secondary_button("导出加密载荷…", "export")
        export_payload.clicked.connect(self.export_payload)
        card.add_layout(ActionBar(CopyButton(lambda: self.summary.toPlainText()), export_summary,
                                  export_certs, export_payload))
        return card

    def do_analyze(self) -> None:
        path = self.picker.path()
        if not path or not os.path.isfile(path):
            self.show_error("请先选择有效的抓包文件。")
            return
        src, dst = self.ip_src.text().strip(), self.ip_dst.text().strip()
        if bool(src) != bool(dst):
            self.show_error("IP 筛选需同时填写源 IP 与目的 IP，或同时留空。")
            return
        ip_filter = (src, dst) if src else None

        def work(progress=None, cancel=None):
            return pcap.analyze_capture(path, ip_filter=ip_filter,
                                        include_tls=self.include_tls.isChecked(),
                                        include_esp=self.include_esp.isChecked(),
                                        progress=progress, cancel=cancel)

        self.run_background(work, self._show_result, lambda exc: self.show_error(exc, "抓包解析失败"),
                            busy_text="正在解析抓包…", cancellable=True)

    def _show_result(self, result) -> None:
        self.result = result
        self.handshake_table.setRowCount(0)
        for hs in result.handshakes:
            details = []
            if hs.details.get("sni"):
                details.append("SNI=" + "、".join(hs.details["sni"]))
            if hs.details.get("selected_cipher"):
                details.append("选择套件=" + hs.details["selected_cipher"])
            if hs.details.get("supported_versions"):
                details.append("支持版本=" + "/".join(hs.details["supported_versions"]))
            _add_row(self.handshake_table, [hs.kind, f"{hs.source} → {hs.destination}", hs.version,
                                            "；".join(details)])
        self.cert_table.setRowCount(0)
        for cert in result.certificates:
            _add_row(self.cert_table, [f"{cert.source} → {cert.destination}", cert.subject, cert.issuer,
                                       cert.signature_algorithm, cert.sha256])
        self.record_table.setRowCount(0)
        for record in result.encrypted:
            _add_row(self.record_table, [record.protocol, f"{record.source} → {record.destination}",
                                         record.detail, len(record.payload)])
        for table in (self.handshake_table, self.cert_table, self.record_table):
            table.resizeColumnsToContents()
            if table.columnCount() > 1:
                table.setColumnWidth(1, max(table.columnWidth(1), 300))
        stats = result.stats
        lines = [
            f"报文总数：{stats.get('报文总数', 0)}",
            f"TCP 流：{stats.get('TCP 流数量', 0)}",
            f"握手消息：{len(result.handshakes)}",
            f"加密记录：{stats.get('加密记录数', 0)}",
            f"证书：{stats.get('证书数', 0)}",
            f"ESP 报文：{stats.get('ESP 报文数', 0)}",
            f"IKE 报文：{stats.get('IKE 报文数', 0)}",
            "",
            "密码套件：",
        ]
        suite_lines = []
        seen_suites = set()
        for hs in result.handshakes:
            pairs = list(hs.details.get("cipher_suites") or [])
            selected = hs.details.get("selected_cipher")
            if selected and selected not in pairs:
                pairs.append(selected)
            for suite in pairs:
                key = (hs.source, hs.destination, suite)
                if key in seen_suites:
                    continue
                seen_suites.add(key)
                suite_lines.append(f"  - {hs.source} → {hs.destination}: {suite}")
        lines += suite_lines if suite_lines else ["  （未发现）"]
        if result.warnings:
            lines += ["", "警告："] + [f"  - {w}" for w in result.warnings[:20]]
        self.summary.setPlainText("\n".join(lines))
        self.status.setText(f"解析完成：{stats.get('加密记录数', 0)} 条加密记录，{stats.get('证书数', 0)} 张证书。")
        self.notify("抓包解析完成")

    def _ensure_result(self) -> bool:
        if self.result is None:
            self.show_error("请先解析抓包文件。")
            return False
        return True

    def export_summary(self) -> None:
        if not self._ensure_result():
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出摘要", "capture-summary.txt", "文本 (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.summary.toPlainText())
            self.notify(f"摘要已导出：{path}")

    def export_certs(self) -> None:
        if not self._ensure_result() or not self.result.certificates:
            return
        directory = QFileDialog.getExistingDirectory(self, "导出证书目录")
        if not directory:
            return
        seen = set()
        count = 0
        for cert in self.result.certificates:
            if not cert.der or cert.sha256 in seen:
                continue
            seen.add(cert.sha256)
            safe_src = cert.source.replace(":", "-").replace("/", "_")
            safe_dst = cert.destination.replace(":", "-").replace("/", "_")
            name = f"{safe_src}-{safe_dst}-{cert.sha256[:16]}.der"
            with open(os.path.join(directory, name), "wb") as fh:
                fh.write(cert.der)
            count += 1
        self.notify(f"已导出 {count} 张证书（已按指纹去重）")

    def export_payload(self) -> None:
        if not self._ensure_result() or not self.result.encrypted:
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出加密载荷", "encrypted-payloads.bin",
                                              "二进制 (*.bin)")
        if not path:
            return
        with open(path, "wb") as fh:
            for record in self.result.encrypted:
                header = (f"=== {record.protocol} {record.source}:{record.sport} -> "
                          f"{record.destination}:{record.dport} {record.detail} ===\n").encode("utf-8")
                fh.write(header)
                fh.write(record.payload)
                fh.write(b"\n")
        self.notify(f"已导出加密载荷：{path}")

