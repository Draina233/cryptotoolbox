"""A 类页面：常见编码转换、密文长度分析、P7 签名数据解析。"""
from __future__ import annotations

import math

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core import encodings, pkcs7
from ...core.digest import DIGEST_SIZES
from ...core.result import FAIL, PASS, SKIP, UNKNOWN, Report
from .. import state
from ..widgets import (
    ActionBar,
    CopyButton,
    FilePicker,
    HintLabel,
    MonoText,
    ResultPanel,
    TextInput,
    combo,
    fmt_combo,
    primary_button,
    secondary_button,
)
from .base import PageBase


class EncodingsPage(PageBase):
    page_id = "encodings"
    title = "常见编码转换"
    subtitle = "十六进制 / Base64 / Base32 / URL / 文本互转、英文大小写、去空格、字符反转、URL编解码、长度统计等等....。"

    def build_ui(self) -> None:
        card = self.card("格式转换", "输入格式 → 输出格式")
        self.in_fmt = fmt_combo(encodings.DATA_FORMATS)
        self.out_fmt = fmt_combo(encodings.DATA_FORMATS, "Base64")
        card.add_row("输入格式", self.in_fmt)
        self.in_text = TextInput("在此粘贴数据…", 120, mono=True)
        card.add(self.in_text)
        card.add_row("输出格式", self.out_fmt)
        self.output = MonoText("转换结果将显示在这里…", 120)
        card.add(self.output)
        convert = primary_button("格式转换", "play")
        convert.clicked.connect(self.do_convert)
        swap = secondary_button("用输出作为输入")
        swap.clicked.connect(self.do_swap)
        clear = secondary_button("清空")
        clear.clicked.connect(self.do_clear)
        card.add_layout(ActionBar(convert, swap, clear, CopyButton(lambda: self.output.toPlainText())))

        text_card = self.card("文本快捷处理")
        self.text_input = TextInput("输入文本，或先用上方格式转换的结果", 80)
        text_card.add(self.text_input)
        self.op = combo(["大写", "小写", "去除空白", "反转字符", "URL 编码", "URL 解码",
                         "字节十进制", "Unicode 码点", "长度统计"])
        text_card.add_row("处理方式", self.op)
        run_op = primary_button("执行文本处理")
        run_op.clicked.connect(self.do_text_op)
        text_card.add_layout(ActionBar(run_op, secondary_button("复制结果", "copy"),
                                       CopyButton(lambda: self.text_output.toPlainText())))
        self.text_output = MonoText("处理结果将显示在这里…", 80)
        text_card.add(self.text_output)

        note = self.card("说明")
        note.add_note("十六进制输入允许空格、冒号、逗号、分号、下划线与 0x 前缀；长度为奇数会报错，不再自动补 0。")
        note.add_note("Base64 默认严格校验字符集与长度；将“宽松模式”勾选后会补全 padding 并忽略非法字符。")
        self.lenient = QCheckBox("Base64 / Base32 宽松模式")
        note.add(self.lenient)

    def do_convert(self) -> None:
        try:
            data = encodings.decode(self.in_text.toPlainText(), self.in_fmt.currentText(),
                                    strict=not self.lenient.isChecked())
            text = encodings.encode(data, self.out_fmt.currentText())
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "格式转换失败")
            return
        self.output.setPlainText(f"{text}\n\n[字节长度] {len(data)} 字节（{len(data) * 8} bit）")
        self.notify(f"转换完成：{len(data)} 字节")

    def do_swap(self) -> None:
        text = self.output.toPlainText().split("\n\n[字节长度]")[0]
        if not text:
            return
        self.in_text.setPlainText(text)
        self.in_fmt.setCurrentText(self.out_fmt.currentText())
        self.notify("已将输出填入输入框")

    def do_clear(self) -> None:
        self.in_text.clear()
        self.output.clear()

    def do_text_op(self) -> None:
        text = self.text_input.toPlainText()
        op = self.op.currentText()
        try:
            if op == "大写":
                result = text.upper()
            elif op == "小写":
                result = text.lower()
            elif op == "去除空白":
                result = "".join(text.split())
            elif op == "反转字符":
                result = text[::-1]
            elif op == "URL 编码":
                result = encodings.url_encode(text.encode("utf-8"))
            elif op == "URL 解码":
                result = encodings.url_decode(text).decode("utf-8")
            elif op == "字节十进制":
                raw = encodings.decode(text, self.in_fmt.currentText())
                result = " ".join(str(b) for b in raw)
            elif op == "Unicode 码点":
                result = " ".join(f"U+{ord(ch):04X}" for ch in text)
            else:
                lines = [f"字符数：{len(text)}", f"UTF-8 字节数：{len(text.encode('utf-8'))}",
                         f"行数：{len(text.splitlines()) or 1}"]
                result = "\n".join(lines)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "文本处理失败")
            return
        self.text_output.setPlainText(result)


class CipherLengthPage(PageBase):
    page_id = "length"
    title = "密文长度分析"
    subtitle = "根据长度与结构特征推断输入数据可能由何种算法类型产生。"

    def build_ui(self) -> None:
        card = self.card("待分析数据")
        self.in_fmt = fmt_combo(encodings.DATA_FORMATS)
        card.add_row("输入格式", self.in_fmt)
        self.input = TextInput("粘贴密文（十六进制 / Base64 / 文本）…", 110, mono=True)
        card.add(self.input)
        analyze = primary_button("分析", "play")
        analyze.clicked.connect(self.do_analyze)
        card.add_layout(ActionBar(analyze, secondary_button("清空"), CopyButton(lambda: self.report_text)))
        self.panel = ResultPanel("分析结果")
        self.body.addWidget(self.panel)
        self.report_text = ""

    def do_analyze(self) -> None:
        try:
            data = encodings.decode(self.input.toPlainText(), self.in_fmt.currentText(),
                                    strict=not False)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "数据解析失败")
            return
        report = self._analyze(data)
        self.report_text = report.to_text()
        self.panel.render(report)
        self.notify(f"分析完成：{len(data)} 字节")

    def _analyze(self, data: bytes) -> Report:
        report = Report(title="密文长度分析")
        report.meta["字节长度"] = len(data)
        report.meta["比特长度"] = len(data) * 8
        report.note("本页为启发式分析，仅依据长度与首字节特征推断，不能替代真实算法识别。")
        digest_matches = [name for name, size in DIGEST_SIZES.items() if size == len(data)]
        if digest_matches:
            report.add("digest", "摘要长度匹配", PASS, "、".join(digest_matches) + " 的输出长度")
        else:
            report.add("digest", "摘要长度匹配", UNKNOWN,
                       f"未与常见摘要输出长度（{', '.join(str(v) for v in sorted(set(DIGEST_SIZES.values())))}）匹配")
        if len(data) % 16 == 0:
            report.add("block16", "16 字节分组对齐", PASS, "可能是 AES / SM4 分组密码密文")
        elif len(data) % 8 == 0:
            report.add("block8", "8 字节分组对齐", PASS, "可能是 DES / 3DES 分组密码密文")
        else:
            report.add("block", "分组对齐", SKIP, "长度不是 8/16 的整数倍，可能为流密码或含头部")
        if len(data) >= 97 and data[0] == 0x04:
            report.add("sm2", "SM2 密文特征", PASS,
                       "以 0x04 开头且长度 ≥97 字节，符合 SM2 C1C3C2/C1C2C3 密文特征（C1 为 65 字节）")
        else:
            report.add("sm2", "SM2 密文特征", SKIP, "首字节不是 0x04 或长度不足")
        for bits in (2048, 3072, 4096):
            if len(data) == bits // 8:
                report.add("rsa", "RSA 模数长度", PASS, f"与 RSA-{bits} 的密文长度一致")
                break
        if len(data) in (64, 96, 104):
            report.add("sig", "签名长度特征", PASS, "可能为 SM2（r||s=64）或 ECDSA 签名")
        else:
            report.add("sig", "签名长度特征", SKIP, "长度与常见签名值不一致")
        return report


class Pkcs7Page(PageBase):
    page_id = "p7"
    title = "P7 签名数据解析"
    subtitle = "解析 PKCS#7 / CMS SignedData，验证签名与 messageDigest，支持国密 OID 与 SM2。"

    def build_ui(self) -> None:
        card = self.card("签名数据")
        self.in_fmt = fmt_combo(["PEM/DER", "十六进制", "Base64"])
        card.add_row("输入格式", self.in_fmt)
        self.input = TextInput("粘贴 PEM / DER HEX / Base64 的 PKCS#7 数据…", 120, mono=True)
        card.add(self.input)
        self.detached = QCheckBox("分离式签名：下方填写签名覆盖的原文")
        card.add(self.detached)
        self.detached_content = TextInput("分离式签名的原文（可选）", 70)
        card.add(self.detached_content)
        run = primary_button("解析并验证", "play")
        run.clicked.connect(self.do_verify)
        card.add_layout(ActionBar(run, secondary_button("清空"), CopyButton(lambda: self.panel.detail.toPlainText())))

        self.panel = ResultPanel("签名验证结果")
        self.body.addWidget(self.panel)
        self.certs_card = self.card("证书导出")
        self.cert_combo = combo([])
        self.cert_combo.currentIndexChanged.connect(self._show_cert)
        self.certs_card.add_row("选择证书", self.cert_combo)
        self.cert_pem = MonoText("证书 PEM 将显示在这里…", 90)
        self.certs_card.add(self.cert_pem)
        export_btn = secondary_button("导出 PEM…", "export")
        export_btn.clicked.connect(self._export)
        self.certs_card.add_layout(ActionBar(export_btn, CopyButton(lambda: self.cert_pem.toPlainText())))
        self._info = None
        self._certs: list[str] = []
        self._last_der = b""

    def do_verify(self) -> None:
        text = self.input.toPlainText().strip()
        if not text:
            self.show_error("请输入 PKCS#7 数据。")
            return
        fmt = self.in_fmt.currentText()
        try:
            if fmt == "PEM/DER":
                if "-----BEGIN" in text:
                    from ...core.keys import unarmor

                    blocks = unarmor(text)
                    if not blocks:
                        raise ValueError("PEM 中没有数据块。")
                    der = blocks[0][1]
                else:
                    der = encodings.decode(text, "Base64" if encodings.looks_like_base64(text) else "十六进制")
            else:
                der = encodings.decode(text, fmt)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "数据解析失败")
            return
        self._last_der = der
        content = self.detached_content.toPlainText().encode("utf-8") if self.detached.isChecked() else None

        def work():
            return pkcs7.verify_p7(der, detached_content=content)

        self.run_background(work, self._show_report, lambda exc: self.show_error(exc, "P7 验证失败"),
                            busy_text="正在解析 PKCS#7 签名数据…")

    def _show_report(self, report) -> None:
        self.panel.render(report)
        from ...core.cms import parse_content_info
        from ...core.keys import certificate_to_pem
        from ...core.x509 import parse_certificate

        self.cert_combo.blockSignals(True)
        self.cert_combo.clear()
        self._certs = []
        try:
            ci = parse_content_info(self._last_der)
            if ci.signed_data:
                for der_cert in ci.signed_data.certificates:
                    cert = parse_certificate(der_cert)
                    self.cert_combo.addItem(cert.subject.common_name() or cert.subject.text()[:40])
                    self._certs.append(certificate_to_pem(der_cert))
        except Exception:  # noqa: BLE001
            pass
        self.cert_combo.blockSignals(False)
        self._show_cert()
        self.notify("P7 解析完成")

    def _show_cert(self) -> None:
        index = self.cert_combo.currentIndex()
        if 0 <= index < len(self._certs):
            self.cert_pem.setPlainText(self._certs[index])
        else:
            self.cert_pem.clear()

    def _export(self) -> None:
        index = self.cert_combo.currentIndex()
        if not (0 <= index < len(self._certs)):
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出证书", "certificate.pem",
                                              "PEM 证书 (*.pem);;DER 证书 (*.cer)")
        if not path:
            return
        try:
            if path.lower().endswith(".cer"):
                from ...core.keys import unarmor

                blocks = unarmor(self._certs[index])
                with open(path, "wb") as fh:
                    fh.write(blocks[0][1])
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self._certs[index])
            self.notify(f"证书已导出：{path}")
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "导出失败")
