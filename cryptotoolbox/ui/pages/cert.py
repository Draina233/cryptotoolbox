"""D 类页面：证书链验证、证书吊销检查、ASN.1 证书解析、CRL 校验。"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from PySide6.QtWidgets import QFileDialog

from ...core import cert as certmod
from ...core import crl as crlmod
from ...core import der, keys
from ...core.result import FAIL, PASS, SKIP, UNKNOWN, Report
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

CERT_FORMATS = ["PEM/DER 自动", "十六进制", "Base64"]




def _read_cert_file(path: str) -> tuple[str, bool]:
    """读取证书/CRL 文件：PEM 返回文本，DER 返回十六进制（并提示切换输入格式）。"""
    data = open(path, "rb").read()
    if b"-----BEGIN" in data:
        return data.decode("utf-8", errors="replace"), False
    if data[:1] == b"\x30":
        return data.hex().upper(), True
    return data.decode("utf-8", errors="replace"), False


def _load_certs(text: str, fmt: str) -> list:
    entries = keys.parse_certificates_text(text, fmt)
    certs = [c for _der, c, _err in entries if c is not None]
    if not certs:
        errors = "；".join(err for _der, _c, err in entries if err)
        raise ValueError(f"输入中未解析到有效证书。{errors}")
    return certs


class CertChainPage(PageBase):
    page_id = "certchain"
    title = "证书链验证"
    subtitle = "逐级验签（RSA / ECDSA / SM2）、有效期、CA 基本约束与 pathLen；结果如实区分通过/失败/未知。"

    def build_ui(self) -> None:
        leaf = self.card("终端实体证书", "左侧输入要被验证的证书")
        self.leaf_fmt = fmt_combo(CERT_FORMATS)
        leaf.add_row("输入格式", self.leaf_fmt)
        self.leaf_text = TextInput("粘贴 PEM / DER HEX / Base64…", 100, mono=True)
        leaf.add(self.leaf_text)
        self.leaf_picker = FilePicker("选择证书文件", "证书 (*.pem *.crt *.cer *.der);;所有文件 (*.*)")
        self.leaf_picker.file_selected.connect(self._load_leaf_file)
        leaf.add(self.leaf_picker)

        pool = self.card("证书链（中间 CA / 根 CA）", "可粘贴多个 PEM，顺序任意")
        self.pool_fmt = fmt_combo(CERT_FORMATS)
        pool.add_row("输入格式", self.pool_fmt)
        self.pool_text = TextInput("粘贴中间 CA、根 CA 证书…", 110, mono=True)
        pool.add(self.pool_text)
        self.pool_picker = FilePicker("追加证书文件", "证书 (*.pem *.crt *.cer *.der);;所有文件 (*.*)",
                                      append_text="追加")
        self.pool_picker.file_selected.connect(self._load_pool_file)
        pool.add(self.pool_picker)

        verify = primary_button("开始验签", "play")
        verify.clicked.connect(self.do_verify)
        clear = secondary_button("清空")
        clear.clicked.connect(lambda: (self.leaf_text.clear(), self.pool_text.clear()))
        pool.add_layout(ActionBar(verify, clear))
        self.chain_panel = ResultPanel("验证结果")
        self.body.addWidget(self.chain_panel)
        summary_card = self.card("证书摘要")
        self.summary = MonoText("证书链逐级摘要将显示在这里…", 120)
        summary_card.add(self.summary)

    def _build_summary_card(self):
        card = self.card("证书摘要")
        card.add(self.summary)
        return card

    def _load_leaf_file(self, path: str) -> None:
        text, is_hex = _read_cert_file(path)
        if is_hex:
            self.leaf_fmt.setCurrentText("十六进制")
        self.leaf_text.setPlainText(text)

    def _load_pool_file(self, path: str) -> None:
        text, is_hex = _read_cert_file(path)
        if is_hex:
            self.pool_fmt.setCurrentText("十六进制")
        current = self.pool_text.toPlainText()
        self.pool_text.setPlainText((current + "\n" + text).strip())

    def do_verify(self) -> None:
        try:
            leaf = _load_certs(self.leaf_text.toPlainText(), self.leaf_fmt.currentText())[0]
            pool = []
            if self.pool_text.toPlainText().strip():
                pool = _load_certs(self.pool_text.toPlainText(), self.pool_fmt.currentText())
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "证书解析失败")
            return

        def work():
            report = certmod.validate_chain(leaf, pool)
            chain = certmod.build_chain(leaf, pool).chain
            return report, chain

        self.run_background(work, self._show_report, lambda exc: self.show_error(exc, "证书链验证失败"),
                            busy_text="正在逐级验证证书链…")

    def _show_report(self, result) -> None:
        report, chain = result
        self.chain_panel.render(report)
        lines = []
        for chain_cert in chain:
            lines.append(chain_cert.summary_text())
            lines.append("-" * 40)
        self.summary.setPlainText("\n".join(lines) if lines else "（未获取到链结构）")
        self.notify("证书链验证完成")


class RevocationPage(PageBase):
    page_id = "revocation"
    title = "证书吊销检查"
    subtitle = "离线 CRL 检查（验签、有效期、颁发者匹配、序列号命中）；在线 OCSP 暂未提供。"

    def build_ui(self) -> None:
        card = self.card("待检证书")
        self.cert_fmt = fmt_combo(CERT_FORMATS)
        card.add_row("输入格式", self.cert_fmt)
        self.cert_text = TextInput("粘贴待吊销检查的证书…", 90, mono=True)
        card.add(self.cert_text)
        picker = FilePicker("选择证书文件", "证书 (*.pem *.crt *.cer *.der);;所有文件 (*.*)")
        picker.file_selected.connect(lambda p: self.cert_text.setPlainText(
            _read_cert_file(p)[0] if not _read_cert_file(p)[1] else _read_cert_file(p)[0]))
        card.add(picker)

        crl = self.card("CRL（可多个）")
        self.crl_fmt = fmt_combo(["PEM/DER 自动", "十六进制", "Base64"])
        crl.add_row("输入格式", self.crl_fmt)
        self.crl_text = TextInput("粘贴 CRL（PEM 或 DER HEX）…", 90, mono=True)
        crl.add(self.crl_text)
        crl_picker = FilePicker("选择 CRL 文件", "CRL (*.crl *.pem *.der);;所有文件 (*.*)")
        crl_picker.file_selected.connect(lambda p: self.crl_text.setPlainText(_read_cert_file(p)[0]))
        crl.add(crl_picker)
        self.ca_text = TextInput("颁发者（CA）证书（用于验证 CRL 签名，可选）…", 70, mono=True)
        crl.add(self.ca_text)
        ca_picker = FilePicker("选择 CA 证书", "证书 (*.pem *.crt *.cer);;所有文件 (*.*)")
        ca_picker.file_selected.connect(lambda p: self.ca_text.setPlainText(_read_cert_file(p)[0]))
        crl.add(ca_picker)

        check = primary_button("检查吊销状态", "play")
        check.clicked.connect(self.do_check)
        self.panel = ResultPanel("检查结果")
        self.body.addWidget(self.panel)
        self.online = HintLabel("在线 OCSP 查询需要联网与完整的响应签名验证，当前版本未提供；请使用离线 CRL 或厂商平台复核。")
        self.body.addWidget(self.online)

    def do_check(self) -> None:
        try:
            cert = _load_certs(self.cert_text.toPlainText(), self.cert_fmt.currentText())[0]
            crls = []
            if self.crl_text.toPlainText().strip():
                crls = self._load_crls(self.crl_text.toPlainText())
            ca_cert = None
            if self.ca_text.toPlainText().strip():
                ca_cert = _load_certs(self.ca_text.toPlainText(), "PEM/DER 自动")[0]
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "输入解析失败")
            return
        report = self._check(cert, crls, ca_cert)
        self.panel.render(report)
        self.notify("吊销状态检查完成")

    def _load_crls(self, text: str) -> list:
        text = text.strip()
        if "-----BEGIN" in text:
            from ...core.keys import unarmor

            crls = []
            for label, der_bytes in unarmor(text):
                if "CRL" in label.upper():
                    crls.append(crlmod.parse_crl(der_bytes))
            if crls:
                return crls
        if "crl" not in text and not text.startswith("30"):
            pass
        raw = None
        try:
            raw = bytes.fromhex("".join(ch for ch in text if ch in "0123456789abcdefABCDEF"))
        except ValueError:
            raw = None
        if raw:
            crls = crlmod.parse_crls(raw)
            if crls:
                return crls
        raise ValueError("CRL 解析失败：请提供 PEM 或 DER（HEX）格式的 CRL。")

    def _check(self, cert, crls, ca_cert) -> Report:
        report = Report(title="证书吊销状态检查")
        report.meta["证书"] = cert.subject.text()
        report.meta["序列号"] = cert.serial_hex
        if not crls:
            report.add("crl", "CRL 可用性", SKIP, "未提供 CRL（在线 OCSP 未提供）。")
            return report
        report.add("count", "CRL 数量", PASS, f"{len(crls)} 个")
        matched = None
        for crl in crls:
            if crl.issuer.raw == cert.issuer.raw:
                matched = crl
                break
        if matched is None:
            report.add("issuer", "CRL 颁发者匹配", FAIL,
                       "所有 CRL 的颁发者与证书 Issuer 不匹配，结论不可信。")
            return report
        report.add("issuer", "CRL 颁发者匹配", PASS, matched.issuer_text)
        if ca_cert is not None:
            try:
                ok, message = certmod.verify_signature(
                    spki=ca_cert.spki, signature_algorithm_oid=matched.signature_algorithm_oid,
                    signature_algorithm_params=matched.signature_algorithm_params,
                    data=matched.tbs, signature=matched.signature,
                    signer_uid=[ca_cert.subject.raw, b"", b"1234567812345678"],
                )
                report.add("sig", "CRL 签名验证", PASS if ok else FAIL, message)
            except Exception as exc:  # noqa: BLE001
                report.add("sig", "CRL 签名验证", UNKNOWN, f"验签异常：{exc}")
        else:
            report.add("sig", "CRL 签名验证", UNKNOWN, "未提供颁发者证书，无法验证 CRL 签名。")
        status = matched.time_status()
        report.add("validity", "CRL 有效期", PASS if status == "仍在有效期" else FAIL,
                   f"thisUpdate={matched.this_update.isoformat()}，nextUpdate="
                   f"{matched.next_update.isoformat() if matched.next_update else '无'}")
        entry = matched.find_serial(cert.serial)
        if entry is None:
            report.add("serial", "吊销条目命中", PASS, "未在 CRL 中发现该证书序列号。")
        else:
            report.add("serial", "吊销条目命中", FAIL,
                       f"证书已被吊销（吊销时间 {entry.revocation_date.isoformat() if entry.revocation_date else '未知'}，"
                       f"原因 {entry.reason or '未注明'}）。")
        report.note("吊销结论仅在 CRL 自身有效、签名正确且由正确 CA 签发时才可信；请核对上述各项。")
        return report


class CertParsePage(PageBase):
    page_id = "certparse"
    title = "ASN.1 证书解析"
    subtitle = "解析证书结构（TLV 树）、字段与扩展，计算 SHA-1/SHA-256/SM3 指纹，支持导出。"

    def build_ui(self) -> None:
        card = self.card("证书输入")
        self.fmt = fmt_combo(CERT_FORMATS)
        card.add_row("输入格式", self.fmt)
        self.text = TextInput("粘贴 PEM / DER HEX / Base64 证书…", 100, mono=True)
        card.add(self.text)
        picker = FilePicker("选择证书文件", "证书 (*.pem *.crt *.cer *.der);;所有文件 (*.*)")
        picker.file_selected.connect(self._load_file)
        card.add(picker)
        parse = primary_button("解析", "play")
        parse.clicked.connect(self.do_parse)
        export_der_btn = secondary_button("导出 DER…", "export")
        export_der_btn.clicked.connect(self.export_der)
        export_pem_btn = secondary_button("导出 PEM…", "export")
        export_pem_btn.clicked.connect(self.export_pem)
        card.add_layout(ActionBar(parse, export_der_btn, export_pem_btn))
        self._certs: list = []
        self._der: bytes = b""
        out = self.card("解析结果")
        self.summary = MonoText("证书摘要将显示在这里…", 110)
        out.add(self.summary)
        self.tree = MonoText("ASN.1 结构树将显示在这里…", 220)
        out.add(self.tree)
        out.add_layout(ActionBar(CopyButton(lambda: self.summary.toPlainText() + "\n" + self.tree.toPlainText())))

    def _load_file(self, path: str) -> None:
        text, is_hex = _read_cert_file(path)
        if is_hex:
            self.fmt.setCurrentText("十六进制")
        self.text.setPlainText(text)

    def do_parse(self) -> None:
        try:
            certs = _load_certs(self.text.toPlainText(), self.fmt.currentText())
            cert = certs[0]
            self._certs = certs
            self._der = cert.der
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "证书解析失败")
            return
        sha1 = hashlib.sha1(cert.der).hexdigest().upper()
        sha256 = hashlib.sha256(cert.der).hexdigest().upper()
        from ...core.digest import sm3

        sm3_hex = sm3(cert.der).hex().upper()
        summary = "\n".join([cert.summary_text(), "", f"SHA-1:   {sha1}", f"SHA-256: {sha256}",
                             f"SM3:     {sm3_hex}", f"DER 长度: {len(cert.der)} 字节"])
        self.summary.setPlainText(summary)
        try:
            lines = der.tree_lines(cert.der, max_depth=12)
            self.tree.setPlainText("\n".join(lines))
        except Exception as exc:  # noqa: BLE001
            self.tree.setPlainText(f"结构树生成失败：{exc}")
        self.notify("证书解析完成")

    def export_der(self) -> None:
        if not self._der:
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出证书 DER", "certificate.der", "DER (*.der)")
        if path:
            with open(path, "wb") as fh:
                fh.write(self._der)
            self.notify(f"已导出 DER：{path}")

    def export_pem(self) -> None:
        if not self._der:
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出证书 PEM", "certificate.pem", "PEM (*.pem)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(keys.certificate_to_pem(self._der))
            self.notify(f"已导出 PEM：{path}")


class CrlPage(PageBase):
    page_id = "crl"
    title = "CRL 格式校验"
    subtitle = "解析 CRL 信息、验证签名与有效期，并列出吊销条目。"

    def build_ui(self) -> None:
        card = self.card("CRL 输入")
        self.fmt = fmt_combo(["PEM/DER 自动", "十六进制", "Base64"])
        card.add_row("输入格式", self.fmt)
        self.text = TextInput("粘贴 PEM 或 DER HEX 的 CRL…", 100, mono=True)
        card.add(self.text)
        picker = FilePicker("选择 CRL 文件", "CRL (*.crl *.pem *.der);;所有文件 (*.*)")
        picker.file_selected.connect(self._load_file)
        card.add(picker)
        self.ca = TextInput("颁发者（CA）证书（用于验签，可选）…", 70, mono=True)
        card.add(self.ca)
        ca_picker = FilePicker("选择 CA 证书", "证书 (*.pem *.crt *.cer);;所有文件 (*.*)")
        ca_picker.file_selected.connect(self._load_ca)
        card.add(ca_picker)
        run = primary_button("解析并验证", "play")
        run.clicked.connect(self.do_parse)
        card.add_layout(ActionBar(run))
        self._crl = None
        out = self.card("结果")
        self.info = MonoText("CRL 信息将显示在这里…", 160)
        out.add(self.info)
        out.add_layout(ActionBar(CopyButton(lambda: self.info.toPlainText())))

    def _load_file(self, path: str) -> None:
        text, is_hex = _read_cert_file(path)
        if is_hex:
            self.fmt.setCurrentText("十六进制")
        self.text.setPlainText(text)

    def _load_ca(self, path: str) -> None:
        self.ca.setPlainText(_read_cert_file(path)[0])

    def do_parse(self) -> None:
        try:
            text = self.text.toPlainText().strip()
            if "-----BEGIN" in text:
                from ...core.keys import unarmor

                blocks = unarmor(text)
                crl_der = next(der_bytes for label, der_bytes in blocks if "CRL" in label.upper())
            else:
                raw = bytes.fromhex("".join(ch for ch in text if ch in "0123456789abcdefABCDEF"))
                crl_der = raw
            crl = crlmod.parse_crl(crl_der)
            self._crl = crl
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "CRL 解析失败")
            return
        lines = [
            f"版本: v{crl.version}",
            f"颁发者: {crl.issuer_text}",
            f"thisUpdate: {crl.this_update.isoformat() if crl.this_update else '无'}",
            f"nextUpdate: {crl.next_update.isoformat() if crl.next_update else '无'}",
            f"签名算法: {crl.signature_algorithm_oid}",
            f"吊销条目数: {len(crl.entries)}",
            f"CRL Number: {crl.crl_number if crl.crl_number is not None else '无'}",
            f"AKI: {crl.akid.hex().upper() if crl.akid else '无'}",
        ]
        if self.ca.toPlainText().strip():
            try:
                ca_cert = _load_certs(self.ca.toPlainText(), "PEM/DER 自动")[0]
                ok, message = certmod.verify_signature(
                    spki=ca_cert.spki, signature_algorithm_oid=crl.signature_algorithm_oid,
                    signature_algorithm_params=crl.signature_algorithm_params,
                    data=crl.tbs, signature=crl.signature,
                    signer_uid=[ca_cert.subject.raw, b"", b"1234567812345678"])
                lines += ["", f"签名验证: {'通过' if ok else '失败'}（{message}）"]
            except Exception as exc:  # noqa: BLE001
                lines += ["", f"签名验证异常: {exc}"]
        else:
            lines += ["", "签名验证: 未提供 CA 证书，跳过"]
        if crl.entries:
            lines += ["", "吊销条目（前 20 条）:"]
            for entry in crl.entries[:20]:
                lines.append(f"  序列号 {entry.serial:X}  时间 {entry.revocation_date.isoformat() if entry.revocation_date else '未知'}  原因 {entry.reason or '未注明'}")
        self.info.setPlainText("\n".join(lines))
        self.notify("CRL 解析完成")

