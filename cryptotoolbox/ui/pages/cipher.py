"""B 类页面：分组密码、序列算法（ZUC）、GCM 模式。"""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QLabel, QMessageBox

from ...core import blockcipher, encodings, gcm, zuc
from ..widgets import (
    ActionBar,
    CopyButton,
    MonoText,
    TextInput,
    combo,
    fmt_combo,
    primary_button,
    secondary_button,
)
from .base import PageBase

KEY_FORMATS = ["十六进制", "Base64", "字符串"]


def _bytes(text: str, fmt: str, strict: bool = True) -> bytes:
    return encodings.decode(text, fmt, strict=strict)


class BlockCipherPage(PageBase):
    page_id = "blockcipher"
    title = "分组密码"
    subtitle = "AES / SM4 / DES / 3DES，模式与填充严格校验；流模式不套填充，CTR 支持 16 字节 IV。"

    def build_ui(self) -> None:
        card = self.card("参数")
        self.alg = fmt_combo(blockcipher.ALGORITHMS, "SM4")
        self.mode = fmt_combo(blockcipher.MODES, "CBC")
        self.padding = fmt_combo(blockcipher.PADDING_SCHEMES, "PKCS7")
        card.add_row("算法", self.alg)
        card.add_row("模式", self.mode)
        card.add_row("填充", self.padding)
        self.note = QLabel("")
        self.note.setObjectName("hintText")
        self.note.setWordWrap(True)
        card.add(self.note)

        data_card = self.card("数据")
        self.data = TextInput("明文 / 密文（十六进制）…", 80, mono=True)
        self.data_fmt = fmt_combo(KEY_FORMATS)
        data_card.add_row("数据", self.data_fmt)
        data_card.add(self.data)
        key_card = self.card("密钥与 IV")
        self.key = TextInput("密钥（十六进制）…", 60, mono=True)
        self.key_fmt = fmt_combo(KEY_FORMATS)
        self.iv = TextInput("IV（十六进制）…", 60, mono=True)
        self.iv_fmt = fmt_combo(KEY_FORMATS)
        key_card.add_row("密钥", self.key, self.key_fmt)
        key_card.add_row("IV", self.iv, self.iv_fmt)

        encrypt_btn = primary_button("加密", "lock")
        encrypt_btn.clicked.connect(self.do_encrypt)
        decrypt_btn = primary_button("解密", "lock")
        decrypt_btn.clicked.connect(self.do_decrypt)
        rnd_btn = secondary_button("随机密钥 / IV")
        rnd_btn.clicked.connect(self.randomize)
        clear_btn = secondary_button("清空")
        clear_btn.clicked.connect(self.clear_all)
        card.add_layout(ActionBar(encrypt_btn, decrypt_btn, rnd_btn, clear_btn))

        out_card = self.card("结果")
        self.output = MonoText("加密/解密结果将显示在这里…", 160)
        out_card.add(self.output)
        out_card.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))

        self.alg.currentTextChanged.connect(self._update_note)
        self.mode.currentTextChanged.connect(self._update_note)
        self.padding.currentTextChanged.connect(self._update_note)
        self._update_note()

    def _update_note(self) -> None:
        mode = self.mode.currentText()
        padding = self.padding.currentText()
        notes = [blockcipher.mode_note(mode, padding)]
        if mode == "ECB":
            notes.append("ECB 模式相同明文块产生相同密文块，仅用于测试/比对，不建议用于实际业务。")
        if self.alg.currentText() == "SM4" and mode == "XTS":
            notes.append("SM4 没有标准 XTS 模式。")
        if mode == "XTS":
            notes.append("XTS 密钥为两份等长密钥拼接；IV 为 16 字节 tweak 输入（数据单元号小端）。")
        if self.alg.currentText() in ("DES", "3DES"):
            notes.append("DES/3DES 已不满足安全强度要求，仅用于兼容性测试。")
        self.note.setText(" ".join(n for n in notes if n))

    def _key_len(self) -> int:
        alg = self.alg.currentText()
        return blockcipher.KEY_SIZES.get(alg, [16])[0] if self.mode.currentText() != "XTS" else \
            {"AES-128": 32, "AES-192": 48, "AES-256": 64}.get(alg, 0)

    def randomize(self) -> None:
        alg = self.alg.currentText()
        sizes = blockcipher.KEY_SIZES.get(alg, [16])
        extra = 0
        if self.mode.currentText() == "XTS":
            extra = 32 if alg in ("AES-128", "AES-192", "AES-256") else 16
        else:
            extra = blockcipher.block_size(alg)
        key_len = (2 * sizes[0]) if self.mode.currentText() == "XTS" else sizes[0]
        self.key.setPlainText(os.urandom(key_len).hex().upper())
        if self.mode.currentText() == "ECB":
            self.iv.clear()
        else:
            self.iv.setPlainText(os.urandom(extra).hex().upper())
        self.notify("已生成随机密钥与 IV")

    def _collect(self):
        data = _bytes(self.data.toPlainText(), self.data_fmt.currentText())
        key = _bytes(self.key.toPlainText(), self.key_fmt.currentText())
        iv_text = self.iv.toPlainText().strip()
        iv = _bytes(iv_text, self.iv_fmt.currentText()) if iv_text else b""
        return data, key, iv

    def do_encrypt(self) -> None:
        try:
            data, key, iv = self._collect()
            ct = blockcipher.encrypt(self.alg.currentText(), self.mode.currentText(),
                                     self.padding.currentText(), data, key, iv)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "加密失败")
            return
        self.output.setPlainText(f"密文（HEX）：\n{ct.hex().upper()}\n\n[长度] {len(ct)} 字节")
        self.notify("加密完成")

    def do_decrypt(self) -> None:
        try:
            data, key, iv = self._collect()
            plain, warning = blockcipher.decrypt(self.alg.currentText(), self.mode.currentText(),
                                                 self.padding.currentText(), data, key, iv)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "解密失败")
            return
        lines = [f"明文（HEX）：\n{plain.hex().upper()}", "", "[UTF-8 文本]"]
        try:
            lines.append(plain.decode("utf-8"))
        except UnicodeDecodeError:
            lines.append("（不是合法 UTF-8 文本）")
        if warning:
            lines += ["", f"[警告] {warning}"]
        self.output.setPlainText("\n".join(lines))
        self.notify("解密完成" if not warning else "解密完成（去填充失败，请核对密钥/填充）")

    def clear_all(self) -> None:
        self.data.clear()
        self.key.clear()
        self.iv.clear()
        self.output.clear()


class ZucPage(PageBase):
    page_id = "streamcipher"
    title = "序列算法（ZUC）"
    subtitle = "ZUC-128 加解密（GM/T 0001.1）；ZUC-256 与 ZUC-MAC 当前版本明确标注为未支持。"

    def build_ui(self) -> None:
        card = self.card("参数")
        self.alg = combo(["ZUC-128", "ZUC-256（未支持）", "ZUC-MAC（未支持）"])
        card.add_row("算法", self.alg)
        self.key = TextInput("密钥（ZUC-128 为 16 字节十六进制）…", 60, mono=True)
        self.key_fmt = fmt_combo(KEY_FORMATS)
        self.iv = TextInput("IV（ZUC-128 为 16 字节十六进制）…", 60, mono=True)
        self.iv_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("密钥", self.key_fmt, self.key)
        card.add_row("IV", self.iv_fmt, self.iv)
        self.message = TextInput("明文 / 密文（十六进制）…", 80, mono=True)
        self.msg_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("数据", self.msg_fmt, self.message)
        encrypt_btn = primary_button("加密", "lock")
        encrypt_btn.clicked.connect(self.do_encrypt)
        decrypt_btn = primary_button("解密", "lock")
        decrypt_btn.clicked.connect(self.do_decrypt)
        card.add_layout(ActionBar(encrypt_btn, decrypt_btn, secondary_button("清空")))
        out = self.card("结果")
        self.output = MonoText("结果将显示在这里…", 140)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))
        note = self.card("说明")
        note.add_note("ZUC-256 与 ZUC-MAC 需要 GM/T 0001.1-2021 附录参数与 S 盒，当前版本未提供，选择时会明确提示。")

    def _check_alg(self) -> bool:
        if self.alg.currentText() != "ZUC-128":
            self.show_error("ZUC-256 与 ZUC-MAC 当前版本暂未支持（需要 GM/T 0001.1-2021 完整参数）。")
            return False
        return True

    def _collect(self) -> tuple[bytes, bytes, bytes]:
        key = _bytes(self.key.toPlainText(), self.key_fmt.currentText())
        iv = _bytes(self.iv.toPlainText(), self.iv_fmt.currentText())
        data = _bytes(self.message.toPlainText(), self.msg_fmt.currentText())
        return data, key, iv

    def do_encrypt(self) -> None:
        if not self._check_alg():
            return
        try:
            data, key, iv = self._collect()
            ct = zuc.crypt(key, iv, data)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "ZUC 加密失败")
            return
        self.output.setPlainText(f"密文（HEX）：\n{ct.hex().upper()}")
        self.notify("ZUC 加密完成")

    def do_decrypt(self) -> None:
        if not self._check_alg():
            return
        try:
            data, key, iv = self._collect()
            plain = zuc.crypt(key, iv, data)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "ZUC 解密失败")
            return
        lines = [f"明文（HEX）：\n{plain.hex().upper()}"]
        try:
            lines += ["", plain.decode("utf-8")]
        except UnicodeDecodeError:
            pass
        self.output.setPlainText("\n".join(lines))
        self.notify("ZUC 解密完成")


class GcmPage(PageBase):
    page_id = "gcm"
    title = "GCM 模式"
    subtitle = "AES-GCM / SM4-GCM 认证加密，支持 AAD 与认证标签校验；认证失败会明确区分原因。"

    def build_ui(self) -> None:
        card = self.card("参数")
        self.alg = fmt_combo(gcm.GCM_ALGORITHMS, "SM4-GCM")
        card.add_row("算法", self.alg)
        self.key = TextInput("密钥（十六进制）…", 60, mono=True)
        self.key_fmt = fmt_combo(KEY_FORMATS)
        self.iv = TextInput("IV（建议 12 字节）…", 60, mono=True)
        self.iv_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("密钥", self.key_fmt, self.key)
        card.add_row("IV", self.iv_fmt, self.iv)
        self.aad = TextInput("AAD（可选）…", 50, mono=True)
        self.aad_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("AAD", self.aad_fmt, self.aad)
        self.message = TextInput("明文 / 密文（十六进制）…", 80, mono=True)
        self.msg_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("数据", self.msg_fmt, self.message)
        self.tag = TextInput("认证标签 Tag（解密时填写）…", 50, mono=True)
        card.add_row("Tag", self.tag)
        encrypt_btn = primary_button("加密", "lock")
        encrypt_btn.clicked.connect(self.do_encrypt)
        decrypt_btn = primary_button("解密", "lock")
        decrypt_btn.clicked.connect(self.do_decrypt)
        card.add_layout(ActionBar(encrypt_btn, decrypt_btn, secondary_button("清空")))
        out = self.card("结果")
        self.output = MonoText("结果将显示在这里…", 140)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))

    def _parts(self):
        key = _bytes(self.key.toPlainText(), self.key_fmt.currentText())
        iv = _bytes(self.iv.toPlainText(), self.iv_fmt.currentText())
        data = _bytes(self.message.toPlainText(), self.msg_fmt.currentText())
        aad = _bytes(self.aad.toPlainText(), self.aad_fmt.currentText()) if self.aad.toPlainText().strip() else b""
        return key, iv, data, aad

    def do_encrypt(self) -> None:
        try:
            key, iv, data, aad = self._parts()
            ct, tag = gcm.encrypt(self.alg.currentText(), data, key, iv, aad, tag_len=16)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "GCM 加密失败")
            return
        self.tag.setPlainText(tag.hex().upper())
        self.output.setPlainText(f"密文（HEX）：\n{ct.hex().upper()}\n\nTag：{tag.hex().upper()}")
        self.notify("GCM 加密完成")

    def do_decrypt(self) -> None:
        try:
            key, iv, data, aad = self._parts()
            tag = _bytes(self.tag.toPlainText(), "十六进制")
            plain = gcm.decrypt(self.alg.currentText(), data, tag, key, iv, aad, tag_len=len(tag))
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "GCM 解密失败")
            return
        lines = [f"明文（HEX）：\n{plain.hex().upper()}"]
        try:
            lines += ["", plain.decode("utf-8")]
        except UnicodeDecodeError:
            pass
        self.output.setPlainText("\n".join(lines))
        self.notify("GCM 解密与认证通过")
