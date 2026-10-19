"""B 类页面：哈希算法、MAC 算法。"""
from __future__ import annotations

from PySide6.QtWidgets import QCheckBox

from ...core import digest, encodings, mac
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


class HashPage(PageBase):
    page_id = "hash"
    title = "哈希算法"
    subtitle = "SM3 / SHA-1 / SHA-2 / SHA-3 / MD5 与 HMAC；SM3 与 HMAC-SM3 均按标准实现。"

    def build_ui(self) -> None:
        card = self.card("参数")
        self.alg = fmt_combo(digest.ALGORITHMS, "SM3")
        card.add_row("算法", self.alg)
        self.message = TextInput("消息（默认按十六进制解析）…", 100, mono=True)
        self.msg_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("消息", self.msg_fmt, self.message)
        self.salt = TextInput("盐值（可选）…", 50, mono=True)
        self.salt_fmt = fmt_combo(KEY_FORMATS)
        self.salt_pos = combo(["前置", "后置", "前后皆用"])
        card.add_row("盐值", self.salt, self.salt_fmt, self.salt_pos)
        self.key = TextInput("HMAC 密钥（可选）…", 50, mono=True)
        self.key_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("HMAC 密钥", self.key, self.key_fmt)
        hash_btn = primary_button("计算哈希", "play")
        hash_btn.clicked.connect(self.do_hash)
        hmac_btn = primary_button("计算 HMAC", "play")
        hmac_btn.clicked.connect(self.do_hmac)
        card.add_layout(ActionBar(hash_btn, hmac_btn, secondary_button("清空")))
        out = self.card("结果")
        self.output = MonoText("结果将显示在这里…", 140)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))
        self.lenient = QCheckBox("输入宽松模式（Base64 自动补 padding / 忽略非法字符）")
        card.add(self.lenient)

    def _msg(self) -> bytes:
        return encodings.decode(self.message.toPlainText(), self.msg_fmt.currentText(),
                                strict=not self.lenient.isChecked())

    def _salt(self) -> bytes:
        if not self.salt.toPlainText().strip():
            return b""
        return encodings.decode(self.salt.toPlainText(), self.salt_fmt.currentText(),
                                strict=not self.lenient.isChecked())

    def _salted(self, data: bytes) -> bytes:
        salt = self._salt()
        if not salt:
            return data
        pos = self.salt_pos.currentText()
        if pos == "前置":
            return salt + data
        if pos == "后置":
            return data + salt
        return salt + data + salt

    def do_hash(self) -> None:
        try:
            data = self._salted(self._msg())
            value = digest.digest_hex(self.alg.currentText(), data)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "哈希计算失败")
            return
        self.output.setPlainText(
            f"算法: {self.alg.currentText()}\n消息字节长度: {len(data)}\n\n哈希结果 HEX:\n{value}"
        )
        self.notify("哈希计算完成")

    def do_hmac(self) -> None:
        try:
            data = self._salted(self._msg())
            key = encodings.decode(self.key.toPlainText(), self.key_fmt.currentText(),
                                   strict=not self.lenient.isChecked())
            if not key:
                raise ValueError("HMAC 密钥不能为空。")
            value = digest.hmac_hex(self.alg.currentText(), key, data)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "HMAC 计算失败")
            return
        self.output.setPlainText(
            f"HMAC 算法: {self.alg.currentText()}\n消息字节长度: {len(data)}\n"
            f"密钥字节长度: {len(key)}\n\nHMAC 结果 HEX:\n{value}"
        )
        self.notify("HMAC 计算完成")


class MacPage(PageBase):
    page_id = "mac"
    title = "MAC 算法"
    subtitle = "CBC-MAC / CMAC（AES、SM4）；其它模式在标准参数完善前明确标注未支持。"

    def build_ui(self) -> None:
        card = self.card("参数")
        self.alg = fmt_combo(mac.ALGORITHMS, "SM4")
        self.mode = combo(mac.MODES + [m + "（未支持）" for m in mac.UNSUPPORTED_MODES])
        card.add_row("算法", self.alg)
        card.add_row("MAC 模式", self.mode)
        self.message = TextInput("消息（默认十六进制）…", 90, mono=True)
        self.msg_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("消息", self.msg_fmt, self.message)
        self.key = TextInput("密钥（十六进制）…", 60, mono=True)
        self.key_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("密钥", self.key_fmt, self.key)
        compute = primary_button("计算 MAC", "play")
        compute.clicked.connect(self.do_compute)
        card.add_layout(ActionBar(compute, secondary_button("清空")))
        out = self.card("结果")
        self.output = MonoText("MAC 结果将显示在这里…", 120)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))

    def do_compute(self) -> None:
        try:
            data = encodings.decode(self.message.toPlainText(), self.msg_fmt.currentText())
            key = encodings.decode(self.key.toPlainText(), self.key_fmt.currentText())
            mode = self.mode.currentText().replace("（未支持）", "")
            tag = mac.compute(mode, self.alg.currentText(), key, data)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "MAC 计算失败")
            return
        self.output.setPlainText(
            f"算法: {self.alg.currentText()} / {mode}\n"
            f"消息长度: {len(data)} 字节\n密钥长度: {len(key)} 字节\n\nMAC (HEX):\n{tag.hex().upper()}"
        )
        self.notify("MAC 计算完成")
