"""B 类页面：RSA 签名验签。"""
from __future__ import annotations

from ...core import encodings, keys
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

HASHES = [
    ("SHA-1", "SHA1"), ("SHA-224", "SHA224"), ("SHA-256", "SHA256"),
    ("SHA-384", "SHA384"), ("SHA-512", "SHA512"),
]
SCHEMES = ["PKCS#1 v1.5", "PSS"]
KEY_FORMATS = ["PEM / HEX 自动识别", "十六进制", "PEM"]


class RsaPage(PageBase):
    page_id = "rsa"
    title = "RSA 签名验签"
    subtitle = "PKCS#1 v1.5 与 PSS；区分“签名无效”与“输入/密钥错误”，不会把参数错误显示成验签失败。"

    def build_ui(self) -> None:
        card = self.card("密钥")
        self.key_text = TextInput("公钥 / 私钥（PEM 或 DER HEX）…", 90, mono=True)
        self.key_fmt = fmt_combo(KEY_FORMATS)
        card.add_row("密钥", self.key_fmt)
        card.add(self.key_text)
        params = self.card("参数")
        self.hash_algo = combo([name for name, _ in HASHES], "SHA-256")
        self.scheme = combo(SCHEMES)
        self.data = TextInput("待签名数据（默认十六进制）…", 80, mono=True)
        self.data_fmt = fmt_combo(["十六进制", "Base64", "字符串"])
        self.signature = TextInput("签名值（十六进制）…", 60, mono=True)
        params.add_row("哈希算法", self.hash_algo, self.scheme)
        params.add_row("数据", self.data_fmt, self.data)
        params.add_row("签名值", self.signature)
        sign_btn = primary_button("签名", "play")
        sign_btn.clicked.connect(self.do_sign)
        verify_btn = primary_button("验签", "play")
        verify_btn.clicked.connect(self.do_verify)
        card.add_layout(ActionBar(sign_btn, verify_btn, secondary_button("清空")))
        out = self.card("结果")
        self.output = MonoText("结果将显示在这里…", 140)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))

    def _key(self):
        try:
            return keys.parse_rsa_key(self.key_text.toPlainText().strip())
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"RSA 密钥解析失败：{exc}") from exc

    def _hasher(self, name: str):
        from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512

        mapping = {"SHA-1": SHA1, "SHA-224": SHA224, "SHA-256": SHA256,
                   "SHA-384": SHA384, "SHA-512": SHA512}
        return mapping[name]

    def do_sign(self) -> None:
        try:
            key = self._key()
            if not key.has_private():
                raise ValueError("当前密钥不是 RSA 私钥，无法签名。")
            data = encodings.decode(self.data.toPlainText(), self.data_fmt.currentText())
            hasher = self._hasher(self.hash_algo.currentText()).new(data)
            if self.scheme.currentText() == "PSS":
                from Crypto.Signature import pss

                signature = pss.new(key).sign(hasher)
            else:
                from Crypto.Signature import pkcs1_15

                signature = pkcs1_15.new(key).sign(hasher)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "RSA 签名失败")
            return
        self.signature.setPlainText(signature.hex().upper())
        self.output.setPlainText(
            f"签名方案: {self.scheme.currentText()} / {self.hash_algo.currentText()}\n"
            f"签名值（HEX）：\n{signature.hex().upper()}"
        )
        self.notify("RSA 签名完成")

    def do_verify(self) -> None:
        try:
            key = self._key()
            public = key.publickey() if key.has_private() else key
            data = encodings.decode(self.data.toPlainText(), self.data_fmt.currentText())
            sig = encodings.hex_decode(self.signature.toPlainText())
            hasher = self._hasher(self.hash_algo.currentText()).new(data)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "验签参数错误")
            return
        try:
            if self.scheme.currentText() == "PSS":
                from Crypto.Signature import pss

                pss.new(public).verify(hasher, sig)
            else:
                from Crypto.Signature import pkcs1_15

                pkcs1_15.new(public).verify(hasher, sig)
            ok = True
        except (ValueError, TypeError) as exc:
            ok = False
            detail = str(exc)
        if ok:
            self.output.setPlainText(f"验签通过（{self.scheme.currentText()} / {self.hash_algo.currentText()}）")
            self.notify("RSA 验签通过")
        else:
            self.output.setPlainText(
                f"验签失败（{self.scheme.currentText()} / {self.hash_algo.currentText()}）：\n"
                f"签名与数据/公钥不匹配（{detail}）。\n"
                "注意：若密钥、数据或方案选择有误，也会导致验签失败；请先确认输入。"
            )
            self.notify("RSA 验签失败")
