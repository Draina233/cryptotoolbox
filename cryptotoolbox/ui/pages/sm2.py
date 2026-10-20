"""B 类页面：SM2 签名验签、SM2 加密解密、密钥对生成。"""
from __future__ import annotations

import os

from PySide6.QtWidgets import QCheckBox

from ...core import encodings, keys, sm2
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
UID_FORMATS = ["十六进制", "ASCII"]


class Sm2SignPage(PageBase):
    page_id = "sm2_sign"
    title = "SM2 签名验签"
    subtitle = "SM3withSM2；用户标识（UID）参与 ZA 计算，支持 r||s 与 DER 两种签名格式。"

    def build_ui(self) -> None:
        card = self.card("密钥")
        self.pk = TextInput("公钥：128/130 位十六进制或 PUBLIC KEY PEM…", 60, mono=True)
        self.sk = TextInput("私钥：64 位十六进制或 EC PRIVATE KEY PEM…", 60, mono=True)
        card.add(self.pk)
        card.add(self.sk)
        uid_row = self.card("用户标识与消息")
        self.uid = TextInput("用户标识 UID（默认 1234567812345678）", 40, mono=True)
        self.uid_fmt = fmt_combo(UID_FORMATS)
        self.uid.setPlainText(sm2.DEFAULT_UID.hex().upper())
        uid_row.add_row("UID", self.uid, self.uid_fmt)
        self.message = TextInput("输入签名原文（默认十六进制）", 80, mono=True)
        self.msg_fmt = fmt_combo(KEY_FORMATS)
        uid_row.add_row("签名原文", self.msg_fmt, self.message)
        self.e_mode = QCheckBox("基于 e 值验签（勾选后下方 e 值参与验签，消息框忽略）")
        uid_row.add(self.e_mode)
        self.e_value = TextInput("e 值（SM3 输出，64 位十六进制）", 40, mono=True)
        uid_row.add(self.e_value)
        self.signature = TextInput("签名值（r||s 128 位十六进制，或 DER）", 60, mono=True)
        uid_row.add(self.signature)

        sign_btn = primary_button("签名", "play")
        sign_btn.clicked.connect(self.do_sign)
        verify_btn = primary_button("验签", "play")
        verify_btn.clicked.connect(self.do_verify)
        to_der = secondary_button("r||s → DER")
        to_der.clicked.connect(lambda: self._convert(True))
        to_raw = secondary_button("DER → r||s")
        to_raw.clicked.connect(lambda: self._convert(False))
        gen_btn = secondary_button("随机密钥对")
        gen_btn.clicked.connect(self.gen_keys)
        uid_row.add_layout(ActionBar(sign_btn, verify_btn, to_der, to_raw, gen_btn))

        out = self.card("结果")
        self.output = MonoText("结果将显示在这里…", 160)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))

    def _uid(self) -> bytes:
        text = self.uid.toPlainText().strip()
        if not text:
            return sm2.DEFAULT_UID
        if text.upper() == sm2.DEFAULT_UID.hex().upper():
            return sm2.DEFAULT_UID
        if self.uid_fmt.currentText() == "ASCII":
            return text.encode("utf-8")
        return encodings.hex_decode(text)

    def _message(self) -> bytes:
        return encodings.decode(self.message.toPlainText(), self.msg_fmt.currentText())

    def gen_keys(self) -> None:
        sk, pk = sm2.generate_keypair()
        self.sk.setPlainText(sk.hex().upper())
        self.pk.setPlainText(pk.hex().upper())
        self.notify("已生成 SM2 密钥对（私钥/公钥已填入）")

    def do_sign(self) -> None:
        try:
            private, _derived = keys.parse_sm2_private(self.sk.toPlainText().strip())
            uid = self._uid()
            data = self._message()
            public = keys.parse_sm2_public(self.pk.toPlainText().strip()) if self.pk.toPlainText().strip() \
                else sm2.derive_public_key(private)
            r, s = sm2.sign(data, private, uid)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "SM2 签名失败")
            return
        der = sm2.rs_to_der(r, s)
        z = sm2.z_value(uid, public)
        e = sm2.e_value(data, uid, public)
        self.signature.setPlainText((r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex().upper())
        self.output.setPlainText(
            "\n".join([
                f"签名值 r||s（HEX）：\n{(r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex().upper()}",
                "",
                f"签名值 DER（HEX）：\n{der.hex().upper()}",
                "",
                f"ZA：\n{z.hex().upper()}",
                "",
                f"e = SM3(ZA || M)：\n{e.hex().upper()}",
                "",
                f"用户标识：{uid.hex().upper()}（{len(uid) * 8} bit）",
            ])
        )
        self.notify("SM2 签名完成")

    def do_verify(self) -> None:
        try:
            public = keys.parse_sm2_public(self.pk.toPlainText().strip())
            signature_text = self.signature.toPlainText().strip()
            if signature_text.startswith("30") and len(signature_text) > 128:
                r, s = sm2.der_to_rs(bytes.fromhex(signature_text))
            else:
                r, s = sm2.raw_rs(encodings.hex_decode(signature_text))
            uid = self._uid()
            if self.e_mode.isChecked():
                e_bytes = encodings.hex_decode(self.e_value.toPlainText())
                ok = sm2.verify_e(e_bytes, (r, s), public)
                detail = f"基于 e 值验签：{'通过' if ok else '失败'}"
            else:
                data = self._message()
                ok = False
                used_uid = uid
                # 兼容不同实现的 UID 约定：显式 UID、默认 UID、空 UID 依次尝试
                candidates = [uid]
                for extra in (sm2.DEFAULT_UID, b""):
                    if extra not in candidates:
                        candidates.append(extra)
                for candidate in candidates:
                    if sm2.verify(data, (r, s), public, candidate):
                        ok, used_uid = True, candidate
                        break
                uid = used_uid
                detail = f"验签：{'通过' if ok else '失败'}"
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "SM2 验签失败")
            return
        lines = [detail, "", f"用户标识：{uid.hex().upper()}"]
        if not self.e_mode.isChecked():
            lines += ["", f"ZA：\n{sm2.z_value(uid, public).hex().upper()}"]
        self.output.setPlainText("\n".join(lines))
        self.notify("SM2 验签通过" if ok else "SM2 验签失败")

    def _convert(self, to_der: bool) -> None:
        try:
            text = self.signature.toPlainText().strip()
            if to_der:
                der = sm2.signature_to_der(encodings.hex_decode(text))
                self.output.setPlainText(f"DER（HEX）：\n{der.hex().upper()}")
            else:
                raw = sm2.signature_from_der(bytes.fromhex(text))
                self.output.setPlainText(f"r||s（HEX）：\n{raw.hex().upper()}")
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "签名格式转换失败")


class Sm2CryptPage(PageBase):
    page_id = "sm2_crypt"
    title = "SM2 加密解密"
    subtitle = "支持 C1C3C2 与 C1C2C3 密文排列；解密时校验 C3 摘要，密文被篡改会报错。"

    def build_ui(self) -> None:
        card = self.card("密钥")
        self.pk = TextInput("公钥（加密用）…", 50, mono=True)
        self.sk = TextInput("私钥（解密用）…", 50, mono=True)
        card.add(self.pk)
        card.add(self.sk)
        body = self.card("数据")
        self.mode = fmt_combo(["C1C3C2", "C1C2C3"], "C1C3C2")
        body.add_row("密文排列", self.mode)
        self.message = TextInput("明文 / 密文（默认十六进制）…", 80, mono=True)
        self.msg_fmt = fmt_combo(KEY_FORMATS)
        body.add_row("数据", self.msg_fmt, self.message)
        enc_btn = primary_button("加密", "lock")
        enc_btn.clicked.connect(self.do_encrypt)
        dec_btn = primary_button("解密", "lock")
        dec_btn.clicked.connect(self.do_decrypt)
        body.add_layout(ActionBar(enc_btn, dec_btn, secondary_button("清空")))
        out = self.card("结果")
        self.output = MonoText("结果将显示在这里…", 160)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))

    def do_encrypt(self) -> None:
        try:
            public = keys.parse_sm2_public(self.pk.toPlainText().strip())
            data = encodings.decode(self.message.toPlainText(), self.msg_fmt.currentText())
            mode = self.mode.currentText()
            cipher = sm2.encrypt(data, public, mode)
            c1, c3, c2 = sm2.split_cipher(cipher, mode)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "SM2 加密失败")
            return
        self.message.setPlainText(cipher.hex().upper())
        self.output.setPlainText(
            "\n".join([
                f"完整密文（{mode}，HEX）：\n{cipher.hex().upper()}",
                "",
                f"C1（65 字节）：\n{c1.hex().upper()}",
                "",
                f"C3（32 字节）：\n{c3.hex().upper()}",
                "",
                f"C2（{len(c2)} 字节）：\n{c2.hex().upper()}",
            ])
        )
        self.notify("SM2 加密完成")

    def do_decrypt(self) -> None:
        try:
            private, _ = keys.parse_sm2_private(self.sk.toPlainText().strip())
            cipher = encodings.decode(self.message.toPlainText(), self.msg_fmt.currentText())
            mode = self.mode.currentText()
            plain = sm2.decrypt(cipher, private, mode)
            c1, c3, c2 = sm2.split_cipher(cipher, mode)
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "SM2 解密失败")
            return
        lines = [f"明文（HEX）：\n{plain.hex().upper()}", "", f"C1：{c1.hex().upper()[:32]}…",
                 f"C3：{c3.hex().upper()}"]
        try:
            lines += ["", f"明文（UTF-8）：{plain.decode('utf-8')}"]
        except UnicodeDecodeError:
            pass
        self.output.setPlainText("\n".join(lines))
        self.notify("SM2 解密成功（C3 校验通过）")


class KeygenPage(PageBase):
    page_id = "keygen"
    title = "密钥对生成"
    subtitle = "SM2 / RSA 密钥对生成与私钥派生；输出标准 PEM 与十六进制格式。"

    def build_ui(self) -> None:
        card = self.card("生成")
        self.alg = combo(["SM2", "RSA-2048", "RSA-3072", "RSA-4096"])
        card.add_row("算法", self.alg)
        self.sk_input = TextInput("基于私钥生成：粘贴 SM2 私钥（64 位十六进制 / PEM）或 RSA 私钥（PEM / HEX）", 70, mono=True)
        card.add(self.sk_input)
        gen = primary_button("随机生成密钥对", "play")
        gen.clicked.connect(self.do_generate)
        derive = secondary_button("基于私钥生成")
        derive.clicked.connect(self.do_derive)
        card.add_layout(ActionBar(gen, derive, secondary_button("清空")))
        out = self.card("输出")
        self.output = MonoText("私钥 / 公钥将显示在这里…", 200)
        out.add(self.output)
        out.add_layout(ActionBar(CopyButton(lambda: self.output.toPlainText())))
        self._last_keys: tuple[str, str] = ("", "")

    def do_generate(self) -> None:
        try:
            alg = self.alg.currentText()
            if alg == "SM2":
                sk, pk = sm2.generate_keypair()
                private_pem = keys.sm2_private_to_pem(sk, pk)
                public_pem = keys.sm2_public_to_pem(pk)
                body = "\n".join([
                    f"私钥（HEX）：\n{sk.hex().upper()}",
                    f"公钥（HEX）：\n{pk.hex().upper()}",
                ])
            else:
                bits = int(alg.split("-")[1])
                key = keys.generate_rsa_keypair(bits)
                private_pem = keys.rsa_private_pem(key, pkcs8=True)
                public_pem = keys.rsa_public_pem(key)
                body = ""
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "密钥生成失败")
            return
        self._last_keys = (private_pem, public_pem)
        self.output.setPlainText(
            "\n".join([
                "【私钥 PEM】", private_pem,
                "【公钥 PEM】", public_pem,
                body,
            ])
        )
        self.notify("密钥对生成完成")

    def do_derive(self) -> None:
        text = self.sk_input.toPlainText().strip()
        if not text:
            self.show_error("请先粘贴私钥。")
            return
        try:
            if self.alg.currentText() == "SM2":
                private, public = keys.parse_sm2_private(text)
                if public is None:
                    public = sm2.derive_public_key(private)
                private_pem = keys.sm2_private_to_pem(private, public)
                public_pem = keys.sm2_public_to_pem(public)
                body = "\n".join([f"私钥（HEX）：\n{private.hex().upper()}",
                                  f"公钥（HEX）：\n{public.hex().upper()}"])
            else:
                key = keys.parse_rsa_key(text)
                if not key.has_private():
                    raise ValueError("该密钥不是 RSA 私钥（缺少私钥分量）。")
                private_pem = keys.rsa_private_pem(key, pkcs8=True)
                public_pem = keys.rsa_public_pem(key)
                body = ""
        except Exception as exc:  # noqa: BLE001
            self.show_error(exc, "私钥解析失败")
            return
        self._last_keys = (private_pem, public_pem)
        self.output.setPlainText("\n".join(["【私钥 PEM】", private_pem, "【公钥 PEM】", public_pem, body]))
        self.notify("已根据私钥生成密钥对")
