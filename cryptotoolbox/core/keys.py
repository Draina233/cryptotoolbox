"""密钥与证书输入的解析/格式化：PEM、DER、HEX、Base64。

- PEM 编解码（多块、带标签）
- RSA 密钥：PyCryptodome 解析/导出/生成
- SM2 密钥：自研解析（PKCS#8 / RFC 5915 EC PRIVATE KEY / SPKI），生成与导出
- 证书输入：PEM/DER/HEX/Base64 多证书
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from . import encodings
from .der import (
    DerError,
    TAG_BIT_STRING,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    build_oid,
    build_sequence,
    build_tlv,
    parse_tlv,
    split_top_level,
)
from .x509 import Certificate, CertificateError, parse_certificate

SM2_CURVE_OID = "1.2.156.10197.1.301"
EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"

_PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


class KeyFormatError(ValueError):
    pass


# ---------------------------------------------------------------- PEM
def unarmor(text: str) -> list[tuple[str, bytes]]:
    blocks: list[tuple[str, bytes]] = []
    for match in _PEM_RE.finditer(text or ""):
        label = match.group(1).strip()
        body = re.sub(r"\s+", "", match.group(2))
        try:
            der = base64.b64decode(body + "=" * (-len(body) % 4))
        except Exception as exc:  # noqa: BLE001
            raise KeyFormatError(f"PEM 块“{label}”Base64 解码失败：{exc}") from exc
        blocks.append((label, der))
    return blocks


def armor(label: str, der: bytes) -> str:
    body = base64.b64encode(bytes(der)).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def looks_like_pem(text: str) -> bool:
    return "-----BEGIN" in (text or "")


# ---------------------------------------------------------------- SM2 密钥
@dataclass
class SM2KeyPair:
    private: bytes | None
    public: bytes | None
    curve_oid: str = ""


def _parse_ec_private_key(der: bytes) -> tuple[bytes, bytes | None]:
    """RFC 5915 ECPrivateKey → (32 字节私钥, 可选 65 字节公钥)。"""
    top = parse_tlv(der)
    if top.tag != TAG_SEQUENCE:
        raise KeyFormatError("EC PRIVATE KEY 结构异常。")
    items = top.children()
    if len(items) < 2:
        raise KeyFormatError("EC PRIVATE KEY 结构不完整。")
    private = items[1].as_octet_string()
    if len(private) != 32:
        # 可能带前导 0x00
        private = private.rjust(32, b"\x00")
    public = None
    for item in items[2:]:
        if item.tag_class == 2 and item.tag == 1:
            bits, _ = item.as_bit_string()
            if bits:
                public = bits if bits[0] == 0x04 else b"\x04" + bits
    return private, public


def parse_sm2_private(data: bytes | str) -> tuple[bytes, bytes | None]:
    """接受 PEM 文本、DER 字节或 64 位十六进制字符串。返回 (私钥 32B, 公钥 65B 或 None)。"""
    if isinstance(data, str):
        text = data.strip()
        if looks_like_pem(text):
            blocks = unarmor(text)
            for label, der in blocks:
                if label == "EC PRIVATE KEY":
                    return _parse_ec_private_key(der)
                if label == "PRIVATE KEY":  # PKCS#8
                    top = parse_tlv(der)
                    items = top.children()
                    if len(items) < 3 or items[2].tag != TAG_OCTET_STRING:
                        raise KeyFormatError("PKCS#8 私钥结构异常。")
                    return _parse_ec_private_key(items[2].value)
            raise KeyFormatError("PEM 中没有找到 EC PRIVATE KEY / PRIVATE KEY 块。")
        text = text.replace("0x", "")
        if re.fullmatch(r"[0-9a-fA-F]{64}", text):
            return bytes.fromhex(text), None
        # 其他文本按 DER HEX 尝试
        try:
            raw = encodings.hex_decode(text)
        except encodings.EncodingError:
            raw = None
        if raw:
            try:
                return _parse_ec_private_key(raw)
            except (DerError, KeyFormatError):
                pass
        raise KeyFormatError("无法识别的 SM2 私钥格式：请提供 EC PRIVATE KEY / PRIVATE KEY PEM 或 64 位十六进制。")
    return _parse_ec_private_key(bytes(data))


def parse_sm2_public(data: bytes | str) -> bytes:
    """接受 PEM(SPKI)、DER、64/65 字节十六进制。返回 65 字节公钥。"""
    if isinstance(data, str):
        text = data.strip()
        if looks_like_pem(text):
            for label, der in unarmor(text):
                if label == "PUBLIC KEY":
                    top = parse_tlv(der)
                    items = top.children()
                    if len(items) < 2:
                        raise KeyFormatError("PUBLIC KEY 结构异常。")
                    bits, _ = items[1].as_bit_string()
                    return bits
            raise KeyFormatError("PEM 中没有找到 PUBLIC KEY 块。")
        text = text.replace("0x", "")
        text = re.sub(r"[\s:;,_]", "", text)
        if len(text) in (128, 130):
            raw = bytes.fromhex(text)
            return b"\x04" + raw if len(raw) == 64 else raw
        raise KeyFormatError("无法识别的 SM2 公钥格式：请提供 PUBLIC KEY PEM 或 128/130 位十六进制。")
    raw = bytes(data)
    if len(raw) == 64:
        return b"\x04" + raw
    return raw


def sm2_private_to_pem(private: bytes, public: bytes | None = None,
                       public_derived: bytes | None = None) -> str:
    """输出 EC PRIVATE KEY（RFC 5915，含 SM2 曲线参数与公钥）。"""
    private = bytes(private)
    pub = public or public_derived
    items = [
        build_tlv(0x02, b"\x01"),          # version 1
        build_tlv(0x04, private),          # privateKey
        build_tlv(0xA0, build_oid(SM2_CURVE_OID)),  # parameters [0] OID
    ]
    if pub:
        items.append(build_tlv(0x81, b"\x00" + bytes(pub)))  # publicKey [1] BIT STRING
    return armor("EC PRIVATE KEY", build_sequence(*items))


def sm2_public_to_pem(public: bytes) -> str:
    spki = build_sequence(
        build_sequence(build_oid(SM2_CURVE_OID), build_oid(SM2_CURVE_OID)),
        build_tlv(0x03, b"\x00" + bytes(public)),
    )
    return armor("PUBLIC KEY", spki)


def generate_sm2_keypair() -> tuple[bytes, bytes]:
    from . import sm2

    return sm2.generate_keypair()


# ---------------------------------------------------------------- RSA 密钥
def parse_rsa_key(data: bytes | str):
    """返回 PyCryptodome RSA 密钥对象（公钥或私钥）。"""
    from Crypto.PublicKey import RSA

    if isinstance(data, str):
        text = data.strip()
        if looks_like_pem(text):
            try:
                return RSA.import_key(text)
            except (ValueError, IndexError) as exc:
                raise KeyFormatError(f"RSA 密钥解析失败：{exc}") from exc
        text = text.replace("0x", "")
        cleaned = re.sub(r"[\s:;,_]", "", text)
        if re.fullmatch(r"[0-9a-fA-F]+", cleaned):
            if len(cleaned) % 2:
                raise KeyFormatError("RSA 密钥 HEX 长度为奇数。")
            try:
                return RSA.import_key(bytes.fromhex(cleaned))
            except (ValueError, IndexError) as exc:
                raise KeyFormatError(f"RSA 密钥解析失败：{exc}") from exc
        raise KeyFormatError("无法识别的 RSA 密钥格式：请提供 PEM 或 DER HEX。")
    try:
        return RSA.import_key(bytes(data))
    except (ValueError, IndexError) as exc:
        raise KeyFormatError(f"RSA 密钥解析失败：{exc}") from exc


def generate_rsa_keypair(bits: int = 2048):
    from Crypto.PublicKey import RSA

    if bits not in (1024, 2048, 3072, 4096):
        raise KeyFormatError("RSA 密钥长度应为 1024/2048/3072/4096 位。")
    return RSA.generate(bits)


def rsa_private_pem(key, pkcs8: bool = False) -> str:
    return key.export_key(format="PEM", pkcs=8 if pkcs8 else 1).decode("ascii")


def rsa_public_pem(key) -> str:
    return key.publickey().export_key(format="PEM").decode("ascii")


# ---------------------------------------------------------------- 证书输入
def parse_certificates_text(text: str, fmt: str = "PEM/DER") -> list[tuple[bytes, Certificate | None, str | None]]:
    """解析多证书输入。返回 [(DER, Certificate 或 None, 错误信息或 None)]。"""
    text = text or ""
    if looks_like_pem(text):
        results = []
        for label, der in unarmor(text):
            if label != "CERTIFICATE":
                continue
            try:
                results.append((der, parse_certificate(der), None))
            except CertificateError as exc:
                results.append((der, None, str(exc)))
        if not results:
            raise KeyFormatError("PEM 中没有找到 CERTIFICATE 块。")
        return results

    raw: bytes
    if fmt in ("十六进制", "HEX", "hex"):
        raw = encodings.hex_decode(text)
    elif fmt in ("Base64", "BASE64", "base64"):
        raw = encodings.base64_decode(text, strict=False)
    else:
        if encodings.looks_like_hex(text):
            raw = encodings.hex_decode(text)
        elif encodings.looks_like_base64(text):
            raw = encodings.base64_decode(text, strict=False)
        else:
            raw = text.encode("utf-8")

    chunks = split_top_level(raw)
    if not chunks:
        raise KeyFormatError("输入中没有可解析的 DER 数据。")
    results = []
    for chunk in chunks:
        try:
            results.append((chunk, parse_certificate(chunk), None))
        except CertificateError as exc:
            results.append((chunk, None, str(exc)))
    return results


def certificate_to_pem(der: bytes) -> str:
    return armor("CERTIFICATE", der)

