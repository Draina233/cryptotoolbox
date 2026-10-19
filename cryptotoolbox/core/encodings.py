"""严格的编码/解码工具。

设计原则（修复原项目“静默清洗”问题）：
- 十六进制：只允许空白、冒号、逗号、分号、下划线、0x 前缀作为分隔，其余字符一律报错；
  长度为奇数直接报错，绝不自动补 0。
- Base64：严格模式校验字符集与长度；宽松模式才自动补 padding 并忽略非法字符。
- 所有错误信息为中文，指出出错位置或原因。
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

TEXT = "字符串"
HEX = "十六进制"
BASE64 = "Base64"
BASE32 = "Base32"
URL = "URL 编码"
PEM = "PEM/DER"

DATA_FORMATS = [TEXT, HEX, BASE64, BASE32, URL]
CERT_FORMATS = [PEM, HEX, BASE64]

_HEX_SEPARATORS = re.compile(r"[\s:;,_\-]")
_HEX_PREFIX = re.compile(r"0x", re.IGNORECASE)


class EncodingError(ValueError):
    pass


def normalize_hex(text: str) -> str:
    """去掉分隔符与 0x 前缀，得到连续十六进制串。"""
    cleaned = _HEX_PREFIX.sub("", text or "")
    cleaned = _HEX_SEPARATORS.sub("", cleaned)
    return cleaned


def hex_decode(text: str) -> bytes:
    cleaned = normalize_hex(text)
    if not cleaned:
        raise EncodingError("十六进制输入为空。")
    invalid = [ch for ch in cleaned if ch not in "0123456789abcdefABCDEF"]
    if invalid:
        raise EncodingError(f"十六进制输入包含非法字符：{invalid[0]!r}（只允许 0-9、A-F 与常见分隔符）。")
    if len(cleaned) % 2:
        raise EncodingError(
            f"十六进制长度为奇数（{len(cleaned)} 个字符），无法按字节解析；请检查是否漏写或多写了一位。"
        )
    return bytes.fromhex(cleaned)


def hex_encode(data: bytes, upper: bool = True) -> str:
    text = bytes(data).hex()
    return text.upper() if upper else text


def base64_decode(text: str, strict: bool = True) -> bytes:
    cleaned = re.sub(r"\s+", "", text or "")
    if not cleaned:
        raise EncodingError("Base64 输入为空。")
    if strict:
        invalid = [ch for ch in cleaned if ch not in
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"]
        if invalid:
            raise EncodingError(f"Base64 输入包含非法字符：{invalid[0]!r}。")
        padded = cleaned + "=" * (-len(cleaned) % 4)
        try:
            return base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EncodingError(f"Base64 解析失败：{exc}") from exc
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4))
    except (binascii.Error, ValueError) as exc:
        raise EncodingError(f"Base64 解析失败：{exc}") from exc


def base64_encode(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def base32_decode(text: str, strict: bool = True) -> bytes:
    cleaned = re.sub(r"\s+", "", text or "").upper()
    if not cleaned:
        raise EncodingError("Base32 输入为空。")
    if strict:
        invalid = [ch for ch in cleaned if ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="]
        if invalid:
            raise EncodingError(f"Base32 输入包含非法字符：{invalid[0]!r}。")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise EncodingError(f"Base32 解析失败：{exc}") from exc


def base32_encode(data: bytes) -> str:
    return base64.b32encode(bytes(data)).decode("ascii")


def url_decode(text: str) -> bytes:
    return urllib.parse.unquote_to_bytes(text or "")


def url_encode(data: bytes, safe: str = "") -> str:
    return urllib.parse.quote_from_bytes(bytes(data), safe=safe)


def decode(text: str, fmt: str, *, strict: bool = True) -> bytes:
    """按界面格式标签把文本解码为字节。"""
    if fmt in (TEXT, "文本", "字符串"):
        return (text or "").encode("utf-8")
    if fmt in (HEX, "十六进制"):
        return hex_decode(text)
    if fmt in (BASE64, "Base64"):
        return base64_decode(text, strict=strict)
    if fmt in (BASE32, "Base32"):
        return base32_decode(text, strict=strict)
    if fmt in (URL, "URL 编码"):
        return url_decode(text)
    raise EncodingError(f"不支持的输入格式：{fmt}")


def encode(data: bytes, fmt: str) -> str:
    if fmt in (TEXT, "文本", "字符串"):
        try:
            return bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EncodingError(
                "字节序列不是合法 UTF-8 文本，无法按“字符串”输出；请改用十六进制或 Base64 输出。"
            ) from exc
    if fmt in (HEX, "十六进制"):
        return hex_encode(data)
    if fmt in (BASE64, "Base64"):
        return base64_encode(data)
    if fmt in (BASE32, "Base32"):
        return base32_encode(data)
    if fmt in (URL, "URL 编码"):
        return url_encode(data)
    raise EncodingError(f"不支持的输出格式：{fmt}")


def looks_like_hex(text: str) -> bool:
    cleaned = normalize_hex(text or "")
    return bool(cleaned) and len(cleaned) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in cleaned)


def looks_like_base64(text: str) -> bool:
    cleaned = re.sub(r"\s+", "", text or "")
    if len(cleaned) < 8 or len(cleaned) % 4:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", cleaned):
        return False
    try:
        base64.b64decode(cleaned, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def sniff(text: str) -> str:
    """粗略嗅探文本格式：pem / hex / base64 / text。"""
    stripped = (text or "").strip()
    if "-----BEGIN" in stripped:
        return PEM
    if looks_like_hex(stripped):
        return HEX
    if looks_like_base64(stripped):
        return BASE64
    return TEXT


def display_text(data: bytes) -> str:
    """用于结果展示：可解码为 UTF-8 则返回文本，否则返回十六进制。"""
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return hex_encode(data)


def hex_dump(data: bytes, width: int = 16, limit: int | None = None, ascii_col: bool = True) -> str:
    """生成带偏移量与 ASCII 列的十六进制视图。"""
    raw = bytes(data)
    shown = raw[:limit] if limit is not None else raw
    lines = []
    for offset in range(0, len(shown), width):
        chunk = shown[offset:offset + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        if ascii_col:
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_part = f"{hex_part:<{width * 3 - 1}}"
            lines.append(f"{offset:08X}  {hex_part}  |{ascii_part}|")
        else:
            lines.append(f"{offset:08X}  {hex_part}")
    if limit is not None and len(raw) > limit:
        lines.append(f"……（共 {len(raw)} 字节，仅显示前 {limit} 字节）")
    return "\n".join(lines)
