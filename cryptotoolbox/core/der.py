"""DER / BER 基础解析与构造。

自研原因：asn1crypto 1.5.1 无法解析带未知椭圆曲线 OID（如 SM2）的证书与 CMS，
会导致国密证书链、PDF/OFD 签章等核心功能不可用。本模块按 X.690 实现，
对未知 OID/结构保持宽容（按原始字节返回），并保留每个元素的偏移量用于结构展示。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

# ---------------------------------------------------------------- 标签常量
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_BIT_STRING = 3
TAG_OCTET_STRING = 4
TAG_NULL = 5
TAG_OID = 6
TAG_ENUMERATED = 10
TAG_UTF8_STRING = 12
TAG_SEQUENCE = 16
TAG_SET = 17
TAG_NUMERIC_STRING = 18
TAG_PRINTABLE_STRING = 19
TAG_T61_STRING = 20
TAG_IA5_STRING = 22
TAG_UTC_TIME = 23
TAG_GENERALIZED_TIME = 24
TAG_VISIBLE_STRING = 26
TAG_BMP_STRING = 30

_STRING_TAGS = {
    TAG_UTF8_STRING, TAG_NUMERIC_STRING, TAG_PRINTABLE_STRING, TAG_T61_STRING,
    TAG_IA5_STRING, TAG_VISIBLE_STRING, TAG_BMP_STRING,
}

TAG_NAMES = {
    TAG_BOOLEAN: "BOOLEAN", TAG_INTEGER: "INTEGER", TAG_BIT_STRING: "BIT STRING",
    TAG_OCTET_STRING: "OCTET STRING", TAG_NULL: "NULL", TAG_OID: "OBJECT IDENTIFIER",
    TAG_ENUMERATED: "ENUMERATED", TAG_UTF8_STRING: "UTF8String",
    TAG_SEQUENCE: "SEQUENCE", TAG_SET: "SET", TAG_PRINTABLE_STRING: "PrintableString",
    TAG_IA5_STRING: "IA5String", TAG_UTC_TIME: "UTCTime", TAG_GENERALIZED_TIME: "GeneralizedTime",
    TAG_T61_STRING: "T61String", TAG_BMP_STRING: "BMPString",
}


class DerError(ValueError):
    pass


@dataclass
class Tlv:
    offset: int
    tag_class: int
    constructed: bool
    tag: int
    header_len: int
    value: bytes
    raw: bytes

    @property
    def end(self) -> int:
        return self.offset + len(self.raw)

    # ------------------------------------------------------------ 类型判断
    @property
    def is_universal(self) -> bool:
        return self.tag_class == UNIVERSAL

    @property
    def is_context(self) -> bool:
        return self.tag_class == CONTEXT

    def type_name(self) -> str:
        if self.tag_class == UNIVERSAL:
            return TAG_NAMES.get(self.tag, f"UNIVERSAL[{self.tag}]")
        prefix = {APPLICATION: "APPLICATION", CONTEXT: "CONTEXT", PRIVATE: "PRIVATE"}[self.tag_class]
        return f"[{prefix} {self.tag}]"

    # ------------------------------------------------------------ 值访问
    def children(self) -> list["Tlv"]:
        if not self.constructed:
            raise DerError(f"{self.type_name()} 不是构造类型，无法取子元素")
        return parse_all(self.value)

    def child(self, tag: int, tag_class: int = UNIVERSAL) -> Optional["Tlv"]:
        for item in self.children():
            if item.tag == tag and item.tag_class == tag_class:
                return item
        return None

    def as_int(self, signed: bool = True) -> int:
        if not self.value:
            return 0
        return int.from_bytes(self.value, "big", signed=signed)

    def as_oid(self) -> str:
        return decode_oid(self.value)

    def as_str(self) -> str:
        if self.tag == TAG_BMP_STRING:
            return self.value.decode("utf-16-be", errors="replace")
        if self.tag == TAG_T61_STRING:
            return self.value.decode("latin-1", errors="replace")
        return self.value.decode("utf-8", errors="replace")

    def as_time(self) -> datetime:
        return decode_time(self.tag, self.value)

    def as_octet_string(self) -> bytes:
        if not self.constructed:
            return self.value
        return b"".join(ch.as_octet_string() for ch in self.children())

    def as_bit_string(self) -> tuple[bytes, int]:
        if not self.value:
            return b"", 0
        unused = self.value[0]
        return self.value[1:], unused

    def as_bits(self, length: int) -> list[bool]:
        data, unused = self.as_bit_string()
        bits: list[bool] = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append(bool(byte & (1 << i)))
        if unused:
            bits = bits[: len(bits) - unused]
        return bits[:length]

    def as_bool(self) -> bool:
        return self.value != b"\x00"

    def as_any_der(self) -> bytes:
        return self.raw

    def describe(self) -> str:
        """结构树展示用的单行描述。"""
        type_name = self.type_name()
        preview = ""
        try:
            if self.tag == TAG_OID:
                preview = self.as_oid()
            elif self.tag in _STRING_TAGS:
                text = self.as_str()
                preview = text if len(text) <= 80 else text[:80] + "…"
            elif self.tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
                preview = self.as_time().isoformat()
            elif self.tag == TAG_INTEGER:
                value = self.as_int()
                preview = str(value) if abs(value) < 10 ** 18 else f"0x{value:X}"
            elif self.tag == TAG_OCTET_STRING:
                hex_str = self.value.hex().upper()
                preview = hex_str if len(hex_str) <= 64 else hex_str[:64] + "…"
            elif self.tag == TAG_BIT_STRING:
                data, unused = self.as_bit_string()
                text = data.hex().upper()
                preview = text if len(text) <= 64 else text[:64] + "…"
            elif self.tag == TAG_NULL:
                preview = "NULL"
        except DerError:
            preview = self.value.hex().upper()[:64]
        size = len(self.value)
        return f"{type_name} ({size} 字节)" + (f" = {preview}" if preview else "")


# ---------------------------------------------------------------- 解析
def parse_tlv(data: bytes, offset: int = 0) -> Tlv:
    data = bytes(data)
    start = offset
    if offset >= len(data):
        raise DerError("数据结束，无法读取标签")
    first = data[offset]
    offset += 1
    tag_class = (first & 0xC0) >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:  # 高标号标签
        tag = 0
        while True:
            if offset >= len(data):
                raise DerError("高标号标签截断")
            byte = data[offset]
            offset += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    if offset >= len(data):
        raise DerError("数据结束，无法读取长度")
    length_byte = data[offset]
    offset += 1
    if length_byte == 0x80:  # BER 不定长
        if not constructed:
            raise DerError("非构造类型不允许不定长长度")
        content_start = offset
        while True:
            if data[offset:offset + 2] == b"\x00\x00":
                content_end = offset
                offset += 2
                break
            if offset >= len(data):
                raise DerError("不定长内容未正确结束")
            child = parse_tlv(data, offset)
            offset = child.end
        return Tlv(start, tag_class, constructed, tag, content_start - start,
                   data[content_start:content_end], data[start:offset])
    if length_byte & 0x80:
        n = length_byte & 0x7F
        if n == 0 or n > 8:
            raise DerError(f"不支持的长度编码（{n} 字节）")
        if offset + n > len(data):
            raise DerError("长度字段截断")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = length_byte
    if offset + length > len(data):
        raise DerError(f"长度越界：声明 {length} 字节，剩余 {len(data) - offset} 字节")
    return Tlv(start, tag_class, constructed, tag, offset - start,
               data[offset:offset + length], data[start:offset + length])


def parse_all(data: bytes) -> list[Tlv]:
    result: list[Tlv] = []
    offset = 0
    while offset < len(data):
        item = parse_tlv(data, offset)
        result.append(item)
        offset = item.end
    return result


def split_top_level(data: bytes) -> list[bytes]:
    """把连续 DER 对象按 TLV 边界切分（用于多证书拼接缓冲区）。"""
    data = bytes(data)
    result: list[bytes] = []
    offset = 0
    while offset < len(data):
        # 跳过零填充
        while offset < len(data) and data[offset] == 0:
            offset += 1
        if offset >= len(data):
            break
        try:
            item = parse_tlv(data, offset)
        except DerError:
            result.append(data[offset:])
            break
        result.append(item.raw)
        offset = item.end
    return result


# ---------------------------------------------------------------- 构造
def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def build_tlv(tag_byte: int, content: bytes) -> bytes:
    return bytes([tag_byte]) + encode_length(len(content)) + content


def build_sequence(*items: bytes) -> bytes:
    return build_tlv(0x30, b"".join(items))


def build_set(*items: bytes) -> bytes:
    return build_tlv(0x31, b"".join(items))


def build_integer(value: int) -> bytes:
    if value == 0:
        return b"\x02\x01\x00"
    if value > 0:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return build_tlv(0x02, raw)
    length = (abs(value).bit_length() + 8) // 8
    raw = value.to_bytes(length, "big", signed=True)
    return build_tlv(0x02, raw)


def build_oid(oid: str) -> bytes:
    return build_tlv(0x06, encode_oid(oid))


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip().split(".")]
    if len(parts) < 2:
        raise DerError(f"非法 OID：{oid}")
    first = 40 * parts[0] + parts[1]
    out = bytearray([first])
    for number in parts[2:]:
        if number < 0:
            raise DerError(f"非法 OID 分量：{number}")
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append((number & 0x7F) | 0x80)
            number >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


# ---------------------------------------------------------------- 时间
import re as _re


def decode_time(tag: int, raw: bytes) -> datetime:
    """解析 UTCTime / GeneralizedTime，返回 UTC 时区感知的 datetime。"""
    text = raw.decode("ascii", errors="replace").strip()
    offset = timedelta(0)
    match = _re.search(r"([+-])(\d{2})(\d{2})?$", text)
    if match:
        text = text[: match.start()]
        delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3) or 0))
        offset = delta if match.group(1) == "+" else -delta
    if text.endswith(("Z", "z")):
        text = text[:-1]
    if "." in text:
        text = text.split(".", 1)[0]
    if tag == TAG_UTC_TIME or len(text) in (10, 12):
        # UTCTime：YYMMDDHHMM[SS]
        if len(text) == 10:
            text += "00"
        if len(text) != 12:
            raise DerError(f"无法解析 UTCTime：{raw!r}")
        year = int(text[0:2])
        year += 1900 if year >= 50 else 2000
        month, day = int(text[2:4]), int(text[4:6])
        hour, minute, second = int(text[6:8]), int(text[8:10]), int(text[10:12])
    else:
        # GeneralizedTime：YYYYMMDDHHMMSS
        if len(text) < 14:
            raise DerError(f"无法解析 GeneralizedTime：{raw!r}")
        year, month, day = int(text[0:4]), int(text[4:6]), int(text[6:8])
        hour, minute, second = int(text[8:10]), int(text[10:12]), int(text[12:14])
    if second >= 60:  # 闰秒
        second = 59
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc) - offset


# ---------------------------------------------------------------- Name / RDN
NAME_OID_LABELS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "STREET",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.17": "postalCode", "2.5.4.5": "serialNumber",
    "2.5.4.4": "SN", "2.5.4.42": "GN", "2.5.4.12": "title", "2.5.4.13": "description",
    "2.5.4.41": "name", "2.5.4.45": "x500UniqueIdentifier",
    "0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.1.9.2": "unstructuredName", "2.5.4.46": "dnQualifier",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}


@dataclass
class AttributeTypeAndValue:
    oid: str
    label: str
    value: str
    raw: bytes


@dataclass
class Name:
    raw: bytes
    rdns: list[list[AttributeTypeAndValue]] = field(default_factory=list)

    def text(self, sep: str = ", ") -> str:
        parts = []
        for rdn in self.rdns:
            for ava in rdn:
                parts.append(f"{ava.label}={ava.value}")
        return sep.join(parts)

    def common_name(self) -> str:
        for rdn in self.rdns:
            for ava in rdn:
                if ava.oid == "2.5.4.3":
                    return ava.value
        return ""

    def values(self, oid: str) -> list[str]:
        return [ava.value for rdn in self.rdns for ava in rdn if ava.oid == oid]


def parse_name(tlv: Tlv) -> Name:
    if tlv.tag != TAG_SEQUENCE:
        raise DerError(f"Name 应为 SEQUENCE，实际为 {tlv.type_name()}")
    rdns: list[list[AttributeTypeAndValue]] = []
    for set_tlv in tlv.children():
        if set_tlv.tag != TAG_SET:
            raise DerError("RDN 应为 SET")
        rdn: list[AttributeTypeAndValue] = []
        for seq in set_tlv.children():
            if seq.tag != TAG_SEQUENCE:
                continue
            children = seq.children()
            if len(children) < 2:
                continue
            oid = children[0].as_oid()
            value_tlv = children[1]
            if value_tlv.tag in _STRING_TAGS:
                value = value_tlv.as_str()
            elif value_tlv.tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
                value = value_tlv.as_time().isoformat()
            else:
                value = value_tlv.value.hex().upper()
            rdn.append(AttributeTypeAndValue(
                oid=oid,
                label=NAME_OID_LABELS.get(oid, oid),
                value=value,
                raw=seq.raw,
            ))
        rdns.append(rdn)
    return Name(raw=tlv.raw, rdns=rdns)


# ---------------------------------------------------------------- 结构树
def tree_lines(data: bytes, max_depth: int = 12, max_lines: int = 4000) -> list[str]:
    """把 DER 数据解析为可读的层级结构行（偏移 / 深度 / 标签 / 预览）。"""
    lines: list[str] = []

    def walk(tlv: Tlv, depth: int) -> None:
        if len(lines) >= max_lines:
            return
        indent = "  " * depth
        lines.append(f"{indent}{tlv.offset:06d}  {tlv.describe()}")
        if depth >= max_depth or not tlv.constructed:
            return
        try:
            for child in tlv.children():
                walk(child, depth + 1)
        except DerError:
            lines.append(f"{indent}  <无法解析子结构>")

    for top in parse_all(bytes(data)):
        walk(top, 0)
    return lines
