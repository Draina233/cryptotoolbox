"""电子签章校验：PDF 与 OFD。

支持两类容器：
1. 标准 CMS/PKCS#7（PDF detached/attached）——按 SignerInfo 匹配证书并验签
2. 国密电子印章容器（GB/T 38540 / GM/T 0031 形态）：
   - PDF：SEQUENCE { SEQUENCE { 印章信息/时间/文档摘要/证书/算法 }, 签名值 BIT STRING }
     签名覆盖内层结构；内嵌文档摘要（SM3）用于核对 PDF ByteRange 原文
   - OFD：Seal.esl = SEQUENCE { 印章信息, 证书 OCTET STRING, 算法 OID, 签名 BIT STRING }
     SignedValue.dat = SEQUENCE { 签章数据, 证书, 算法 OID, 签名 }，签章数据内含时间与 Signature.xml 的 SM3；
     Signature.xml 的 References/CheckValue 用于逐个文件完整性校验
三态结论：通过 / 未通过 / 未知，无法识别或无法验证时绝不显示为通过。
"""
from __future__ import annotations

import base64
import hashlib
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import cms, pkcs7
from .cert import HASH_OID_MAP, verify_signature
from .der import DerError, TAG_BIT_STRING, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, parse_tlv
from .digest import sm3
from .result import FAIL, PASS, SKIP, UNKNOWN, CheckResult, Report
from .x509 import Certificate, parse_certificate

MAX_FILE_BYTES = 60 * 1024 * 1024

SM2_SM3_OID = "1.2.156.10197.1.501"
KNOWN_SIG_OIDS = {
    "1.2.156.10197.1.501", "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3", "1.2.840.113549.1.1.1",
}
OID_LABELS = {
    "1.2.156.10197.1.501": "SM3withSM2",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.5": "SHA1withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.13": "SHA512withRSA",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.113549.1.1.1": "RSA (PKCS#1 v1.5)",
}


class SealError(ValueError):
    pass


@dataclass
class SealContainer:
    signed_data: bytes
    cert: Optional[Certificate]
    certs: list[Certificate]
    algorithm_oid: str
    signature: bytes
    hash_value: Optional[bytes] = None
    sign_time: Optional[datetime] = None
    path: str = ""


@dataclass
class SignatureDetail:
    kind: str
    index: int
    certificates: list[Certificate] = field(default_factory=list)
    signer: Optional[Certificate] = None
    signature_hex: str = ""
    contents_hex: str = ""
    signed_bytes: int = 0
    byte_range: list[int] = field(default_factory=list)
    sign_time: str = ""
    filter_name: str = ""
    sub_filter: str = ""
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- 通用
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sm3_hex(data: bytes) -> str:
    return sm3(data).hex().upper()


def _cert_validity_row(report: Report, key: str, cert: Certificate, now: datetime) -> None:
    status = cert.time_status(now)
    report.add(key, "证书有效期", PASS if status == "有效期内" else FAIL,
               f"{cert.validity_text()}（{status}）")


def _cert_rows(report: Report, prefix: str, cert: Certificate, now: datetime) -> None:
    _cert_validity_row(report, f"{prefix}-validity", cert, now)
    report.add(f"{prefix}-subject", "签名者", PASS, cert.subject.text())
    report.add(f"{prefix}-issuer", "颁发者", PASS, cert.issuer.text())


def _verify_container(container: SealContainer) -> tuple[Optional[bool], str]:
    """验证容器签名（覆盖 signed_data）。返回 (True/False/None, 说明)。"""
    if container.cert is None:
        return None, "签名容器中未找到可解析的证书，无法验证签名。"
    oid = container.algorithm_oid
    label = OID_LABELS.get(oid, oid)
    try:
        ok, message = verify_signature(
            spki=container.cert.spki,
            signature_algorithm_oid=oid,
            signature_algorithm_params=b"",
            data=container.signed_data,
            signature=container.signature,
            signer_uid=[container.cert.subject.raw, b"", b"1234567812345678"],
        )
        return ok, message if ok else message
    except Exception as exc:  # noqa: BLE001
        return None, f"签名算法暂不支持或验签异常（{label}）：{exc}"


# ---------------------------------------------------------------- 容器解析
def _cert_from_octet(value: bytes) -> Optional[Certificate]:
    for candidate in (value, value.lstrip(b"\x00")):
        try:
            return parse_certificate(candidate)
        except Exception:  # noqa: BLE001
            continue
    try:
        tlv = parse_tlv(value)
        return parse_certificate(tlv.raw)
    except Exception:  # noqa: BLE001
        return None


def _collect_certs(tlv, depth: int = 0) -> list[Certificate]:
    certs: list[Certificate] = []
    seen: set[bytes] = set()

    def walk(node, level: int) -> None:
        if level > 8:
            return
        if node.tag == TAG_SEQUENCE:
            try:
                cert = parse_certificate(node.raw)
                if cert.der not in seen:
                    certs.append(cert)
                    seen.add(cert.der)
                return
            except Exception:  # noqa: BLE001
                pass
        if node.tag == TAG_OCTET_STRING:
            cert = _cert_from_octet(node.value)
            if cert is not None and cert.der not in seen:
                certs.append(cert)
                seen.add(cert.der)
            return
        if node.constructed:
            try:
                for child in node.children():
                    walk(child, level + 1)
            except DerError:
                return

    walk(tlv, depth)
    return certs


def _find_signature_oid(tlv) -> str:
    """在结构中寻找签名算法 OID（优先已知签名算法）。"""
    found = []

    def walk(node, level: int) -> None:
        if level > 6:
            return
        if node.tag == TAG_OID:
            oid = node.as_oid()
            if oid in KNOWN_SIG_OIDS:
                found.append(oid)
        elif node.constructed:
            try:
                for child in node.children():
                    walk(child, level + 1)
            except DerError:
                return

    walk(tlv, 0)
    return found[0] if found else ""


def _find_bit_string(tlv, length: int, depth: int = 0) -> Optional[bytes]:
    if depth > 6:
        return None
    if tlv.tag == TAG_BIT_STRING:
        data, _unused = tlv.as_bit_string()
        if len(data) == length:
            return data
        return None
    if tlv.constructed:
        try:
            for child in tlv.children():
                found = _find_bit_string(child, length, depth + 1)
                if found is not None:
                    return found
        except DerError:
            return None
    return None


_TIME_ASCII = re.compile(rb"^(\d{10}|\d{12}|\d{14})Z?$")


def _find_sign_time(tlv, depth: int = 0) -> Optional[datetime]:
    """寻找时间：GeneralizedTime/UTCTime 或 BIT STRING 内的 ASCII 时间（YYMMDDHHMMSSZ）。"""
    if depth > 6:
        return None
    if tlv.tag in (23, 24):
        try:
            return tlv.as_time()
        except DerError:
            return None
    if tlv.tag == TAG_BIT_STRING:
        data, _ = tlv.as_bit_string()
        if _TIME_ASCII.match(data):
            try:
                from .der import TAG_UTC_TIME, decode_time

                return decode_time(TAG_UTC_TIME if len(data) in (10, 12) else 24, data)
            except Exception:  # noqa: BLE001
                return None
        return None
    if tlv.constructed:
        try:
            for child in tlv.children():
                found = _find_sign_time(child, depth + 1)
                if found is not None:
                    return found
        except DerError:
            return None
    return None


def _find_path(tlv, depth: int = 0) -> str:
    if depth > 6:
        return ""
    if tlv.tag == 22:  # IA5String
        text = tlv.as_str()
        if text:
            return text
        return ""
    if tlv.constructed:
        try:
            for child in tlv.children():
                found = _find_path(child, depth + 1)
                if found:
                    return found
        except DerError:
            return ""
    return ""


def parse_container(der: bytes) -> Optional[SealContainer]:
    """解析国密电子印章/签章容器。支持：
    A) SEQUENCE { 内层结构, 签名值 BIT STRING }（PDF 电子印章）
    B) SEQUENCE { 签章数据, 证书 OCTET STRING, 算法 OID, 签名值 BIT STRING }（OFD）
    """
    try:
        top = parse_tlv(der)
        items = top.children()
    except DerError:
        return None
    if len(items) == 2 and items[0].tag == TAG_SEQUENCE and items[1].tag == TAG_BIT_STRING:
        inner = items[0]
        signature, _ = items[1].as_bit_string()
        if not signature:
            return None
        direct_cert: Optional[Certificate] = None
        direct_oid = ""
        try:
            inner_children = inner.children()
        except DerError:
            inner_children = []
        for child in inner_children:
            if child.tag == TAG_OCTET_STRING and direct_cert is None:
                direct_cert = _cert_from_octet(child.value)
            elif child.tag == TAG_OID and not direct_oid:
                direct_oid = child.as_oid()
        oid = direct_oid if direct_oid in KNOWN_SIG_OIDS else _find_signature_oid(inner)
        if not oid:
            return None
        certs = _collect_certs(inner)
        cert = direct_cert or (certs[0] if certs else None)
        return SealContainer(
            signed_data=inner.raw, cert=cert, certs=certs,
            algorithm_oid=oid, signature=signature,
            hash_value=_find_bit_string(inner, 32), sign_time=_find_sign_time(inner),
            path=_find_path(inner),
        )
    if (len(items) == 4 and items[0].tag == TAG_SEQUENCE and items[1].tag == TAG_OCTET_STRING
            and items[2].tag == TAG_OID and items[3].tag == TAG_BIT_STRING):
        inner = items[0]
        cert = _cert_from_octet(items[1].value)
        if cert is None:
            return None
        signature, _ = items[3].as_bit_string()
        if not signature:
            return None
        return SealContainer(
            signed_data=inner.raw, cert=cert, certs=[cert] if cert else [],
            algorithm_oid=items[2].as_oid(), signature=signature,
            hash_value=_find_bit_string(inner, 32), sign_time=_find_sign_time(inner),
            path=_find_path(inner),
        )
    return None


# ---------------------------------------------------------------- PDF
def _find_pdf_signatures(pdf_bytes: bytes) -> list[dict]:
    """查找 /ByteRange 并定位对应的 /Contents 值（支持 < hex > 与 ( literal )）。"""
    results: list[dict] = []
    for match in re.finditer(rb"/ByteRange\s*\[\s*([0-9\s]+)\]", pdf_bytes):
        numbers = [int(x) for x in re.findall(rb"\d+", match.group(1))]
        if len(numbers) < 4 or len(numbers) % 2:
            continue
        br_start = match.start()
        results.append({"byte_range": numbers, "br_pos": br_start})
    # 补充配对信息：扫描 /Contents 值的起点（结构校验用）
    contents_starts = [m.start() for m in re.finditer(rb"/Contents\s*", pdf_bytes)]
    for item in results:
        br = item["byte_range"]
        if len(br) < 2:
            continue
        start = br[1]
        item["contents_start"] = start
        if contents_starts:
            item["br_pos"] = min(contents_starts, key=lambda p: abs(p - br[0] - br[1]))
    return results


# ---------------------------------------------------------------- PDF 内容解码
def _pdf_unescape(body: bytes) -> bytes:
    out = bytearray()
    j = 0
    mapping = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 40, 0x29: 41, 0x5C: 92}
    while j < len(body):
        c = body[j]
        if c == 0x5C and j + 1 < len(body):
            nxt = body[j + 1]
            if nxt in mapping:
                out.append(mapping[nxt]); j += 2; continue
            if 0x30 <= nxt <= 0x37:
                k = j + 1; value = 0; digits = 0
                while k < len(body) and digits < 3 and 0x30 <= body[k] <= 0x37:
                    value = value * 8 + (body[k] - 0x30); k += 1; digits += 1
                out.append(value & 0xFF); j = k; continue
            out.append(nxt); j += 2; continue
        out.append(c); j += 1
    return bytes(out)


def _trim_tlv(data: bytes) -> bytes:
    data = bytes(data)
    try:
        return parse_tlv(data).raw
    except DerError:
        pass
    index = data.find(b"\x30")
    if index >= 0:
        try:
            return parse_tlv(data, index).raw
        except DerError:
            pass
    return data.rstrip(b"\x00 \r\n\t")


def _decode_pdf_contents(pdf_bytes: bytes, start: int, end: int) -> bytes:
    if start < 0 or end > len(pdf_bytes) or start >= end:
        raise SealError("ByteRange 指向的 Contents 范围非法。")
    marker = pdf_bytes[start:start + 1]
    if marker not in (b"(", b"<"):
        # 容错：在附近寻找定界符
        for delta in range(1, 16):
            if pdf_bytes[start + delta:start + delta + 1] in (b"(", b"<"):
                start = start + delta
                marker = pdf_bytes[start:start + 1]
                break
    if marker == b"(":
        body = pdf_bytes[start + 1:end - 1] if pdf_bytes[end - 1:end] == b")" else pdf_bytes[start + 1:end]
        return _trim_tlv(_pdf_unescape(body))
    if marker == b"<":
        hex_text = re.sub(rb"\s+", b"", pdf_bytes[start + 1:end - 1])
        try:
            return _trim_tlv(bytes.fromhex(hex_text.decode("ascii")))
        except ValueError as exc:
            raise SealError(f"Contents 十六进制解码失败：{exc}") from exc
    raise SealError("无法识别的 /Contents 定界符（既不是 ( 也不是 <）。")


def _reconstruct_ranges(pdf_bytes: bytes, byte_range: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(byte_range), 2):
        if i + 1 >= len(byte_range):
            break
        start, length = byte_range[i], byte_range[i + 1]
        if start < 0 or length < 0 or start + length > len(pdf_bytes):
            raise SealError(f"ByteRange 越界：start={start}, length={length}, 文件 {len(pdf_bytes)} 字节。")
        out.extend(pdf_bytes[start:start + length])
    return bytes(out)


def _pdf_signature_rows(report: Report, pdf_bytes: bytes, item: dict, now: datetime) -> SignatureDetail:
    detail = SignatureDetail(kind="pdf", index=0)
    br = item["byte_range"]
    detail.byte_range = list(br)
    fmt_ok = len(br) >= 4 and len(br) % 2 == 0
    report.add("fmt", "电子签章数据格式正确性", PASS if fmt_ok else FAIL,
               "已发现 /ByteRange 签名域" if fmt_ok else "ByteRange 结构不完整。")
    if not fmt_ok:
        return detail
    start, end = br[1], br[2]
    reason = ""
    consistent = True
    if br[0] != 0:
        consistent = False
        reason = "ByteRange 第一段未从文件起始处开始。"
    elif pdf_bytes[start:start + 1] not in (b"(", b"<"):
        consistent = False
        reason = "ByteRange 指向的位置不是 /Contents 值的定界符。"
    elif pdf_bytes[end - 1:end] not in (b")", b">"):
        # 部分生成器把结束定界符计入签名范围：允许在其后 16 字节内寻找
        tail = pdf_bytes[end - 1:min(len(pdf_bytes), end + 16)]
        if not any(ch in tail for ch in (b")", b">")):
            consistent = False
            reason = "ByteRange 结束位置附近未找到 /Contents 值的结束定界符。"
    elif br[2] + br[3] > len(pdf_bytes):
        consistent = False
        reason = f"ByteRange 超出文件大小（{br[2] + br[3]} > {len(pdf_bytes)}）。"
    report.add("bytrange", "签名覆盖范围（ByteRange）一致性", PASS if consistent else FAIL,
               reason or "签名覆盖除 Contents 值外的全部字节。")
    try:
        signed = _reconstruct_ranges(pdf_bytes, br)
    except SealError as exc:
        report.add("signed", "签名原文还原", FAIL, str(exc))
        return detail
    detail.signed_bytes = len(signed)
    try:
        der = _decode_pdf_contents(pdf_bytes, start, end)
    except SealError as exc:
        report.add("sigval", "电子签章签名值正确性", UNKNOWN, str(exc))
        return detail
    detail.contents_hex = der.hex().upper()
    report.meta["ByteRange"] = " ".join(str(x) for x in br)

    # 1) 标准 CMS
    try:
        ci = cms.parse_content_info(der)
    except Exception:  # noqa: BLE001
        ci = None
    if ci is not None and ci.signed_data is not None:
        _pdf_cms_rows(report, ci.signed_data, der, signed, detail, now)
        return detail

    # 2) 国密电子印章容器
    container = parse_container(der)
    if container is None:
        report.add("sigval", "电子签章签名值正确性", UNKNOWN,
                   "签名容器既不是标准 CMS，也不是可识别的电子印章容器。")
        report.add("digest", "原文摘要匹配", UNKNOWN, "无法解析签名容器中的文档摘要。")
        return detail
    detail.signer = container.cert
    detail.certificates = list(container.certs)
    detail.signature_hex = container.signature.hex().upper()
    alg_label = OID_LABELS.get(container.algorithm_oid, container.algorithm_oid)
    report.add("alg", "签名算法", PASS, f"{alg_label}（{container.algorithm_oid}）")
    report.meta["签名算法"] = alg_label
    if container.cert is not None:
        report.meta["公钥算法"] = container.cert.spki.algorithm_label + (
            f" / {container.cert.spki.curve_label}" if container.cert.spki.curve_label else ""
        )
        report.raw["公钥(HEX)"] = container.cert.spki.key_bits.hex().upper()
    report.raw["签名原文(HEX)"] = container.signed_data.hex().upper()
    report.raw["签名值(HEX)"] = container.signature.hex().upper()
    ok, message = _verify_container(container)
    if ok is None:
        report.add("sigval", "电子签章签名值正确性", UNKNOWN, message)
    else:
        report.add("sigval", "电子签章签名值正确性", PASS if ok else FAIL, message)
    if container.hash_value is None:
        report.add("digest", "原文摘要匹配", UNKNOWN, "签名容器未包含文档摘要，无法核对签名后的文件内容。")
    else:
        actual = sm3(signed)
        if actual == container.hash_value:
            report.add("digest", "原文摘要匹配", PASS, "容器内嵌摘要与 ByteRange 覆盖内容的 SM3 一致。")
        else:
            report.add("digest", "原文摘要匹配", FAIL,
                       "容器内嵌摘要与 ByteRange 覆盖内容的 SM3 不一致（文件可能在签名后被修改）。")
    if container.cert is not None:
        _cert_rows(report, "cert", container.cert, now)
    if container.sign_time is not None:
        detail.sign_time = container.sign_time.isoformat()
        report.add("sign_time", "签章时间", PASS, detail.sign_time)
    else:
        report.add("sign_time", "签章时间", SKIP, "容器中未解析到签章时间。")
    report.note("本工具未内置信任根，证书链信任关系需结合单位 CA/CRL 人工确认。")
    report.raw["签名值"] = detail.signature_hex
    return detail


def _pdf_cms_rows(report: Report, signed_data, der: bytes, signed: bytes,
                  detail: SignatureDetail, now: datetime) -> None:
    report.add("alg", "签名算法", PASS, "CMS / PKCS#7 SignedData")
    certs = []
    for der_cert in signed_data.certificates:
        try:
            certs.append(parse_certificate(der_cert))
        except Exception:  # noqa: BLE001
            continue
    detail.certificates = certs
    if not certs:
        report.add("sigval", "电子签章签名值正确性", UNKNOWN, "签名容器中没有证书。")
        return
    if not signed_data.signer_infos:
        report.add("sigval", "电子签章签名值正确性", UNKNOWN, "签名容器中没有 SignerInfo。")
        return
    signer_info = signed_data.signer_infos[0]
    signer = None
    for cert in certs:
        if signer_info.sid_kind == "issuer_serial" and signer_info.issuer is not None:
            if signer_info.issuer.raw == cert.issuer.raw and signer_info.serial == cert.serial:
                signer = cert
                break
        elif signer_info.subject_key_identifier and signer_info.subject_key_identifier == cert.ski:
            signer = cert
            break
    if signer is None:
        report.add("match", "签章者证书匹配", UNKNOWN, "未找到与 SignerInfo 匹配的证书。")
        return
    detail.signer = signer
    report.add("match", "签章者证书匹配", PASS, signer.subject.text())
    try:
        ok, message = pkcs7.verify_signer_signature(signed_data, signer_info, signer, signed)
        report.add("sigval", "电子签章签名值正确性", PASS if ok else FAIL, message)
    except Exception as exc:  # noqa: BLE001
        report.add("sigval", "电子签章签名值正确性", UNKNOWN, f"验签异常：{exc}")
    status, md_detail = pkcs7.check_message_digest(signed_data, signer_info, signed)
    report.add("digest", "原文摘要匹配", status, md_detail)
    _cert_rows(report, "cert", signer, now)
    st = signer_info.signing_time()
    if st is not None:
        detail.sign_time = st.isoformat()
        report.add("sign_time", "签章时间", PASS, detail.sign_time)
    else:
        report.add("sign_time", "签章时间", SKIP, "签名未包含 signingTime 属性。")
    detail.signature_hex = signer_info.signature.hex().upper()
    detail.contents_hex = der.hex().upper()
    report.meta["签名算法"] = OID_LABELS.get(signer_info.signature_algorithm_oid, signer_info.signature_algorithm_oid)
    report.meta["公钥算法"] = signer.spki.algorithm_label
    report.raw["签名原文(HEX)"] = (signer_info.signed_attrs_raw or signed).hex().upper()
    report.raw["签名值(HEX)"] = detail.signature_hex
    report.raw["公钥(HEX)"] = signer.spki.key_bits.hex().upper()


def verify_pdf(path: str, now: datetime | None = None) -> list[Report]:
    now = now or _now()
    pdf_bytes = Path(path).read_bytes()
    if len(pdf_bytes) > MAX_FILE_BYTES:
        raise SealError(f"文件超过 {MAX_FILE_BYTES // 1024 // 1024} MB 限制。")
    sigs = _find_pdf_signatures(pdf_bytes)
    if not sigs:
        report = Report(title="PDF 电子签章校验")
        report.add("fmt", "电子签章数据格式正确性", FAIL, "未在 PDF 中发现带 /ByteRange 的签名域。")
        return [report]
    reports: list[Report] = []
    for index, item in enumerate(sigs, start=1):
        report = Report(title=f"PDF 签章 {index}")
        detail = _pdf_signature_rows(report, pdf_bytes, item, now)
        detail.index = index
        if detail.certificates:
            report.raw["证书链"] = [c.subject.text() for c in detail.certificates]
        reports.append(report)
    return reports


# ---------------------------------------------------------------- OFD
_XML_REF = re.compile(rb'<(?:[A-Za-z0-9]+:)?Reference\s+FileRef="([^"]+)"[^>]*>\s*<(?:[A-Za-z0-9]+:)?CheckValue>([^<]+)</(?:[A-Za-z0-9]+:)?CheckValue>', re.S)
_XML_VALUE = r'<(?:[A-Za-z0-9]+:)?%s[^>]*>([^<]+)</(?:[A-Za-z0-9]+:)?%s>'


def _xml_value(xml: bytes, tag: str) -> str:
    match = re.search((_XML_VALUE % (tag, tag)).encode(), xml, re.S)
    if not match:
        return ""
    try:
        return match.group(1).strip().decode("utf-8")
    except UnicodeDecodeError:
        return match.group(1).strip().decode("latin-1", errors="replace")


def _parse_signature_xml(xml: bytes) -> dict:
    return {
        "method": _xml_value(xml, "SignatureMethod"),
        "time": _xml_value(xml, "SignatureDateTime"),
        "references": [
            (m.group(1).decode("utf-8", errors="replace"), m.group(2).decode("ascii", errors="replace"))
            for m in _XML_REF.finditer(xml)
        ],
    }


def _ofd_check_references(archive: zipfile.ZipFile, refs: list[tuple[str, str]]) -> tuple[str, str]:
    """返回 (status, detail)。status: PASS/FAIL/UNKNOWN。"""
    if not refs:
        return UNKNOWN, "Signature.xml 未包含引用文件摘要。"
    matched = 0
    mismatches = []
    for path, expected_b64 in refs:
        entry = path.lstrip("/")
        if entry not in archive.namelist():
            mismatches.append(f"{entry}（文件缺失）")
            continue
        actual = base64.b64encode(sm3(archive.read(entry))).decode("ascii")
        if actual == expected_b64.strip():
            matched += 1
        else:
            mismatches.append(entry)
    if not mismatches:
        return PASS, f"{matched}/{len(refs)} 个引用文件的 SM3 摘要与 CheckValue 一致。"
    return FAIL, f"{matched}/{len(refs)} 个文件摘要一致；不一致/缺失：{', '.join(mismatches[:6])}"


def _ofd_signature_dirs(names: list[str]) -> list[str]:
    dirs = set()
    for name in names:
        normalized = name.replace("\\", "/")
        if "/Signs/" in normalized:
            base = normalized.split("/Signs/", 1)[0]
            dirs.add(base + "/Signs")
    return sorted(dirs)


def verify_ofd(path: str, now: datetime | None = None) -> list[Report]:
    now = now or _now()
    if Path(path).stat().st_size > MAX_FILE_BYTES:
        raise SealError(f"文件超过 {MAX_FILE_BYTES // 1024 // 1024} MB 限制。")
    try:
        archive = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise SealError(f"不是有效的 OFD（ZIP）文件：{exc}") from exc
    names = archive.namelist()
    sign_dirs = _ofd_signature_dirs(names)
    if not sign_dirs:
        report = Report(title="OFD 电子签章校验")
        report.add("fmt", "电子签章数据格式正确性", FAIL, "ZIP 内未找到 Signs 目录（可能未签章）。")
        return [report]
    reports: list[Report] = []
    index = 0
    for sroot in sign_dirs:
        prefix = sroot.rstrip("/") + "/"
        seal_files = [n for n in names if n.startswith(prefix) and n.lower().endswith("seal.esl")]
        for seal_name in seal_files:
            index += 1
            report = Report(title=f"OFD 签章 {index}")
            detail = SignatureDetail(kind="ofd", index=index)
            esl = archive.read(seal_name)
            base_dir = seal_name.rsplit("/", 1)[0]
            sv_name = base_dir + "/SignedValue.dat"
            xml_name = base_dir + "/Signature.xml"
            signed_value = archive.read(sv_name) if sv_name in names else b""
            sig_xml = archive.read(xml_name) if xml_name in names else b""
            report.meta["印章文件"] = seal_name

            seal_container = parse_container(esl)
            if seal_container is None:
                certs = _collect_certs(parse_tlv(esl)) if esl else []
                report.add("fmt", "电子签章数据格式正确性", UNKNOWN,
                           "未能识别 Seal.esl 的国密印章结构；已尝试提取证书。")
                for cert in certs[:2]:
                    _cert_rows(report, "cert", cert, now)
                reports.append(report)
                continue
            report.add("fmt", "电子签章数据格式正确性", PASS,
                       f"Seal.esl 识别成功（{OID_LABELS.get(seal_container.algorithm_oid, seal_container.algorithm_oid)}）")
            detail.certificates = list(seal_container.certs)
            if seal_container.cert is not None:
                detail.signer = seal_container.cert
            seal_ok, seal_msg = _verify_container(seal_container)
            report.add("seal_sig", "电子印章签名值", PASS if seal_ok else (FAIL if seal_ok is False else UNKNOWN), seal_msg)
            if seal_container.cert is not None:
                _cert_rows(report, "seal_cert", seal_container.cert, now)

            sv_container = parse_container(signed_value) if signed_value else None
            if sv_container is None:
                report.add("sign_sig", "签章签名值", UNKNOWN, "未找到可解析的 SignedValue.dat。")
            else:
                detail.signature_hex = sv_container.signature.hex().upper()
                sign_ok, sign_msg = _verify_container(sv_container)
                report.add("sign_sig", "签章签名值", PASS if sign_ok else (FAIL if sign_ok is False else UNKNOWN), sign_msg)
                if sv_container.cert is not None:
                    _cert_rows(report, "sign_cert", sv_container.cert, now)
                sign_time = sv_container.sign_time
                if sign_time is None and sig_xml:
                    text = _xml_value(sig_xml, "SignatureDateTime")
                    if text:
                        report.add("sign_time", "签章时间", PASS, text)
                elif sign_time is not None:
                    detail.sign_time = sign_time.isoformat()
                    report.add("sign_time", "签章时间", PASS, detail.sign_time)
                if sv_container.hash_value is None:
                    report.add("xml_hash", "签名引用摘要", UNKNOWN, "SignedValue 中未解析到 Signature.xml 摘要。")
                elif sig_xml:
                    if sm3(sig_xml) == sv_container.hash_value:
                        report.add("xml_hash", "签名引用摘要", PASS, "签名覆盖的 Signature.xml 的 SM3 与内嵌摘要一致。")
                    else:
                        report.add("xml_hash", "签名引用摘要", FAIL, "Signature.xml 的 SM3 与内嵌摘要不一致。")
                else:
                    report.add("xml_hash", "签名引用摘要", UNKNOWN, "缺少 Signature.xml。")

            if sig_xml:
                info = _parse_signature_xml(sig_xml)
                if info["method"]:
                    report.meta["SignatureMethod"] = info["method"]
                status, detail_text = _ofd_check_references(archive, info["references"])
                report.add("files", "引用文件完整性（SM3）", status, detail_text)
            else:
                report.add("files", "引用文件完整性（SM3）", UNKNOWN, "缺少 Signature.xml，无法校验引用文件。")
            report.meta["印章签名算法"] = OID_LABELS.get(seal_container.algorithm_oid, seal_container.algorithm_oid)
            if seal_container.cert is not None:
                report.meta["印章公钥算法"] = seal_container.cert.spki.algorithm_label
                report.raw["印章公钥(HEX)"] = seal_container.cert.spki.key_bits.hex().upper()
            report.raw["印章签名原文(HEX)"] = seal_container.signed_data.hex().upper()
            report.raw["印章签名值(HEX)"] = seal_container.signature.hex().upper()
            if sv_container is not None and sv_container.cert is not None:
                report.meta["签章签名算法"] = OID_LABELS.get(sv_container.algorithm_oid, sv_container.algorithm_oid)
                report.raw["签章公钥(HEX)"] = sv_container.cert.spki.key_bits.hex().upper()
                report.raw["签章签名原文(HEX)"] = sv_container.signed_data.hex().upper()
                report.raw["签章签名值(HEX)"] = sv_container.signature.hex().upper()
            report.note("本工具未内置信任根，OFD 证书链信任关系需结合单位 CA/CRL 人工确认。")
            if detail.certificates:
                report.raw["证书链"] = [c.subject.text() for c in detail.certificates]
            reports.append(report)
    if not reports:
        report = Report(title="OFD 电子签章校验")
        report.add("fmt", "电子签章数据格式正确性", FAIL, "Signs 目录下没有 Seal.esl。")
        reports.append(report)
    return reports


# ---------------------------------------------------------------- 统一入口
def verify_seal_file(path: str, now: datetime | None = None) -> list[Report]:
    lower = path.lower()
    if lower.endswith(".pdf"):
        return verify_pdf(path, now)
    if lower.endswith(".ofd"):
        return verify_ofd(path, now)
    raise SealError("仅支持 .pdf 或 .ofd 文件。")
