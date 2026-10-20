"""构造测试用签章样本：CMS PDF、国密容器 PDF、OFD（Seal.esl + SignedValue + Signature.xml）。"""
from __future__ import annotations

import base64
import datetime
import hashlib
import io
import zipfile
from pathlib import Path

from cryptotoolbox.core import sm2
from cryptotoolbox.core.der import (
    build_integer,
    build_oid,
    build_sequence,
    build_set,
    build_tlv,
    parse_tlv,
)
from cryptotoolbox.core.digest import sm3
from cryptotoolbox.core.keys import parse_certificates_text
from cryptotoolbox.core.x509 import parse_certificate

SM2_SM3_OID = "1.2.156.10197.1.501"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"


def load_cert_der(fixtures_dir: Path, name: str) -> bytes:
    text = (fixtures_dir / name).read_text(encoding="utf-8")
    return parse_certificates_text(text, "PEM/DER")[0][0]


def load_key_pem(fixtures_dir: Path, name: str) -> bytes:
    return (fixtures_dir / name).read_bytes()


def load_sm2_private(fixtures_dir: Path, name: str) -> bytes:
    from cryptotoolbox.core.keys import parse_sm2_private

    return parse_sm2_private((fixtures_dir / name).read_text(encoding="utf-8"))[0]


def _utctime(when: datetime.datetime) -> bytes:
    return build_tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _alg(oid: str) -> bytes:
    return build_sequence(build_oid(oid), build_tlv(0x05, b""))


# ---------------------------------------------------------------- CMS（标准 PKCS#7）
def build_signed_attrs(econtent: bytes, digest_oid: str, when: datetime.datetime) -> tuple[bytes, bytes]:
    if digest_oid == "1.2.156.10197.1.401":
        digest_value = sm3(econtent)
    else:
        digest_value = hashlib.new({ "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256"}[digest_oid], econtent).digest()
    attrs = [
        build_sequence(build_oid("1.2.840.113549.1.9.3"), build_set(build_oid("1.2.840.113549.1.7.1"))),
        build_sequence(build_oid("1.2.840.113549.1.9.4"), build_set(build_tlv(0x04, digest_value))),
        build_sequence(build_oid("1.2.840.113549.1.9.5"), build_set(_utctime(when))),
    ]
    return build_set(*attrs), b"".join(attrs)


def build_cms(cert_der: bytes, signer_key, econtent: bytes, *, sm2_sm3: bool = True,
              when: datetime.datetime | None = None) -> bytes:
    when = when or datetime.datetime.now(datetime.timezone.utc)
    cert = parse_certificate(cert_der)
    digest_oid = "1.2.156.10197.1.401" if sm2_sm3 else "2.16.840.1.101.3.4.2.1"
    signed_attrs_der, _ = build_signed_attrs(econtent, digest_oid, when)
    if sm2_sm3:
        signature = sm2.signature_from_der(
            sm2.rs_to_der(*sm2.sign(signed_attrs_der, signer_key, cert.subject.raw))
        )
        sig_alg = build_sequence(build_oid(SM2_SM3_OID))
        signature = sm2.rs_to_der(*sm2.sign(signed_attrs_der, signer_key, cert.subject.raw))
    else:
        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15

        key = RSA.import_key(signer_key)
        signature = pkcs1_15.new(key).sign(SHA256.new(signed_attrs_der))
        sig_alg = build_sequence(build_oid(SHA256_RSA_OID), build_tlv(0x05, b""))
    signer_info = build_sequence(
        build_integer(1),
        build_sequence(cert.issuer.raw, build_integer(cert.serial)),
        _alg(digest_oid),
        build_tlv(0xA0, parse_tlv(signed_attrs_der).value),
        sig_alg,
        build_tlv(0x04, signature),
    )
    signed_data = build_sequence(
        build_integer(1),
        build_set(_alg(digest_oid)),
        build_sequence(build_oid("1.2.840.113549.1.7.1")),
        build_tlv(0xA0, cert_der),
        build_set(signer_info),
    )
    return build_sequence(build_oid("1.2.840.113549.1.7.2"), build_tlv(0xA0, signed_data))


# ---------------------------------------------------------------- 国密容器（PDF / OFD）
def _sign_container(cert_der: bytes, key, data: bytes, sm2_mode: bool) -> tuple[str, bytes]:
    if sm2_mode:
        r, s = sm2.sign(data, key, b"1234567812345678")
        return SM2_SM3_OID, sm2.rs_to_der(r, s)
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15

    signature = pkcs1_15.new(RSA.import_key(key)).sign(SHA256.new(data))
    return SHA256_RSA_OID, signature


def build_seal_container(cert_der: bytes, key, signed_bytes: bytes, sm2_mode: bool) -> bytes:
    """PDF 国密电子印章容器：SEQUENCE { 内层(印章信息/时间/摘要/证书/算法), 签名值 }。"""
    cert = parse_certificate(cert_der)
    when = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    time_bits = when.strftime("%y%m%d%H%M%SZ").encode("ascii")
    seal_info = build_sequence(build_tlv(0x0C, "测试电子印章".encode("utf-8")))
    inner_parts = [
        build_integer(1),
        seal_info,
        build_tlv(0x03, b"\x00" + time_bits),
        build_tlv(0x03, b"\x00" + sm3(signed_bytes)),
        build_tlv(0x16, b""),
        build_tlv(0x04, cert_der),
    ]
    oid, signature = _sign_container(cert_der, key, b"", sm2_mode)
    inner = build_sequence(*inner_parts, build_oid(oid))
    oid, signature = _sign_container(cert_der, key, inner, sm2_mode)
    return build_sequence(inner, build_tlv(0x03, b"\x00" + signature))


def build_signed_pdf(payload: bytes, width: int = 16384) -> bytes:
    """构造带签名域的 PDF；ByteRange 精确排除 /Contents 的 <hex> 值。"""
    import re

    hex_len = width * 2
    placeholder = (
        b"%PDF-1.6\n%\xe2\xe3\xcf\xd3\n"
        b"1 0 obj\n<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[6 0 R]/SigFlags 3>>>>\nendobj\n"
        b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
        b"3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]/Contents 4 0 R>>\nendobj\n"
        b"4 0 obj\n<</Length 0>>\nstream\n\nendstream\nendobj\n"
        b"6 0 obj\n<</Type/Annot/Subtype/Widget/FT/Sig/T(Signature1)/Rect[20 20 120 60]/P 3 0 R/V 7 0 R>>\nendobj\n"
        b"7 0 obj\n<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached"
        b"/ByteRange[0 0000000000 0000000000 0000000000]"
        b"/Contents <" + ("00" * width).encode("ascii") + b">"
        b"/M(D:20260101000000Z)>>\nendobj\n"
    )

    def layout(text: bytes) -> tuple[bytes, int, int]:
        br = re.search(rb"/ByteRange\[0 0000000000 0000000000 0000000000\]", text)
        cm = re.search(rb"/Contents <", text)
        hex_start = cm.start() + len(b"/Contents ")
        hex_end = hex_start + 1 + hex_len + 1
        tail = text + b"\n%%EOF\n"
        br_text = ("[%d %010d %010d %010d]" % (0, hex_start, hex_end, len(tail) - hex_end)).encode("ascii")
        patched = text[:br.start()] + b"/ByteRange" + br_text + text[br.end():]
        return patched, hex_start, hex_end

    text, first_len, second_start = layout(placeholder)
    final = text + b"\n%%EOF\n"
    hex_sig = payload.hex().upper()
    if len(hex_sig) > hex_len:
        raise AssertionError(f"签名容器过长（{len(hex_sig)} hex > {hex_len}）")
    hex_sig = hex_sig.ljust(hex_len, "0")
    return final[:first_len] + b"<" + hex_sig.encode("ascii") + b">" + final[second_start:]


# ---------------------------------------------------------------- OFD
def build_signed_ofd(cert_der: bytes, sm2_private: bytes, *, tamper: bool = False) -> bytes:
    cert = parse_certificate(cert_der)
    seal_info = build_sequence(build_tlv(0x0C, "测试电子印章".encode("utf-8")))
    r, s = sm2.sign(seal_info, sm2_private, b"1234567812345678")
    esl = build_sequence(
        seal_info,
        build_tlv(0x04, cert_der),
        build_oid(SM2_SM3_OID),
        build_tlv(0x03, b"\x00" + sm2.rs_to_der(r, s)),
    )
    files = {
        "OFD.xml": b"<OFD/>",
        "Doc_0/Document.xml": b"<Document/>",
    }
    refs = "".join(
        f'<ofd:Reference FileRef="/{name}"><ofd:CheckValue>{base64.b64encode(sm3(content)).decode()}</ofd:CheckValue></ofd:Reference>'
        for name, content in files.items()
    )
    sig_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ofd:Signature xmlns:ofd="http://www.ofdspec.org/2016"><ofd:SignedInfo>'
        '<ofd:SignatureMethod>1.2.156.10197.1.501</ofd:SignatureMethod>'
        '<ofd:SignatureDateTime>2026-01-02T03:04:05Z</ofd:SignatureDateTime>'
        f'<ofd:References>{refs}</ofd:References></ofd:SignedInfo></ofd:Signature>'
    ).encode("utf-8")
    when = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    inner = build_sequence(
        build_integer(4),
        build_tlv(0x30, parse_tlv(esl).value),
        build_tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode("ascii")),
        build_tlv(0x03, b"\x00" + sm3(sig_xml)),
        build_tlv(0x16, b"/Doc_0/Signs/Sign_0/Signature.xml"),
    )
    r2, s2 = sm2.sign(inner, sm2_private, b"1234567812345678")
    signed_value = build_sequence(
        inner,
        build_tlv(0x04, cert_der),
        build_oid(SM2_SM3_OID),
        build_tlv(0x03, b"\x00" + sm2.rs_to_der(r2, s2)),
    )
    if tamper:
        esl = esl[:-1] + bytes([esl[-1] ^ 1])
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
        zf.writestr("Doc_0/Signs/Sign_0/Seal.esl", esl)
        zf.writestr("Doc_0/Signs/Sign_0/SignedValue.dat", signed_value)
        zf.writestr("Doc_0/Signs/Sign_0/Signature.xml", sig_xml)
    return buffer.getvalue()




def build_gm_signed_pdf(cert_der: bytes, key) -> bytes:
    """构造国密电子签章 SignedData（OID 1.2.156.10197.6.1.4.2.2）PDF 样本。"""
    from cryptotoolbox.core.der import build_integer, build_oid, build_sequence, build_set, build_tlv
    from cryptotoolbox.core.x509 import parse_certificate

    cert = parse_certificate(cert_der)
    placeholder = build_signed_pdf(build_tlv(0x30, b""))
    sig = __import__("cryptotoolbox.core.seal", fromlist=["_find_pdf_signatures"])._find_pdf_signatures(placeholder)[0]
    signed = __import__("cryptotoolbox.core.seal", fromlist=["_reconstruct_ranges"])._reconstruct_ranges(placeholder, sig["byte_range"])
    signature = sm2.rs_to_der(*sm2.sign(signed, key, b"1234567812345678"))
    sm3_oid = "1.2.156.10197.1.401"
    signer = build_sequence(
        build_integer(1),
        build_sequence(cert.issuer.raw, build_integer(cert.serial)),
        build_sequence(build_oid(sm3_oid)),
        build_sequence(build_oid("1.2.156.10197.1.301.1")),
        build_tlv(0x04, signature),
    )
    signed_data = build_sequence(
        build_integer(1),
        build_set(build_sequence(build_oid(sm3_oid))),
        build_sequence(build_tlv(0x06, b"\x00")),
        build_tlv(0xA0, cert_der),
        build_set(signer),
    )
    content_info = build_sequence(
        build_oid("1.2.156.10197.6.1.4.2.2"),
        build_tlv(0xA0, signed_data),
    )
    return build_signed_pdf(content_info)



def build_gm_seal_container(cert_der: bytes, key) -> bytes:
    """构造 GB/T 38540 形态的电子印章容器：SEQUENCE{印章数据, 证书, 算法 OID, 签名值}。"""
    from cryptotoolbox.core.der import (
        build_integer,
        build_oid,
        build_sequence,
        build_tlv,
    )
    from cryptotoolbox.core.digest import sm3
    from cryptotoolbox.core.x509 import parse_certificate

    cert = parse_certificate(cert_der)
    seal_info = build_sequence(build_tlv(0x0C, "测试电子印章".encode("utf-8")))
    data = build_sequence(
        build_integer(1),
        seal_info,
        build_tlv(0x18, b"20260102030405Z"),
        build_tlv(0x03, b"\x00" + sm3(b"pdf-bytes")),
        build_tlv(0x16, b"[0 1 2 3]"),
    )
    signature = sm2.rs_to_der(*sm2.sign(data, key, b"1234567812345678"))
    return build_sequence(
        data,
        build_tlv(0x04, cert_der),
        build_oid("1.2.156.10197.1.501"),
        build_tlv(0x03, b"\x00" + signature),
    )
