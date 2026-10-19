"""CMS / PKCS#7 SignedData 解析（RFC 5652，兼容 GM/T 0010 国密 OID）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .der import (
    CONTEXT,
    TAG_BIT_STRING,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_SET,
    DerError,
    Name,
    Tlv,
    build_tlv,
    decode_oid,
    parse_all,
    parse_name,
    parse_tlv,
)

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SIGNED_DATA_GM = "1.2.156.10197.6.1.4.2.1"
OID_DATA = "1.2.840.113549.1.7.1"

ATTR_LABELS = {
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.2.840.113549.1.9.6": "counterSignature",
    "1.2.840.113549.1.9.16.2.14": "signatureTimeStampToken",
    "1.2.840.113549.1.9.16.2.47": "signingCertificateV2",
    "1.2.840.113549.1.9.16.2.15": "smimeCapabilities",
    "1.2.156.10197.6.1.4.2.1": "gmSignedAttrs",
}


class CmsError(ValueError):
    pass


@dataclass
class Attribute:
    oid: str
    values: list[bytes] = field(default_factory=list)
    value_text: str = ""

    @property
    def label(self) -> str:
        return ATTR_LABELS.get(self.oid, self.oid)


@dataclass
class SignerInfo:
    version: int
    sid_kind: str  # "issuer_serial" | "ski"
    issuer: Optional[Name]
    serial: Optional[int]
    subject_key_identifier: bytes
    digest_algorithm_oid: str
    signed_attrs_raw: bytes  # 用于验签的 SET OF DER（0x31 标签）
    signed_attrs: list[Attribute]
    signature_algorithm_oid: str
    signature_algorithm_params: bytes
    signature: bytes
    unsigned_attrs_raw: bytes = b""

    def attribute(self, oid: str) -> Optional[Attribute]:
        for attr in self.signed_attrs:
            if attr.oid == oid:
                return attr
        return None

    def signing_time(self) -> Optional[datetime]:
        attr = self.attribute("1.2.840.113549.1.9.5")
        if attr and attr.values:
            try:
                tlv = parse_tlv(attr.values[0])
                return tlv.as_time()
            except DerError:
                return None
        return None


@dataclass
class SignedData:
    version: int
    digest_algorithm_oids: list[str]
    econtent_type: str
    econtent: Optional[bytes]  # None 表示 detached
    certificates: list[bytes]
    crls: list[bytes]
    signer_infos: list[SignerInfo]
    raw: bytes = b""

    @property
    def is_detached(self) -> bool:
        return self.econtent is None


@dataclass
class ContentInfo:
    content_type: str
    signed_data: Optional[SignedData]
    raw: bytes


def is_signed_data_oid(oid: str) -> bool:
    return oid in (OID_SIGNED_DATA, OID_SIGNED_DATA_GM)


def parse_content_info(der: bytes) -> ContentInfo:
    der = bytes(der)
    top = parse_tlv(der)
    if top.tag != TAG_SEQUENCE:
        raise CmsError("CMS ContentInfo 顶层不是 SEQUENCE。")
    items = top.children()
    if not items or items[0].tag != TAG_OID:
        raise CmsError("CMS ContentInfo 缺少 contentType OID。")
    content_type = items[0].as_oid()
    signed: Optional[SignedData] = None
    if len(items) > 1 and items[1].tag_class == CONTEXT and items[1].tag == 0:
        inner = items[1].children()
        if inner:
            if not is_signed_data_oid(content_type):
                raise CmsError(f"不支持的内容类型 OID：{content_type}（仅支持 SignedData）。")
            signed = parse_signed_data(inner[0])
    return ContentInfo(content_type=content_type, signed_data=signed, raw=der)


def parse_signed_data(seq: Tlv) -> SignedData:
    if seq.tag != TAG_SEQUENCE:
        raise CmsError("SignedData 不是 SEQUENCE。")
    items = seq.children()
    if len(items) < 4:
        raise CmsError("SignedData 结构不完整。")
    version = items[0].as_int() if items and items[0].tag == TAG_INTEGER else 1
    digest_oids = []
    for alg in items[1].children() if items[1].tag == TAG_SET else []:
        parts = alg.children()
        if parts and parts[0].tag == TAG_OID:
            digest_oids.append(parts[0].as_oid())
    encap = items[2]
    econtent_type = ""
    econtent: Optional[bytes] = None
    if encap.tag == TAG_SEQUENCE:
        encap_items = encap.children()
        if encap_items and encap_items[0].tag == TAG_OID:
            econtent_type = encap_items[0].as_oid()
        for item in encap_items[1:]:
            if item.tag_class == CONTEXT and item.tag == 0:
                inner = item.children()
                if inner:
                    econtent = inner[0].as_octet_string()
                else:
                    econtent = item.value

    certificates: list[bytes] = []
    crls: list[bytes] = []
    signer_infos: list[SignerInfo] = []
    for item in items[3:]:
        if item.tag_class == CONTEXT and item.tag == 0:
            for cert in item.children() if item.constructed else []:
                certificates.append(cert.raw)
        elif item.tag_class == CONTEXT and item.tag == 1:
            for crl in item.children() if item.constructed else []:
                crls.append(crl.raw)
        elif item.tag == TAG_SET:
            for si in item.children():
                signer_infos.append(_parse_signer_info(si))
    return SignedData(
        version=version,
        digest_algorithm_oids=digest_oids,
        econtent_type=econtent_type,
        econtent=econtent,
        certificates=certificates,
        crls=crls,
        signer_infos=signer_infos,
        raw=seq.raw,
    )


def _parse_signer_info(seq: Tlv) -> SignerInfo:
    items = seq.children()
    idx = 0
    version = items[idx].as_int()
    idx += 1
    sid = items[idx]
    idx += 1
    issuer = None
    serial = None
    ski = b""
    sid_kind = "issuer_serial"
    if sid.tag == TAG_SEQUENCE:
        sid_items = sid.children()
        if len(sid_items) >= 2:
            issuer = parse_name(sid_items[0])
            serial = sid_items[1].as_int(signed=False)
    elif sid.tag_class == CONTEXT and sid.tag == 0:
        sid_kind = "ski"
        ski = sid.value
    digest_oid = ""
    if idx < len(items) and items[idx].tag == TAG_SEQUENCE:
        parts = items[idx].children()
        if parts and parts[0].tag == TAG_OID:
            digest_oid = parts[0].as_oid()
        idx += 1
    signed_attrs_raw = b""
    signed_attrs: list[Attribute] = []
    if idx < len(items) and items[idx].tag_class == CONTEXT and items[idx].tag == 0:
        attrs_tlv = items[idx]
        # RFC 5652：验签输入是 SignedAttributes 的 DER（SET OF，0x31 标签）
        signed_attrs_raw = build_tlv(0x31, attrs_tlv.value)
        signed_attrs = _parse_attributes(attrs_tlv)
        idx += 1
    sig_alg_oid = ""
    sig_alg_params = b""
    if idx < len(items) and items[idx].tag == TAG_SEQUENCE:
        parts = items[idx].children()
        if parts and parts[0].tag == TAG_OID:
            sig_alg_oid = parts[0].as_oid()
        if len(parts) > 1:
            sig_alg_params = parts[1].raw
        idx += 1
    signature = b""
    if idx < len(items) and items[idx].tag == TAG_OCTET_STRING:
        signature = items[idx].value
        idx += 1
    unsigned_raw = b""
    return SignerInfo(
        version=version,
        sid_kind=sid_kind,
        issuer=issuer,
        serial=serial,
        subject_key_identifier=ski,
        digest_algorithm_oid=digest_oid,
        signed_attrs_raw=signed_attrs_raw,
        signed_attrs=signed_attrs,
        signature_algorithm_oid=sig_alg_oid,
        signature_algorithm_params=sig_alg_params,
        signature=signature,
        unsigned_attrs_raw=unsigned_raw,
    )


def _parse_attributes(tlv: Tlv) -> list[Attribute]:
    attrs: list[Attribute] = []
    try:
        items = tlv.children()
    except DerError:
        return attrs
    for item in items:
        parts = item.children()
        if len(parts) < 2:
            continue
        if parts[0].tag != TAG_OID:
            continue
        oid = parts[0].as_oid()
        values = [v.raw for v in (parts[1].children() if parts[1].tag == TAG_SET else [])]
        text = _attribute_text(oid, parts[1])
        attrs.append(Attribute(oid=oid, values=values, value_text=text))
    return attrs


def _attribute_text(oid: str, values_tlv: Tlv) -> str:
    texts = []
    try:
        values = values_tlv.children() if values_tlv.tag == TAG_SET else []
    except DerError:
        values = []
    for value in values:
        try:
            if oid == "1.2.840.113549.1.9.4":  # messageDigest OCTET STRING
                texts.append(value.value.hex().upper())
            elif oid == "1.2.840.113549.1.9.5":  # signingTime
                texts.append(value.as_time().isoformat())
            elif oid == "1.2.840.113549.1.9.3":  # contentType OID
                texts.append(value.as_oid())
            elif value.tag == TAG_OID:
                texts.append(value.as_oid())
            elif value.tag in (23, 24):
                texts.append(value.as_time().isoformat())
            elif value.tag == TAG_OCTET_STRING:
                texts.append(value.value.hex().upper())
            else:
                texts.append(value.describe())
        except DerError:
            texts.append(value.value.hex().upper())
    return " / ".join(texts)


def signer_matches(signer: SignerInfo, cert) -> bool:
    """判断 signerInfo 的 SignerIdentifier 是否指向该证书。"""
    if signer.sid_kind == "issuer_serial":
        if signer.issuer is None or signer.serial is None:
            return False
        return signer.issuer.raw == cert.issuer.raw and signer.serial == cert.serial
    if signer.subject_key_identifier:
        return signer.subject_key_identifier == cert.ski
    return False
