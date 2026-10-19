"""CRL（证书吊销列表，RFC 5280）解析与签名验证辅助。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .der import (
    CONTEXT,
    TAG_BIT_STRING,
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_UTC_TIME,
    DerError,
    Name,
    Tlv,
    parse_name,
    parse_tlv,
    split_top_level,
)

CRL_REASON_LABELS = {
    0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
    4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL",
    9: "privilegeWithdrawn", 10: "aACompromise",
}


class CrlError(ValueError):
    pass


@dataclass
class RevokedEntry:
    serial: int
    revocation_date: Optional[datetime] = None
    reason: str = ""


@dataclass
class CertificateList:
    der: bytes
    tbs: bytes
    version: int
    issuer: Name
    this_update: Optional[datetime]
    next_update: Optional[datetime]
    entries: list[RevokedEntry] = field(default_factory=list)
    akid: bytes = b""
    crl_number: Optional[int] = None
    signature_algorithm_oid: str = ""
    signature_algorithm_params: bytes = b""
    signature: bytes = b""

    @property
    def issuer_text(self) -> str:
        return self.issuer.text()

    def find_serial(self, serial: int) -> Optional[RevokedEntry]:
        for entry in self.entries:
            if entry.serial == serial:
                return entry
        return None

    def time_status(self, now: datetime | None = None) -> str:
        now = now or datetime.now().astimezone()
        if self.next_update is None:
            return "无 nextUpdate"
        return "仍在有效期" if now <= self.next_update else "CRL 已过期"


def parse_crl(der: bytes) -> CertificateList:
    der = bytes(der)
    top = parse_tlv(der)
    if top.tag != TAG_SEQUENCE:
        raise CrlError("CRL 顶层不是 SEQUENCE。")
    items = top.children()
    if len(items) < 3:
        raise CrlError("CRL 结构不完整。")
    tbs, sig_alg, sig_value = items[0], items[1], items[2]
    if tbs.tag != TAG_SEQUENCE or sig_alg.tag != TAG_SEQUENCE or sig_value.tag != TAG_BIT_STRING:
        raise CrlError("CRL 结构异常：tbsCertList / 签名算法 / 签名值标签不正确。")
    alg_items = sig_alg.children()
    sig_oid = alg_items[0].as_oid() if alg_items and alg_items[0].tag == TAG_OID else ""
    sig_params = alg_items[1].raw if len(alg_items) > 1 else b""
    signature, _ = sig_value.as_bit_string()

    values = tbs.children()
    idx = 0
    version = 1
    if values and values[0].tag == TAG_INTEGER:
        version = values[0].as_int() + 1
        idx += 1
    if idx < len(values) and values[idx].tag == TAG_SEQUENCE:
        idx += 1  # 内层签名算法
    if idx >= len(values):
        raise CrlError("CRL 缺少颁发者。")
    issuer = parse_name(values[idx])
    idx += 1
    if idx >= len(values):
        raise CrlError("CRL 缺少 thisUpdate。")
    this_update = values[idx].as_time()
    idx += 1
    next_update = None
    if idx < len(values) and values[idx].tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
        next_update = values[idx].as_time()
        idx += 1

    entries: list[RevokedEntry] = []
    if idx < len(values) and values[idx].tag == TAG_SEQUENCE:
        for entry in values[idx].children():
            parts = entry.children()
            if len(parts) < 2:
                continue
            serial = parts[0].as_int(signed=False)
            date = parts[1].as_time()
            reason = ""
            for extra in parts[2:]:
                if extra.tag_class == CONTEXT and extra.tag == 0:
                    inner = extra.children()
                    if inner:
                        for ext in inner[0].children():
                            ext_parts = ext.children()
                            if len(ext_parts) >= 2 and ext_parts[0].as_oid() == "2.5.29.21":
                                try:
                                    reason_value = parse_tlv(ext_parts[-1].value)
                                    reason = CRL_REASON_LABELS.get(reason_value.as_int(), str(reason_value.as_int()))
                                except DerError:
                                    pass
            entries.append(RevokedEntry(serial=serial, revocation_date=date, reason=reason))
        idx += 1

    akid = b""
    crl_number = None
    while idx < len(values):
        item = values[idx]
        if item.tag_class == CONTEXT and item.tag == 0:
            for ext in item.children()[0].children() if item.children() else []:
                parts = ext.children()
                if len(parts) < 2:
                    continue
                oid = parts[0].as_oid()
                value = parts[-1].value
                try:
                    value_tlv = parse_tlv(value)
                except DerError:
                    continue
                if oid == "2.5.29.35":  # AKI
                    for child in value_tlv.children():
                        if child.tag_class == CONTEXT and child.tag == 0:
                            akid = child.value
                elif oid == "2.5.29.20":  # CRL Number
                    try:
                        crl_number = value_tlv.as_int(signed=False)
                    except DerError:
                        crl_number = None
        idx += 1

    return CertificateList(
        der=der,
        tbs=tbs.raw,
        version=version,
        issuer=issuer,
        this_update=this_update,
        next_update=next_update,
        entries=entries,
        akid=akid,
        crl_number=crl_number,
        signature_algorithm_oid=sig_oid,
        signature_algorithm_params=sig_params,
        signature=signature,
    )


def parse_crls(blob: bytes) -> list[CertificateList]:
    result = []
    for chunk in split_top_level(blob):
        try:
            result.append(parse_crl(chunk))
        except CrlError:
            continue
    return result
