"""X.509 证书解析（自研，支持未知曲线 OID 如 SM2）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .der import (
    CONTEXT,
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_GENERALIZED_TIME,
    TAG_IA5_STRING,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_SET,
    TAG_UTC_TIME,
    DerError,
    Name,
    Tlv,
    decode_oid,
    parse_all,
    parse_name,
    parse_tlv,
    split_top_level,
)

SIG_OID_LABELS = {
    "1.2.840.113549.1.1.5": "SHA1withRSA",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.13": "SHA512withRSA",
    "1.2.840.113549.1.1.14": "SHA224withRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ECDSA-SHA1",
    "1.2.840.10045.4.3.1": "ECDSA-SHA224",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA512",
    "1.2.156.10197.1.501": "SM3withSM2",
}

PK_ALG_OID_LABELS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.156.10197.1.301": "SM2",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
}

CURVE_OID_LABELS = {
    "1.2.156.10197.1.301": "SM2 (sm2p256v1)",
    "1.2.840.10045.3.1.7": "P-256 (prime256v1)",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.3.132.0.10": "secp256k1",
}

KEY_USAGE_NAMES = [
    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
]
KEY_USAGE_ZH = {
    "digitalSignature": "数字签名",
    "nonRepudiation": "不可否认",
    "keyEncipherment": "密钥加密",
    "dataEncipherment": "数据加密",
    "keyAgreement": "密钥协商",
    "keyCertSign": "签发证书",
    "cRLSign": "签发CRL",
    "encipherOnly": "仅加密",
    "decipherOnly": "仅解密",
}

EKU_LABELS = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}

EXT_NAMES = {
    "2.5.29.14": "SubjectKeyIdentifier",
    "2.5.29.15": "KeyUsage",
    "2.5.29.17": "SubjectAltName",
    "2.5.29.18": "IssuerAltName",
    "2.5.29.19": "BasicConstraints",
    "2.5.29.30": "NameConstraints",
    "2.5.29.31": "CRLDistributionPoints",
    "2.5.29.32": "CertificatePolicies",
    "2.5.29.33": "PolicyMappings",
    "2.5.29.35": "AuthorityKeyIdentifier",
    "2.5.29.36": "PolicyConstraints",
    "2.5.29.37": "ExtendedKeyUsage",
    "2.5.29.46": "FreshestCRL",
    "2.5.29.54": "InhibitAnyPolicy",
    "1.3.6.1.5.5.7.1.1": "AuthorityInfoAccess",
    "1.3.6.1.5.5.7.1.11": "SubjectInfoAccess",
    "1.3.6.1.4.1.11129.2.4.2": "CT Precertificate SCTs",
}

AIA_OCSP = "1.3.6.1.5.5.7.48.1"
AIA_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"


class CertificateError(ValueError):
    pass


@dataclass
class Extension:
    oid: str
    critical: bool
    value: bytes
    name: str = ""
    parsed: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = EXT_NAMES.get(self.oid, self.oid)


@dataclass
class SubjectPublicKeyInfo:
    algorithm_oid: str
    parameters_raw: bytes
    key_bits: bytes
    unused_bits: int = 0
    raw: bytes = b""

    @property
    def algorithm_label(self) -> str:
        return PK_ALG_OID_LABELS.get(self.algorithm_oid, self.algorithm_oid)

    @property
    def curve_label(self) -> str:
        if self.parameters_raw:
            try:
                param = parse_tlv(self.parameters_raw)
                if param.tag == TAG_OID:
                    return CURVE_OID_LABELS.get(param.as_oid(), param.as_oid())
            except DerError:
                pass
        return ""

    @property
    def is_rsa(self) -> bool:
        return self.algorithm_oid in ("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10")

    @property
    def is_sm2(self) -> bool:
        if self.algorithm_oid == "1.2.156.10197.1.301":
            return True
        # OpenSSL 等实现用 id-ecPublicKey + 曲线参数 OID 表示 SM2
        if self.algorithm_oid == "1.2.840.10045.2.1" and self.parameters_raw:
            try:
                param = parse_tlv(self.parameters_raw)
                if param.tag == TAG_OID and param.as_oid() == "1.2.156.10197.1.301":
                    return True
            except DerError:
                pass
        return False

    @property
    def is_ec(self) -> bool:
        return self.algorithm_oid == "1.2.840.10045.2.1"


@dataclass
class Certificate:
    der: bytes
    tbs: bytes
    version: int
    serial: int
    signature_alg_oid: str
    signature_alg_params: bytes
    signature_bits: bytes
    signature_unused: int
    issuer: Name
    subject: Name
    not_before: datetime
    not_after: datetime
    spki: SubjectPublicKeyInfo
    extensions: list[Extension] = field(default_factory=list)

    # ------------------------------------------------------------ 便捷属性
    @property
    def serial_hex(self) -> str:
        return f"{self.serial:X}"

    @property
    def signature_alg_label(self) -> str:
        return SIG_OID_LABELS.get(self.signature_alg_oid, self.signature_alg_oid)

    @property
    def is_self_signed(self) -> bool:
        return self.issuer.raw == self.subject.raw

    @property
    def basic_constraints(self) -> dict:
        for ext in self.extensions:
            if ext.oid == "2.5.29.19":
                return ext.parsed
        return {}

    @property
    def is_ca(self) -> bool:
        return bool(self.basic_constraints.get("ca"))

    @property
    def path_len(self) -> int | None:
        return self.basic_constraints.get("path_len")

    @property
    def key_usage(self) -> list[str]:
        for ext in self.extensions:
            if ext.oid == "2.5.29.15":
                return list(ext.parsed.get("bits", []))
        return []

    @property
    def extended_key_usage(self) -> list[str]:
        for ext in self.extensions:
            if ext.oid == "2.5.29.37":
                return list(ext.parsed.get("eku", []))
        return []

    @property
    def subject_alt_names(self) -> list[str]:
        for ext in self.extensions:
            if ext.oid == "2.5.29.17":
                return list(ext.parsed.get("names", []))
        return []

    @property
    def crl_urls(self) -> list[str]:
        for ext in self.extensions:
            if ext.oid == "2.5.29.31":
                return list(ext.parsed.get("urls", []))
        return []

    @property
    def ocsp_urls(self) -> list[str]:
        for ext in self.extensions:
            if ext.oid == "1.3.6.1.5.5.7.1.1":
                return list(ext.parsed.get("ocsp", []))
        return []

    @property
    def ca_issuers_urls(self) -> list[str]:
        for ext in self.extensions:
            if ext.oid == "1.3.6.1.5.5.7.1.1":
                return list(ext.parsed.get("ca_issuers", []))
        return []

    @property
    def ski(self) -> bytes:
        for ext in self.extensions:
            if ext.oid == "2.5.29.14":
                return bytes(ext.parsed.get("key_id", b""))
        return b""

    @property
    def aki(self) -> bytes:
        for ext in self.extensions:
            if ext.oid == "2.5.29.35":
                return bytes(ext.parsed.get("key_id", b""))
        return b""

    def validity_text(self) -> str:
        return f"{self.not_before.isoformat()} ~ {self.not_after.isoformat()}"

    def time_status(self, now: datetime | None = None) -> str:
        now = now or datetime.now().astimezone().astimezone()
        if now < self.not_before:
            return "尚未生效"
        if now > self.not_after:
            return "已过期"
        return "有效期内"

    def summary_text(self) -> str:
        spki = self.spki
        lines = [
            f"版本: v{self.version}",
            f"序列号: {self.serial_hex}",
            f"签名算法: {self.signature_alg_label} ({self.signature_alg_oid})",
            f"颁发者: {self.issuer.text()}",
            f"使用者: {self.subject.text()}",
            f"有效期: {self.validity_text()}",
            f"公钥算法: {spki.algorithm_label}"
            + (f" / {spki.curve_label}" if spki.curve_label else "")
            + f"（公钥 {len(spki.key_bits)} 字节）",
        ]
        if self.is_ca:
            lines.append(f"CA: 是（pathLen={self.path_len if self.path_len is not None else '无限制'}）")
        for ext in self.extensions:
            detail = ""
            if ext.oid == "2.5.29.15":
                detail = "、".join(KEY_USAGE_ZH.get(b, b) for b in ext.parsed.get("bits", []))
            elif ext.oid == "2.5.29.37":
                detail = "、".join(EKU_LABELS.get(e, e) for e in ext.parsed.get("eku", []))
            elif ext.oid == "2.5.29.17":
                detail = "、".join(ext.parsed.get("names", []))
            elif ext.oid == "2.5.29.31":
                detail = "、".join(ext.parsed.get("urls", []))
            elif ext.oid == "1.3.6.1.5.5.7.1.1":
                parts = []
                if ext.parsed.get("ocsp"):
                    parts.append("OCSP=" + "、".join(ext.parsed["ocsp"]))
                if ext.parsed.get("ca_issuers"):
                    parts.append("CAIssuers=" + "、".join(ext.parsed["ca_issuers"]))
                detail = "；".join(parts)
            elif ext.oid == "2.5.29.19":
                detail = f"ca={ext.parsed.get('ca')}, pathLen={ext.parsed.get('path_len')}"
            if detail:
                lines.append(f"扩展 {ext.name}（critical={ext.critical}）: {detail}")
            else:
                lines.append(f"扩展 {ext.name}（critical={ext.critical}）")
        return "\n".join(lines)


# ---------------------------------------------------------------- 解析入口
def parse_certificate(der: bytes) -> Certificate:
    der = bytes(der)
    top = parse_tlv(der)
    if top.tag != TAG_SEQUENCE:
        raise CertificateError("证书顶层不是 SEQUENCE，可能不是 DER 编码的 X.509 证书。")
    items = top.children()
    if len(items) < 3:
        raise CertificateError("证书结构不完整（缺少 tbs/signatureAlgorithm/signatureValue）。")
    tbs, outer_sig_alg, sig_value = items[0], items[1], items[2]
    if tbs.tag != TAG_SEQUENCE or outer_sig_alg.tag != TAG_SEQUENCE or sig_value.tag != TAG_BIT_STRING:
        raise CertificateError("证书结构异常：tbsCertificate / 签名算法 / 签名值标签不正确。")
    sig_bits, unused = sig_value.as_bit_string()
    sig_oid, sig_params = _algorithm(outer_sig_alg)

    values = tbs.children()
    idx = 0
    version = 1
    if values and values[0].tag_class == CONTEXT and values[0].tag == 0:
        inner = values[0].children()
        if inner:
            version = inner[0].as_int(signed=True) + 1
        else:
            version = 2
        idx = 1
    if idx >= len(values):
        raise CertificateError("证书缺少序列号。")
    serial = values[idx].as_int(signed=False)
    idx += 1
    if idx + 1 >= len(values):
        raise CertificateError("证书缺少签名算法/颁发者。")
    idx += 1  # 内层 signature AlgorithmIdentifier（不单独使用）
    issuer = parse_name(values[idx])
    idx += 1
    validity = values[idx]
    idx += 1
    not_before = validity.children()[0].as_time()
    not_after = validity.children()[1].as_time()
    subject = parse_name(values[idx])
    idx += 1
    spki = _parse_spki(values[idx])
    idx += 1

    extensions: list[Extension] = []
    while idx < len(values):
        item = values[idx]
        if item.tag_class == CONTEXT and item.tag == 3:
            inner = item.children()
            if inner:
                extensions = _parse_extensions(inner[0])
        idx += 1

    return Certificate(
        der=der,
        tbs=tbs.raw,
        version=version,
        serial=serial,
        signature_alg_oid=sig_oid,
        signature_alg_params=sig_params,
        signature_bits=sig_bits,
        signature_unused=unused,
        issuer=issuer,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        spki=spki,
        extensions=extensions,
    )


def parse_certificates(blob: bytes) -> list[Certificate]:
    """从连续 DER 缓冲区解析一张或多张证书。"""
    result: list[Certificate] = []
    for chunk in split_top_level(blob):
        try:
            result.append(parse_certificate(chunk))
        except Exception:  # noqa: BLE001 - 跳过非证书块
            continue
    return result


def _algorithm(seq: Tlv) -> tuple[str, bytes]:
    """AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }"""
    items = seq.children()
    if not items or items[0].tag != TAG_OID:
        raise CertificateError("AlgorithmIdentifier 缺少 OID。")
    oid = items[0].as_oid()
    params = items[1].raw if len(items) > 1 else b""
    return oid, params


def _parse_spki(seq: Tlv) -> SubjectPublicKeyInfo:
    items = seq.children()
    if len(items) < 2:
        raise CertificateError("SubjectPublicKeyInfo 结构不完整。")
    oid, params = _algorithm(items[0])
    bits, unused = items[1].as_bit_string()
    return SubjectPublicKeyInfo(algorithm_oid=oid, parameters_raw=params, key_bits=bits,
                                unused_bits=unused, raw=seq.raw)


# ---------------------------------------------------------------- 扩展解析
def _parse_extensions(seq: Tlv) -> list[Extension]:
    result: list[Extension] = []
    for item in seq.children():
        if item.tag != TAG_SEQUENCE:
            continue
        parts = item.children()
        if len(parts) < 2:
            continue
        oid = parts[0].as_oid()
        critical = False
        value_index = 1
        if parts[1].tag == TAG_BOOLEAN:
            critical = parts[1].as_bool()
            value_index = 2
        if value_index >= len(parts):
            continue
        value = parts[value_index].value
        ext = Extension(oid=oid, critical=critical, value=value)
        try:
            ext.parsed = _parse_extension_value(oid, value)
        except Exception:  # noqa: BLE001 - 未知扩展保持原样
            ext.parsed = {}
        result.append(ext)
    return result


def _parse_extension_value(oid: str, value: bytes) -> dict:
    tlv = parse_tlv(value)
    if oid == "2.5.29.15":  # KeyUsage
        bits, _ = tlv.as_bit_string()
        names = []
        for i, name in enumerate(KEY_USAGE_NAMES):
            byte_index, bit_index = divmod(i, 8)
            if byte_index < len(bits) and bits[byte_index] & (0x80 >> bit_index):
                names.append(name)
        return {"bits": names}
    if oid == "2.5.29.19":  # BasicConstraints
        result: dict = {"ca": False, "path_len": None}
        for child in tlv.children():
            if child.tag == TAG_BOOLEAN:
                result["ca"] = child.as_bool()
            elif child.tag == TAG_INTEGER:
                result["path_len"] = child.as_int(signed=False)
        return result
    if oid == "2.5.29.37":  # ExtendedKeyUsage
        return {"eku": [child.as_oid() for child in tlv.children() if child.tag == TAG_OID]}
    if oid == "2.5.29.17":  # SubjectAltName
        return {"names": _parse_general_names(tlv)}
    if oid == "2.5.29.14":  # SKI
        return {"key_id": tlv.value if tlv.tag == TAG_OCTET_STRING else tlv.raw}
    if oid == "2.5.29.35":  # AKI
        result = {"key_id": b"", "issuer_raw": b"", "serial": None}
        for child in tlv.children():
            if child.tag_class == CONTEXT and child.tag == 0:
                result["key_id"] = child.value
            elif child.tag_class == CONTEXT and child.tag == 1:
                result["issuer_raw"] = child.raw
            elif child.tag_class == CONTEXT and child.tag == 2:
                result["serial"] = child.as_int(signed=False)
        return result
    if oid == "2.5.29.31":  # CRLDistributionPoints
        urls = []
        for dp in tlv.children():
            for child in dp.children():
                if child.tag_class == CONTEXT and child.tag == 0:
                    for name in child.children():
                        if name.tag_class == CONTEXT and name.tag == 0:
                            urls.extend(_parse_general_names(name))
        return {"urls": urls}
    if oid == "1.3.6.1.5.5.7.1.1":  # AIA
        result = {"ocsp": [], "ca_issuers": [], "other": []}
        for ad in tlv.children():
            parts = ad.children()
            if len(parts) < 2:
                continue
            method = parts[0].as_oid()
            location = _parse_general_names(parts[1])
            if method == AIA_OCSP:
                result["ocsp"].extend(location)
            elif method == AIA_CA_ISSUERS:
                result["ca_issuers"].extend(location)
            else:
                result["other"].extend(location)
        return result
    if oid == "2.5.29.32":  # CertificatePolicies
        policies = []
        for pi in tlv.children():
            parts = pi.children()
            if parts:
                policies.append(parts[0].as_oid())
        return {"policies": policies}
    return {}


def _parse_general_names(tlv: Tlv) -> list[str]:
    """解析 GeneralNames 或单个 GeneralName。"""
    names: list[str] = []
    items = tlv.children() if tlv.constructed else [tlv]
    for item in items:
        if item.tag_class != CONTEXT:
            continue
        try:
            if item.tag in (1, 2, 6):  # rfc822Name / dNSName / URI
                names.append(item.value.decode("utf-8", errors="replace"))
            elif item.tag == 4:  # directoryName
                inner = item.children()
                if inner:
                    names.append(parse_name(inner[0]).text())
            elif item.tag == 7:  # iPAddress
                raw = item.value
                if len(raw) == 4:
                    names.append(".".join(str(b) for b in raw))
                elif len(raw) == 16:
                    names.append(":".join(f"{int.from_bytes(raw[i:i + 2], 'big'):x}" for i in range(0, 16, 2)))
                else:
                    names.append(raw.hex().upper())
            elif item.tag == 8:  # registeredID
                names.append(decode_oid(item.value))
        except Exception:  # noqa: BLE001
            continue
    return names
