"""PKCS#7 / CMS 解析与验证（页面 A-P7 解析、PDF 签章共用）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .cert import HASH_OID_MAP, VerifyError, verify_signature
from .cms import (
    ATTR_LABELS,
    CmsError,
    ContentInfo,
    SignedData,
    SignerInfo,
    is_signed_data_oid,
    parse_content_info,
)
from .digest import digest
from .result import FAIL, PASS, SKIP, UNKNOWN, CheckResult, Report
from .x509 import Certificate, parse_certificate


@dataclass
class P7Info:
    content_type: str
    content_type_label: str
    signed: Optional[SignedData]
    content_attached: bool = False
    econtent: bytes = b""
    certificates: list[Certificate] = field(default_factory=list)
    cert_errors: list[str] = field(default_factory=list)
    digest_algorithms: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    gm: dict = field(default_factory=dict)


CONTENT_TYPE_LABELS = {
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData (PKCS#7/CMS)",
    "1.2.156.10197.6.1.4.2.1": "signedData (GM/T 0010 SM2)",
    "1.2.156.10197.6.1.4.2.2": "signedData (国密电子签章结构 1.2.156.10197.6.1.4.2.2)",
}


def parse_p7(der: bytes) -> P7Info:
    # 国密电子签章容器（SignedData 结构，但 ContentInfo OID 非标准）单独适配
    if _is_gm_signed_container(der):
        from .der import parse_tlv

        return _parse_gm_signed_container(der, parse_tlv(der))
    ci = parse_content_info(der)
    label = CONTENT_TYPE_LABELS.get(ci.content_type, f"未知内容类型 {ci.content_type}")
    info = P7Info(content_type=ci.content_type, content_type_label=label, signed=ci.signed_data)
    if ci.signed_data is None:
        info.warnings.append("该内容不是 SignedData，仅支持解析 SignedData。")
        return info
    sd = ci.signed_data
    info.digest_algorithms = list(sd.digest_algorithm_oids)
    info.content_attached = sd.econtent is not None
    info.econtent = sd.econtent or b""
    for der_cert in sd.certificates:
        try:
            info.certificates.append(parse_certificate(der_cert))
        except Exception as exc:  # noqa: BLE001
            info.cert_errors.append(str(exc))
    return info


GM_SIGNED_CONTENT_TYPE = "1.2.156.10197.6.1.4.2.2"


def _is_gm_signed_container(der: bytes) -> bool:
    """是否为 OID 1.2.156.10197.6.1.4.2.2 的国密签章 SignedData（内容类型非标准）。"""
    from .der import DerError, parse_tlv

    try:
        items = parse_tlv(der).children()
    except (DerError, Exception):  # noqa: BLE001
        return False
    return (len(items) == 2 and items[0].tag == 6
            and items[0].as_oid() == GM_SIGNED_CONTENT_TYPE and items[1].constructed)


def _parse_gm_signed_container(der: bytes, top) -> P7Info:
    """解析 OID 1.2.156.10197.6.1.4.2.2 的国密签章 SignedData（detached，签名直接覆盖原文）。"""
    from .seal import parse_gm_signed_data

    content_type = "1.2.156.10197.6.1.4.2.2"
    info = P7Info(
        content_type=content_type,
        content_type_label=CONTENT_TYPE_LABELS[content_type],
        signed=None,
        content_attached=False,
    )
    data = parse_gm_signed_data(der)
    if data is None:
        info.warnings.append("无法解析国密签章 SignedData 结构。")
        return info
    cert = data.get("cert")
    if cert is not None:
        info.certificates.append(cert)
    info.digest_algorithms = [data.get("digest_oid", "")]
    info.gm = {
        "signature_oid": data.get("signature_oid", ""),
        "signature": data.get("signature", b""),
        "signed_attrs": data.get("signed_attrs"),
        "cert": cert,
    }
    if data.get("signed_attrs") is None:
        info.warnings.append(
            "该结构为国密电子签章数据，采用 detached 签名且无 signedAttrs，"
            "签名直接覆盖原文；如为 detached，请在下方填写签名原文后再验签。"
        )
    return info


def find_signer_certificate(signed: SignedData, signer: SignerInfo) -> Optional[Certificate]:
    for der_cert in signed.certificates:
        try:
            cert = parse_certificate(der_cert)
        except Exception:  # noqa: BLE001
            continue
        if signer.sid_kind == "issuer_serial":
            if signer.issuer is not None and signer.serial is not None:
                if signer.issuer.raw == cert.issuer.raw and signer.serial == cert.serial:
                    return cert
        elif signer.subject_key_identifier:
            if signer.subject_key_identifier == cert.ski:
                return cert
    return None


def verify_signer_signature(signed: SignedData, signer: SignerInfo,
                            signer_cert: Certificate, detached_content: bytes | None) -> tuple[bool, str]:
    """验证 signerInfo 的签名。signed_attrs 存在时签名覆盖其 DER（SET OF 编码）。"""
    if signer.signed_attrs_raw:
        data = signer.signed_attrs_raw
    else:
        data = signed.econtent if signed.econtent is not None else detached_content
        if data is None:
            raise CmsError("分离式签名（detached）缺少原文，请提供签名覆盖的原文。")
    digest_hint = HASH_OID_MAP.get(signer.digest_algorithm_oid)
    try:
        return verify_signature(
            spki=signer_cert.spki,
            signature_algorithm_oid=signer.signature_algorithm_oid,
            signature_algorithm_params=signer.signature_algorithm_params,
            data=data,
            signature=signer.signature,
            digest_hint=digest_hint,
            signer_uid=[signer_cert.subject.raw, b"", b"1234567812345678"],
        )
    except VerifyError as exc:
        return False, str(exc)


def check_message_digest(signed: SignedData, signer: SignerInfo,
                         detached_content: bytes | None) -> tuple[str, str]:
    """校验 messageDigest 属性。返回 (status, detail)。"""
    attr = signer.attribute("1.2.840.113549.1.9.4")
    if attr is None:
        return UNKNOWN, "签名未包含 messageDigest 属性（直接对原文签名，符合 RFC 5652 允许的情形）。"
    econtent = signed.econtent if signed.econtent is not None else detached_content
    if econtent is None:
        return UNKNOWN, "分离式签名缺少原文，无法比对 messageDigest。"
    algo = HASH_OID_MAP.get(signer.digest_algorithm_oid)
    if algo is None:
        return UNKNOWN, f"未知摘要算法 OID：{signer.digest_algorithm_oid}"
    if algo == "sm3":
        from .digest import sm3

        expected = sm3(econtent)
    else:
        import hashlib

        expected = hashlib.new(algo, econtent).digest()
    try:
        from .der import parse_tlv

        actual = parse_tlv(attr.values[0]).value
    except Exception:  # noqa: BLE001
        actual = b""
    if actual == expected:
        return PASS, f"messageDigest 与原文摘要一致（{algo.upper()}）。"
    return FAIL, f"messageDigest 与原文摘要不一致（{algo.upper()}）。"


def verify_p7(der: bytes, detached_content: bytes | None = None) -> Report:
    info = parse_p7(der)
    report = Report(title="P7 / CMS 签名数据解析与验证")
    report.meta["内容类型"] = f"{info.content_type}（{info.content_type_label}）"
    if info.gm:
        return _verify_gm_container(info, report, detached_content)
    if info.signed is None:
        report.add("content", "SignedData 结构", FAIL, "内容不是 CMS/PKCS#7 SignedData。")
        for warning in info.warnings:
            report.note(warning)
        return report
    sd = info.signed
    report.add("version", "SignedData 版本", PASS, f"v{sd.version}")
    report.add("digest", "摘要算法", PASS, "、".join(_hash_label(oid) for oid in sd.digest_algorithm_oids))
    report.add("econtent", "内容封装方式", PASS,
               "attached（内容内嵌）" if sd.econtent is not None else "detached（分离式，需提供原文）")
    report.meta["证书数量"] = len(sd.certificates)

    for index, signer in enumerate(sd.signer_infos, start=1):
        cert = find_signer_certificate(sd, signer)
        if cert is None:
            report.add(f"signer-{index}", f"签名者 {index}", UNKNOWN,
                       "签名容器中未找到与 SignerInfo 匹配的证书，无法验证签名。")
            continue
        report.add(f"signer-cert-{index}", f"签名者证书 {index}", PASS,
                   f"{cert.subject.text()}（序列号 {cert.serial_hex}）")
        try:
            ok, message = verify_signer_signature(sd, signer, cert, detached_content)
            report.add(f"signer-sig-{index}", f"签名者 {index} 签名值", PASS if ok else FAIL, message)
        except (VerifyError, CmsError) as exc:
            report.add(f"signer-sig-{index}", f"签名者 {index} 签名值", UNKNOWN, str(exc))
        status, detail = check_message_digest(sd, signer, detached_content)
        report.add(f"signer-md-{index}", f"签名者 {index} messageDigest", status, detail)
        signing_time = signer.signing_time()
        if signing_time is not None:
            report.add(f"signer-time-{index}", f"签名者 {index} 签名时间", PASS, signing_time.isoformat())
        else:
            report.add(f"signer-time-{index}", f"签名者 {index} 签名时间", SKIP, "未包含 signingTime 属性。")
    if info.cert_errors:
        for err in info.cert_errors:
            report.note(f"证书解析警告：{err}")
    return report


def _verify_gm_container(info: P7Info, report: Report, detached_content: bytes | None) -> Report:
    """国密签章容器验签：签名直接覆盖原文（detached 时需提供原文）。"""
    gm = info.gm
    cert = gm.get("cert")
    signature_oid = gm.get("signature_oid", "")
    signature = gm.get("signature", b"")
    attrs = gm.get("signed_attrs")
    report.add("content", "SignedData 结构", PASS, "已识别国密电子签章 SignedData 结构。")
    report.add("alg", "签名算法", PASS, f"{_sig_label(signature_oid)}（{signature_oid}）")
    data = b""
    if attrs is not None:
        data = attrs.raw if attrs.raw[:1] != b"\xa0" else b"\x31" + attrs.raw[1:]
    elif detached_content is not None:
        data = detached_content
    if cert is None:
        report.add("signer-cert", "签名证书", UNKNOWN, "未在签名数据中找到可解析的证书。")
    else:
        report.add("signer-cert", "签名证书", PASS,
                   f"{cert.subject.text()}（序列号 {cert.serial_hex}）")
    if not data:
        report.add("signer-sig", "签名值", SKIP,
                   "该结构为 detached 签名且无 signedAttrs：请在“分离式签名原文”中填写被签名数据后重新验证。")
    elif cert is None:
        report.add("signer-sig", "签名值", UNKNOWN, "缺少签名证书，无法验证。")
    else:
        try:
            ok, message = verify_signature(
                spki=cert.spki,
                signature_algorithm_oid=signature_oid,
                signature_algorithm_params=b"",
                data=data,
                signature=signature,
                signer_uid=[cert.subject.raw, b"", b"1234567812345678"],
            )
            report.add("signer-sig", "签名值", PASS if ok else FAIL, message)
        except VerifyError as exc:
            report.add("signer-sig", "签名值", UNKNOWN, str(exc))
    report.meta["签名值长度"] = len(signature)
    for warning in info.warnings:
        report.note(warning)
    return report


def _sig_label(oid: str) -> str:
    return {
        "1.2.156.10197.1.501": "SM3withSM2",
        "1.2.156.10197.1.301.1": "SM3withSM2（国密电子签章）",
        "1.2.840.113549.1.1.11": "SHA256withRSA",
    }.get(oid, oid)


def _hash_label(oid: str) -> str:
    names = {
        "1.3.14.3.2.26": "SHA-1",
        "2.16.840.1.101.3.4.2.4": "SHA-224",
        "2.16.840.1.101.3.4.2.1": "SHA-256",
        "2.16.840.1.101.3.4.2.2": "SHA-384",
        "2.16.840.1.101.3.4.2.3": "SHA-512",
        "1.2.156.10197.1.401": "SM3",
    }
    return names.get(oid, oid)
