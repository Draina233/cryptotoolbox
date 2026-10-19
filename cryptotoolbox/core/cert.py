"""证书签名验证与证书链构建（RFC 5280 / GB/T 20518）。

支持算法：
- RSA PKCS#1 v1.5（SHA-1/224/256/384/512）
- RSA-PSS（参数中指定哈希与盐长）
- ECDSA（DER 编码签名，修复原项目误用 P1363 的问题）
- SM2withSM3（使用签名者证书 subject DER 作为用户标识，符合 GM/T 0009 实践）

链验证规则：
- 逐级验签 + 有效期 + 中间 CA 的 basicConstraints/keyUsage + pathLen
- 找不到上级时明确提示截断；未知算法返回“未知”而不是通过
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import sm2
from .result import CheckResult, Report, FAIL, PASS, SKIP, UNKNOWN
from .x509 import (
    Certificate,
    SIG_OID_LABELS,
    parse_certificate,
    parse_certificates,
)

HASH_OID_MAP = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.5": "sha3_224",
    "2.16.840.1.101.3.4.2.6": "sha3_256",
    "2.16.840.1.101.3.4.2.7": "sha3_384",
    "2.16.840.1.101.3.4.2.8": "sha3_512",
    "1.2.156.10197.1.401": "sm3",
}

SIG_ALG_INFO = {
    "1.2.840.113549.1.1.1": ("rsa-pkcs1", None),  # CMS 中 RSA 的 signatureAlgorithm 常用 rsaEncryption，哈希由 digestAlgorithm 指定
    "1.2.840.113549.1.1.5": ("rsa-pkcs1", "sha1"),
    "1.2.840.113549.1.1.11": ("rsa-pkcs1", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa-pkcs1", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa-pkcs1", "sha512"),
    "1.2.840.113549.1.1.14": ("rsa-pkcs1", "sha224"),
    "1.2.840.113549.1.1.10": ("rsa-pss", None),
    "1.2.840.10045.4.1": ("ecdsa", "sha1"),
    "1.2.840.10045.4.3.1": ("ecdsa", "sha224"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    "1.2.156.10197.1.501": ("sm2", "sm3"),
    "1.2.156.10197.1.301.1": ("sm2", "sm3"),  # 国密电子签章中的 SM2-with-SM3
}

_PYCRYPTO_HASHERS = {
    "sha1": "SHA1", "sha224": "SHA224", "sha256": "SHA256", "sha384": "SHA384",
    "sha512": "SHA512", "sha3_224": "SHA3_224", "sha3_256": "SHA3_256",
    "sha3_384": "SHA3_384", "sha3_512": "SHA3_512",
}


class VerifyError(ValueError):
    pass


def _hash(algo: str, data: bytes):
    return hashlib.new(algo, data)


def _sm2_der_to_rs(signature: bytes) -> tuple[int, int]:
    from .der import parse_tlv

    top = parse_tlv(signature)
    if top.tag != 16:
        raise VerifyError("SM2 签名值不是 DER SEQUENCE。")
    items = top.children()
    if len(items) != 2:
        raise VerifyError("SM2 签名 DER 应包含 r、s。")
    return items[0].as_int(), items[1].as_int()


def _ecdsa_der_to_raw(signature: bytes, coordinate_size: int) -> bytes:
    from .der import parse_tlv

    top = parse_tlv(signature)
    if top.tag != 16:
        raise VerifyError("ECDSA 签名值不是 DER SEQUENCE。")
    items = top.children()
    if len(items) != 2:
        raise VerifyError("ECDSA 签名 DER 应包含 r、s。")
    r, s = items[0].as_int(), items[1].as_int()
    return r.to_bytes(coordinate_size, "big") + s.to_bytes(coordinate_size, "big")


def _pss_params(params: bytes) -> tuple[str, int]:
    """解析 RSASSA-PSS-params：返回 (哈希名, 盐长度)。缺省 SHA1/20。"""
    from .der import DerError, parse_tlv

    hash_name, salt_len = "sha1", 20
    if not params:
        return hash_name, salt_len
    try:
        top = parse_tlv(params)
    except DerError:
        return hash_name, salt_len
    for item in top.children():
        if not item.constructed or item.tag_class != 2:
            continue
        inner = item.children()
        if item.tag == 0 and inner and inner[0].tag == 6:  # hashAlgorithm
            hash_name = HASH_OID_MAP.get(inner[0].as_oid(), hash_name)
        elif item.tag == 2 and inner:  # saltLength
            salt_len = inner[0].as_int()
    return hash_name, salt_len


def verify_signature(*, spki, signature_algorithm_oid: str, signature_algorithm_params: bytes,
                     data: bytes, signature: bytes, digest_hint: str | None = None,
                     signer_uid: bytes | list[bytes] | None = None) -> tuple[bool, str]:
    """验证一段数据的签名。返回 (是否通过, 说明)。未知算法抛 VerifyError 由调用方转 UNKNOWN。

    signer_uid 对 SM2 可以是候选用户标识列表：按顺序尝试，报告实际使用的约定。
    （不同实现的 SM2 UID 约定不同：签名者证书 Subject DER / 默认 1234567812345678 / 空）
    """
    info = SIG_ALG_INFO.get(signature_algorithm_oid)
    if info is None:
        raise VerifyError(f"暂不支持的签名算法 OID：{signature_algorithm_oid}")
    kind, hash_name = info
    if digest_hint:
        hash_name = digest_hint
    if kind == "rsa-pkcs1":
        from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15

        hashers = {"sha1": SHA1, "sha224": SHA224, "sha256": SHA256,
                   "sha384": SHA384, "sha512": SHA512}
        hasher = hashers.get(hash_name)
        if hasher is None:
            raise VerifyError(f"RSA 验签不支持的哈希：{hash_name}")
        try:
            key = RSA.import_key(spki.raw)
        except (ValueError, TypeError, IndexError) as exc:
            return False, f"签名算法为 RSA，但颁发者公钥不是 RSA 公钥（{exc}）。"
        digest_obj = hasher.new(data)
        try:
            pkcs1_15.new(key).verify(digest_obj, signature)
            return True, f"RSA PKCS#1 v1.5 验签通过（{hash_name.upper()}）"
        except (ValueError, TypeError) as exc:
            return False, f"RSA PKCS#1 v1.5 验签失败（{hash_name.upper()}）：{exc}"
    if kind == "rsa-pss":
        from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pss

        hash_name, salt_len = _pss_params(signature_algorithm_params)
        hashers = {"sha1": SHA1, "sha224": SHA224, "sha256": SHA256,
                   "sha384": SHA384, "sha512": SHA512}
        hasher = hashers.get(hash_name)
        if hasher is None:
            raise VerifyError(f"RSA-PSS 验签不支持的哈希：{hash_name}")
        try:
            key = RSA.import_key(spki.raw)
        except (ValueError, TypeError, IndexError) as exc:
            return False, f"签名算法为 RSA-PSS，但颁发者公钥不是 RSA 公钥（{exc}）。"
        digest_obj = hasher.new(data)
        try:
            pss.new(key, salt_bytes=salt_len).verify(digest_obj, signature)
            return True, f"RSA-PSS 验签通过（{hash_name.upper()}，盐长 {salt_len}）"
        except (ValueError, TypeError) as exc:
            return False, f"RSA-PSS 验签失败（{hash_name.upper()}）：{exc}"
    if kind == "ecdsa":
        from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS

        hashers = {"sha1": SHA1, "sha224": SHA224, "sha256": SHA256,
                   "sha384": SHA384, "sha512": SHA512}
        hasher = hashers.get(hash_name)
        if hasher is None:
            raise VerifyError(f"ECDSA 验签不支持的哈希：{hash_name}")
        try:
            key = ECC.import_key(spki.raw)
        except (ValueError, TypeError, IndexError) as exc:
            return False, f"签名算法为 ECDSA，但颁发者公钥不是 EC 公钥（{exc}）。"
        try:
            coordinate = max(1, (len(spki.key_bits) - 1) // 2)
            raw_sig = _ecdsa_der_to_raw(signature, coordinate)
        except Exception as exc:  # noqa: BLE001
            return False, f"ECDSA 签名值解析失败：{exc}"
        digest_obj = hasher.new(data)
        try:
            DSS.new(key, "fips-186-3").verify(digest_obj, raw_sig)
            return True, f"ECDSA 验签通过（{hash_name.upper()}）"
        except (ValueError, TypeError) as exc:
            return False, f"ECDSA 验签失败（{hash_name.upper()}）：{exc}"
    if kind == "sm2":
        uid_candidates: list[bytes]
        if isinstance(signer_uid, bytes):
            uid_candidates = [signer_uid]
        elif isinstance(signer_uid, list):
            uid_candidates = signer_uid
        else:
            uid_candidates = [b""]
        if not spki.is_sm2:
            raise VerifyError("签名算法为 SM2，但公钥不是 SM2 公钥。")
        try:
            r, s = _sm2_der_to_rs(signature)
        except Exception as exc:  # noqa: BLE001
            return False, f"SM2 签名值解析失败：{exc}"
        public = spki.key_bits if len(spki.key_bits) == 65 else b"\x04" + bytes(spki.key_bits)
        tried = []
        for uid in uid_candidates:
            label = ("空" if not uid else
                     ("默认 1234567812345678" if uid == b"1234567812345678" else "证书 Subject DER"))
            tried.append(label)
            try:
                if sm2.verify(data, (r, s), public, uid):
                    return True, f"SM2 验签通过（SM3withSM2，用户标识：{label}）"
            except sm2.SM2Error as exc:
                return False, f"SM2 验签失败：{exc}"
        return False, f"SM2 验签失败（已尝试用户标识约定：{'、'.join(tried)}）"
    raise VerifyError(f"暂不支持的签名算法：{kind}")
    raise VerifyError(f"暂不支持的签名算法：{kind}")


def verify_certificate(child: Certificate, issuer: Certificate) -> tuple[bool, str]:
    """用 issuer 的公钥验证 child 的签名。"""
    return verify_signature(
        spki=issuer.spki,
        signature_algorithm_oid=child.signature_alg_oid,
        signature_algorithm_params=child.signature_alg_params,
        data=child.tbs,
        signature=child.signature_bits,
        signer_uid=[issuer.subject.raw, b"", b"1234567812345678"],
    )


# ---------------------------------------------------------------- 链构建
@dataclass
class ChainHop:
    cert: Certificate
    issuer: Optional[Certificate]
    ok: bool
    message: str


@dataclass
class ChainResult:
    chain: list[Certificate]
    hops: list[ChainHop] = field(default_factory=list)
    hint: str = ""
    truncated: bool = False


def _find_candidates(issuer_name, pool: list[Certificate]) -> list[Certificate]:
    return [c for c in pool if c.subject.raw == issuer_name.raw]


def build_chain(leaf: Certificate, pool: list[Certificate], max_depth: int = 16) -> ChainResult:
    """从终端实体向上构建链；返回 ChainResult（含逐级验签结果）。"""
    chain: list[Certificate] = [leaf]
    hops: list[ChainHop] = []
    seen = {leaf.der}
    current = leaf
    truncated = False
    hint = ""

    for _ in range(max_depth):
        if current.is_self_signed:
            ok, message = verify_certificate(current, current)
            hops.append(ChainHop(current, current, ok, message))
            break
        candidates = [c for c in pool if c.der not in seen and c.subject.raw == current.issuer.raw]
        # 优先 AKI/SKI 匹配
        if len(candidates) > 1 and current.aki:
            preferred = [c for c in candidates if c.ski == current.aki]
            if preferred:
                candidates = preferred
        if not candidates:
            truncated = True
            hint = ("证书池中找不到当前证书 Issuer 对应的上级证书（常见为缺少中间 CA 或根 CA），"
                    "已在已提供的最高一级处结束；下方验签仅覆盖池中已衔接的层级。")
            break
        verified = None
        messages = []
        for candidate in candidates:
            if candidate.der in seen:
                continue
            ok, message = verify_certificate(current, candidate)
            messages.append(f"{candidate.subject.common_name() or candidate.issuer.text()}: {message}")
            if ok:
                verified = candidate
                break
        if verified is None:
            # 所有候选都验签失败：记录失败
            candidate = candidates[0]
            hops.append(ChainHop(current, candidate, False, "；".join(messages) or "验签失败"))
            chain.append(candidate)
            break
        hops.append(ChainHop(current, verified, True, "验签通过"))
        seen.add(verified.der)
        chain.append(verified)
        current = verified
    else:
        hint = "证书链层级过多或存在循环引用。"
        truncated = True

    return ChainResult(chain=chain, hops=hops, hint=hint, truncated=truncated)


# ---------------------------------------------------------------- 链校验报告
def _is_self_issued(cert: Certificate) -> bool:
    return cert.issuer.raw == cert.subject.raw


def validate_chain(leaf: Certificate, pool: list[Certificate], now: datetime | None = None) -> Report:
    now = now or datetime.now(timezone.utc)
    report = Report(title="证书链验证")
    report.meta["终端实体"] = leaf.subject.text()
    report.meta["证书池数量"] = len(pool)

    result = build_chain(leaf, pool)
    report.meta["链长度"] = len(result.chain)
    if result.truncated:
        report.note(result.hint)

    # 1) 逐级验签
    for index, hop in enumerate(result.hops):
        detail = hop.message if hop.ok else f"{hop.message}（签名者：{hop.issuer.subject.text() if hop.issuer else '未知'}）"
        report.add(f"hop-{index}", f"第 {index + 1} 级验签：{hop.cert.subject.common_name() or '证书'}", PASS if hop.ok else FAIL, detail)

    # 2) 有效期
    for index, cert in enumerate(result.chain):
        status = cert.time_status(now)
        passed = status == "有效期内"
        report.add(f"time-{index}", f"第 {index + 1} 级有效期：{cert.subject.common_name() or '证书'}",
                   PASS if passed else FAIL, f"{cert.validity_text()}（{status}）")

    # 3) CA 约束（除终端实体之外的中间 CA）
    for index, cert in enumerate(result.chain[1:], start=1):
        if cert.is_self_signed and index == len(result.chain) - 1:
            continue  # 根证书自签，不要求 keyCertSign
        if not cert.is_ca:
            report.add(f"ca-{index}", f"第 {index + 1} 级 CA 基本约束", FAIL,
                       "该证书 basicConstraints 未标记 CA=TRUE，不能作为签发 CA。")
        elif "keyCertSign" not in cert.key_usage and cert.key_usage:
            report.add(f"ca-{index}", f"第 {index + 1} 级 CA 密钥用法", FAIL,
                       "keyUsage 未包含 keyCertSign，不能用于签发证书。")
        else:
            report.add(f"ca-{index}", f"第 {index + 1} 级 CA 基本约束", PASS,
                       f"CA=TRUE，pathLen={cert.path_len if cert.path_len is not None else '无限制'}")

    # 4) pathLen 约束
    path_violation = None
    for index, cert in enumerate(result.chain):
        if not cert.is_ca or cert.path_len is None:
            continue
        below = sum(1 for c in result.chain[:index] if c.is_ca and not _is_self_issued(c))
        if below > cert.path_len:
            path_violation = f"证书 {cert.subject.common_name()} 的 pathLen={cert.path_len}，但下方有 {below} 个 CA 证书。"
            break
    report.add("pathlen", "路径长度约束（pathLenConstraint）",
               FAIL if path_violation else PASS, path_violation or "满足约束")

    # 5) 终端实体不应为 CA
    if leaf.is_ca:
        report.note("注意：终端实体证书 basicConstraints 为 CA=TRUE。")
    # 6) 自签名根告警
    top = result.chain[-1]
    if top.is_self_signed:
        report.note("最上级证书为自签名证书；请确认该根证书确为可信锚点（离线工具需人工确认信任关系）。")

    return report


def parse_cert_input(text: str, fmt: str) -> list[Certificate]:
    entries = parse_certificates_text(text, fmt)
    certs = []
    for der, cert, err in entries:
        if cert is not None:
            certs.append(cert)
    if not certs:
        raise VerifyError("输入中未解析到任何有效证书。")
    return certs


def parse_certificates_text(text: str, fmt: str):
    from .keys import parse_certificates_text as _parse

    return _parse(text, fmt)
