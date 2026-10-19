"""页面注册表：分组、标题、图标与懒加载工厂。

新增页面只需：
1. 在 ui/pages 下新建模块，导出 Page 类（继承 PageBase）
2. 在 GROUPS 中登记 id/title/module/class
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field


@dataclass
class PageSpec:
    id: str
    title: str
    module: str
    cls: str
    keywords: str = ""


@dataclass
class PageGroup:
    id: str
    title: str
    icon: str
    items: list[PageSpec] = field(default_factory=list)


GROUPS: list[PageGroup] = [
    PageGroup(
        id="A",
        title="常用工具",
        icon="tools",
        items=[
            PageSpec("score", "分数计算", "score", "ScorePage", "分数 评分 密评 GB/T 39786 cacscore"),
            PageSpec("encodings", "常见编码转换", "common_tools", "EncodingsPage", "编码 转换 hex base64"),
            PageSpec("length", "密文长度分析", "common_tools", "CipherLengthPage", "长度 分析 摘要 分组"),
            PageSpec("p7", "P7 签名数据解析", "common_tools", "Pkcs7Page", "pkcs7 cms 签名 解析"),
        ],
    ),
    PageGroup(
        id="B",
        title="密码算法校验",
        icon="lock",
        items=[
            PageSpec("blockcipher", "分组密码", "cipher", "BlockCipherPage", "分组 SM4 AES DES 模式 填充"),
            PageSpec("streamcipher", "序列算法", "cipher", "ZucPage", "序列 ZUC 流密码"),
            PageSpec("gcm", "GCM 模式", "cipher", "GcmPage", "GCM AEAD 认证加密"),
            PageSpec("hash", "哈希算法", "hash_mac", "HashPage", "哈希 SM3 SHA MD5"),
            PageSpec("mac", "MAC 算法", "hash_mac", "MacPage", "MAC CMAC CBC-MAC HMAC"),
            PageSpec("sm2_sign", "SM2 签名验签", "sm2", "Sm2SignPage", "SM2 签名 验签 UID"),
            PageSpec("sm2_crypt", "SM2 加密解密", "sm2", "Sm2CryptPage", "SM2 加密 解密 C1C3C2"),
            PageSpec("keygen", "密钥对生成", "sm2", "KeygenPage", "密钥 生成 密钥对 SM2 RSA"),
            PageSpec("rsa", "RSA 签名验签", "rsa_page", "RsaPage", "RSA 签名 验签 PKCS1 PSS"),
        ],
    ),
    PageGroup(
        id="C",
        title="协议分析",
        icon="network",
        items=[
            PageSpec("pcap", "PCAP 加密数据提取", "pcap_page", "PcapPage", "PCAP TLS TLCP ESP 证书"),
        ],
    ),
    PageGroup(
        id="D",
        title="数字证书",
        icon="cert",
        items=[
            PageSpec("certchain", "证书链验证", "cert", "CertChainPage", "证书链 验签 信任"),
            PageSpec("revocation", "证书吊销检查", "cert", "RevocationPage", "CRL OCSP 吊销"),
            PageSpec("certparse", "ASN.1 证书解析", "cert", "CertParsePage", "ASN.1 证书 解析 结构"),
            PageSpec("crl", "CRL 格式校验", "cert", "CrlPage", "CRL 吊销列表 验签"),
        ],
    ),
    PageGroup(
        id="E",
        title="随机数检测",
        icon="dice",
        items=[
            PageSpec("randomness", "GM/T 0005-2021 随机性检测", "randomness", "RandomnessPage", "随机性 检测 GM/T 0005"),
        ],
    ),
    PageGroup(
        id="F",
        title="电子签章",
        icon="seal",
        items=[
            PageSpec("seal", "电子签章校验", "seal_page", "SealPage", "电子签章 PDF OFD 验签"),
        ],
    ),
]


def all_specs() -> list[PageSpec]:
    return [spec for group in GROUPS for spec in group.items]


def find_spec(page_id: str) -> PageSpec | None:
    for spec in all_specs():
        if spec.id == page_id:
            return spec
    return None


def load_page(page_id: str, window=None):
    """按需导入并实例化页面。失败时抛出异常，由主窗口展示占位页。"""
    spec = find_spec(page_id)
    if spec is None:
        raise KeyError(f"未知页面: {page_id}")
    module = importlib.import_module(f"cryptotoolbox.ui.pages.{spec.module}")
    cls = getattr(module, spec.cls)
    return cls(window)
