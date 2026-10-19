"""消息认证码：CBC-MAC 与 CMAC（AES / SM4）。

- CMAC 按 NIST SP 800-38B / GB/T 15852 实现（子密钥生成 + 10* 填充）
- CBC-MAC 为带填充的零 IV CBC 取末块
- 其它模式（EMAC/ANSI X9.19/LMAC/CBCR/TrCBC）暂不提供，界面显式标注
"""
from __future__ import annotations

from .blockcipher import block_size, encrypt

ALGORITHMS = ["SM4", "AES-128", "AES-192", "AES-256"]
MODES = ["CBC-MAC", "CMAC"]
UNSUPPORTED_MODES = ["EMAC", "ANSI X9.19", "MacDES", "LMAC", "CBCR", "TrCBC"]


class MacError(ValueError):
    pass


def _double(block: bytes) -> bytes:
    """GF(2^n) 上左移一位，按分组长度做多项式约简。"""
    bs = len(block)
    value = int.from_bytes(block, "big")
    carry = value >> (bs * 8 - 1)
    value = ((value << 1) & ((1 << (bs * 8)) - 1))
    if carry:
        value ^= 0x87 if bs == 16 else 0x1B
    return value.to_bytes(bs, "big")


def _encrypt_block(alg: str, key: bytes, block: bytes) -> bytes:
    return encrypt(alg, "ECB", "无填充", block, key)


def cmac(alg: str, key: bytes, data: bytes) -> bytes:
    bs = block_size(alg)
    if len(key) not in {"SM4": (16,), "AES-128": (16,), "AES-192": (24,), "AES-256": (32,)}[alg]:
        raise MacError(f"{alg} 的密钥长度不正确。")
    data = bytes(data)
    l_block = _encrypt_block(alg, key, bytes(bs))
    k1 = _double(l_block)
    k2 = _double(k1)
    if data and len(data) % bs == 0:
        last = bytes(a ^ b for a, b in zip(data[-bs:], k1))
        body = data[:-bs]
    else:
        pad_len = bs - (len(data) % bs)
        padded = data + b"\x80" + b"\x00" * (pad_len - 1)
        last = bytes(a ^ b for a, b in zip(padded[-bs:], k2))
        body = padded[:-bs]
    x = bytes(bs)
    for offset in range(0, len(body), bs):
        block = bytes(a ^ b for a, b in zip(x, body[offset:offset + bs]))
        x = _encrypt_block(alg, key, block)
    return _encrypt_block(alg, key, bytes(a ^ b for a, b in zip(x, last)))


def cbc_mac(alg: str, key: bytes, data: bytes) -> bytes:
    """CBC-MAC：数据为分组整数倍时按无填充处理（标准向量语义），否则 PKCS7 填充。"""
    bs = block_size(alg)
    iv = bytes(bs)
    padding = "无填充" if len(data) % bs == 0 and data else "PKCS7"
    cipher = encrypt(alg, "CBC", padding, data, key, iv)
    return cipher[-bs:]


def compute(mode: str, alg: str, key: bytes, data: bytes) -> bytes:
    if mode == "CMAC":
        return cmac(alg, key, data)
    if mode == "CBC-MAC":
        return cbc_mac(alg, key, data)
    raise MacError(f"暂不支持的 MAC 模式：{mode}（当前版本提供 CBC-MAC 与 CMAC）。")
