"""分组密码：AES / DES / 3DES / SM4，模式与填充。

关键修复（相对原项目）：
- AES-CTR 支持任意长度 IV（含最常见的 16 字节初始计数器），不再把 IV 当 nonce 而必然报错
- CTR/OFB/CFB 为流模式，不套分组填充；选择填充时明确提示“流模式忽略填充”
- 密钥/IV 长度校验给出中文原因
- XTS 仅支持 AES（国密 SM4 无标准 XTS 模式），密钥须为两倍长度
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .encodings import EncodingError

BLOCK_SIZES = {
    "SM4": 16,
    "AES-128": 16,
    "AES-192": 16,
    "AES-256": 16,
    "DES": 8,
    "3DES": 8,
}

KEY_SIZES = {
    "SM4": [16],
    "AES-128": [16],
    "AES-192": [24],
    "AES-256": [32],
    "DES": [8],
    "3DES": [16, 24],
}

ALGORITHMS = list(KEY_SIZES.keys())
MODES = ["ECB", "CBC", "CFB", "OFB", "CTR", "XTS"]
PADDING_SCHEMES = ["PKCS7", "ISO10126", "ISO7816-4", "ANSI X9.23", "Zero", "无填充"]

STREAM_MODES = {"CFB", "OFB", "CTR"}
UNSUPPORTED_COMBOS = {
    ("SM4", "XTS"): "SM4 没有标准 XTS 模式（XTS 仅用于 AES 磁盘加密场景）。",
    ("DES", "XTS"): "DES 不支持 XTS 模式。",
    ("3DES", "XTS"): "3DES 不支持 XTS 模式。",
}


class CipherError(ValueError):
    pass


class PaddingError(ValueError):
    pass


def block_size(alg: str) -> int:
    if alg not in BLOCK_SIZES:
        raise CipherError(f"未知算法：{alg}")
    return BLOCK_SIZES[alg]


def validate_key(alg: str, key: bytes) -> None:
    sizes = KEY_SIZES.get(alg)
    if sizes is None:
        raise CipherError(f"未知算法：{alg}")
    if len(key) not in sizes:
        wanted = " / ".join(str(s) for s in sizes)
        raise CipherError(f"{alg} 的密钥长度应为 {wanted} 字节，当前为 {len(key)} 字节。")


def validate_iv(alg: str, mode: str, iv: bytes, key: bytes | None = None) -> None:
    if mode == "ECB":
        return
    if mode == "XTS":
        if alg != "AES-128" and alg != "AES-256":
            raise CipherError(UNSUPPORTED_COMBOS.get((alg, mode), "XTS 仅支持 AES-128/AES-256。"))
        if key is not None and len(key) not in (32, 64):
            raise CipherError("XTS 模式密钥须为两倍分组长度（AES-128→32 字节，AES-256→64 字节）。")
        if len(iv) != 16:
            raise CipherError(f"XTS 的 IV（tweak）应为 16 字节，当前 {len(iv)} 字节。")
        return
    bs = block_size(alg)
    if not iv:
        raise CipherError(f"{mode} 模式需要 IV，当前为空。")
    if mode == "CTR":
        if len(iv) > bs:
            raise CipherError(f"CTR 的 IV 不能超过 {bs} 字节（当前 {len(iv)} 字节）。")
        return
    if len(iv) != bs:
        raise CipherError(f"{alg} 的 {mode} 模式 IV 应为 {bs} 字节，当前 {len(iv)} 字节。")


def mode_uses_padding(mode: str) -> bool:
    return mode not in STREAM_MODES


# ---------------------------------------------------------------- 填充
def pad(data: bytes, bs: int, scheme: str) -> tuple[bytes, str]:
    """返回 (填充后数据, 提示)。流模式不填充。"""
    if scheme in ("无填充", "", None):
        if len(data) % bs:
            raise PaddingError(f"当前选择“无填充”，但数据长度 {len(data)} 不是分组长度 {bs} 的整数倍。")
        return bytes(data), ""
    if len(data) % bs == 0 and scheme != "Zero":
        n = bs
    else:
        n = bs - (len(data) % bs)
        if n == bs and scheme == "Zero":
            return bytes(data), ""
    if scheme == "PKCS7":
        return bytes(data) + bytes([n]) * n, ""
    if scheme == "ISO10126":
        return bytes(data) + os.urandom(n - 1) + bytes([n]), ""
    if scheme == "ISO7816-4":
        return bytes(data) + b"\x80" + b"\x00" * (n - 1), ""
    if scheme == "ANSI X9.23":
        return bytes(data) + b"\x00" * (n - 1) + bytes([n]), ""
    if scheme == "Zero":
        pad_len = bs - (len(data) % bs)
        return bytes(data) + b"\x00" * pad_len, ""
    raise PaddingError(f"未知填充方式：{scheme}")


def unpad(data: bytes, bs: int, scheme: str) -> tuple[bytes, str]:
    """返回 (去填充数据, 警告)。警告非空表示去填充失败，data 为原始内容。"""
    if scheme in ("无填充", "", None):
        return bytes(data), ""
    if scheme == "Zero":
        stripped = bytes(data).rstrip(b"\x00")
        warning = "" if len(stripped) != len(data) else "Zero 填充未找到填充字节；若明文本身以 0x00 结尾，结尾字节可能被误删。"
        return stripped, warning
    if not data:
        raise PaddingError("数据为空，无法去填充。")
    if scheme == "ISO7816-4":
        # 填充为 0x80 后跟若干 0x00；最后字节可能是 0x00，需向前查找 0x80
        idx = len(data) - 1
        while idx >= 0 and data[idx] == 0x00:
            idx -= 1
        if idx < 0 or data[idx] != 0x80:
            raise PaddingError("ISO 7816-4 填充校验失败：未找到 0x80 标记（密钥或数据可能错误）。")
        return bytes(data[:idx]), ""
    n = data[-1]
    if n == 0 or n > bs:
        raise PaddingError(f"填充非法：最后一个字节为 {n:#04x}，超出 1..{bs} 范围（密钥或数据可能错误）。")
    if scheme == "PKCS7":
        if not all(b == n for b in data[-n:]):
            raise PaddingError("PKCS7 填充校验失败：填充字节不一致（密钥或数据可能错误）。")
        return bytes(data[:-n]), ""
    if scheme == "ISO10126":
        return bytes(data[:-n]), ""
    if scheme == "ANSI X9.23":
        return bytes(data[:-n]), ""
    raise PaddingError(f"未知填充方式：{scheme}")


# ---------------------------------------------------------------- 底层分组运算
def _sm4_cipher(key: bytes, mode: str, iv: bytes):
    try:
        from tongsuopy.crypto.ciphers import Cipher, algorithms, modes
    except Exception as exc:  # noqa: BLE001
        raise CipherError("SM4 需要 tongsuopy 库（pip install tongsuopy）。") from exc
    mode_obj = {
        "ECB": modes.ECB,
        "CBC": lambda: modes.CBC(iv),
        "CFB": lambda: modes.CFB(iv),
        "OFB": lambda: modes.OFB(iv),
        "CTR": lambda: modes.CTR(iv),
    }[mode]()
    return Cipher(algorithms.SM4(bytes(key)), mode_obj)


def _aes_cipher(key: bytes, mode: str, iv: bytes):
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    if mode == "ECB":
        return AES.new(bytes(key), AES.MODE_ECB)
    if mode == "CBC":
        return AES.new(bytes(key), AES.MODE_CBC, iv=bytes(iv))
    if mode == "CFB":
        return AES.new(bytes(key), AES.MODE_CFB, iv=bytes(iv), segment_size=128)
    if mode == "OFB":
        return AES.new(bytes(key), AES.MODE_OFB, iv=bytes(iv))
    if mode == "CTR":
        iv16 = bytes(iv) + b"\x00" * (16 - len(iv))
        counter = Counter.new(128, initial_value=int.from_bytes(iv16, "big"))
        return AES.new(bytes(key), AES.MODE_CTR, counter=counter)
    if mode == "XTS":
        return AES.new(bytes(key), AES.MODE_XTS)
    raise CipherError(f"AES 不支持模式：{mode}")


def _des_cipher(key: bytes, alg: str, mode: str, iv: bytes):
    from Crypto.Cipher import DES, DES3

    factory = DES if alg == "DES" else DES3
    mode_map = {
        "ECB": (factory.MODE_ECB, None),
        "CBC": (factory.MODE_CBC, bytes(iv)),
        "CFB": (factory.MODE_CFB, bytes(iv)),
        "OFB": (factory.MODE_OFB, bytes(iv)),
    }
    if mode not in mode_map:
        raise CipherError(f"{alg} 不支持模式：{mode}")
    mode_const, iv_value = mode_map[mode]
    if iv_value is None:
        return factory.new(bytes(key), mode_const)
    return factory.new(bytes(key), mode_const, iv=iv_value)


# ---------------------------------------------------------------- XTS（IEEE 1619）
def _xts_mul_alpha(tweak: bytes) -> bytes:
    value = int.from_bytes(tweak, "little")
    carry = value >> 127
    value = ((value << 1) & ((1 << 128) - 1)) ^ (0x87 if carry else 0)
    return value.to_bytes(16, "little")


def _xts_crypt(decrypt: bool, data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-XTS（IEEE 1619-2007）：IV 为数据单元号的 16 字节小端编码（tweak 输入）。"""
    from Crypto.Cipher import AES

    half = len(key) // 2
    k1, k2 = bytes(key[:half]), bytes(key[half:])
    ecb_k1 = AES.new(k1, AES.MODE_ECB)
    ecb_k2 = AES.new(k2, AES.MODE_ECB)
    tweak = ecb_k2.encrypt(bytes(iv))  # T_0 = E_k2(IV)
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        x = bytes(a ^ b for a, b in zip(block, tweak))
        y = ecb_k1.decrypt(x) if decrypt else ecb_k1.encrypt(x)
        out.extend(a ^ b for a, b in zip(y, tweak))
        tweak = _xts_mul_alpha(tweak)
    return bytes(out)


def _new_cipher(alg: str, mode: str, key: bytes, iv: bytes):
    if alg == "SM4":
        return _sm4_cipher(key, mode, iv)
    if alg.startswith("AES"):
        return _aes_cipher(key, mode, iv)
    if alg in ("DES", "3DES"):
        return _des_cipher(key, alg, mode, iv)
    raise CipherError(f"未知算法：{alg}")


def _encrypt_raw(alg: str, mode: str, data: bytes, key: bytes, iv: bytes) -> bytes:
    if mode == "XTS":
        return _xts_crypt(False, data, key, iv)
    if alg in ("DES", "3DES") and mode == "ECB" and alg == "3DES" and len(key) == 16:
        key = DES3_expand(key)
    cipher = _new_cipher(alg, mode, key, iv)
    if alg == "SM4":
        enc = cipher.encryptor()
        return enc.update(bytes(data)) + enc.finalize()
    return cipher.encrypt(bytes(data))


def _decrypt_raw(alg: str, mode: str, data: bytes, key: bytes, iv: bytes) -> bytes:
    if mode == "XTS":
        return _xts_crypt(True, data, key, iv)
    if alg in ("DES", "3DES") and mode == "ECB" and alg == "3DES" and len(key) == 16:
        key = DES3_expand(key)
    cipher = _new_cipher(alg, mode, key, iv)
    if alg == "SM4":
        dec = cipher.decryptor()
        return dec.update(bytes(data)) + dec.finalize()
    return cipher.decrypt(bytes(data))


def DES3_expand(key16: bytes) -> bytes:
    """16 字节 3DES 密钥（K1K2）扩展为 24 字节 K1K2K1。"""
    return bytes(key16) + bytes(key16[:8])


# ---------------------------------------------------------------- 对外接口
XTS_KEY_SIZES = {"AES-128": 32, "AES-192": 48, "AES-256": 64}


def _validate(alg: str, mode: str, key: bytes, iv: bytes) -> None:
    if (alg, mode) in UNSUPPORTED_COMBOS:
        raise CipherError(UNSUPPORTED_COMBOS[(alg, mode)])
    if mode == "XTS":
        expected = XTS_KEY_SIZES.get(alg)
        if expected is None:
            raise CipherError("XTS 仅支持 AES-128/AES-192/AES-256。")
        if len(key) != expected:
            raise CipherError(f"{alg} 的 XTS 密钥应为 {expected} 字节（两份 {expected // 2} 字节密钥），当前 {len(key)} 字节。")
        if not iv or len(iv) != 16:
            raise CipherError(f"XTS 的 IV（tweak）应为 16 字节，当前 {len(iv)} 字节。")
        return
    validate_key(alg, key)
    validate_iv(alg, mode, iv, key)


def encrypt(alg: str, mode: str, padding: str, data: bytes, key: bytes, iv: bytes = b"") -> bytes:
    data = bytes(data)
    _validate(alg, mode, key, iv)
    bs = block_size(alg)
    if mode_uses_padding(mode):
        padded, _ = pad(data, bs, padding)
        return _encrypt_raw(alg, mode, padded, key, iv)
    return _encrypt_raw(alg, mode, data, key, iv)


def decrypt(alg: str, mode: str, padding: str, data: bytes, key: bytes, iv: bytes = b"") -> tuple[bytes, str]:
    data = bytes(data)
    _validate(alg, mode, key, iv)
    bs = block_size(alg)
    plain = _decrypt_raw(alg, mode, data, key, iv)
    if mode_uses_padding(mode):
        try:
            return unpad(plain, bs, padding)
        except PaddingError as exc:
            return plain, f"{exc}（以下为未去填充的原始解密结果，请人工核对。）"
    if padding not in ("无填充", "", None):
        return plain, f"{mode} 为流模式，未应用“{padding}”填充。"
    return plain, ""


def mode_note(mode: str, padding: str) -> str:
    if mode in STREAM_MODES and padding not in ("无填充", "", None):
        return f"{mode} 为流模式，将忽略“{padding}”填充设置。"
    return ""
