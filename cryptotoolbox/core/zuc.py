"""ZUC 序列密码（GM/T 0001，原 ZUC-128）。

ZUC-256 与 ZUC-MAC 需要 GM/T 0001.1-2021 附录中的 S 盒与参数，当前版本暂不支持，
界面会明确提示“未支持”，不会给出错误结果。
"""
from __future__ import annotations

ZUC_SUPPORTED = ["ZUC-128"]
ZUC_UNSUPPORTED_NOTE = "ZUC-256 与 ZUC-MAC 需依据 GM/T 0001.1-2021 实现，当前版本暂未支持。"


class ZucError(ValueError):
    pass


def keystream(key: bytes, iv: bytes, length: int) -> bytes:
    if len(key) != 16:
        raise ZucError(f"ZUC-128 密钥应为 16 字节，当前 {len(key)} 字节。")
    if len(iv) != 16:
        raise ZucError(f"ZUC-128 IV 应为 16 字节，当前 {len(iv)} 字节。")
    if length < 0:
        raise ZucError("长度不能为负数。")
    try:
        from gmalg import ZUC
    except Exception as exc:  # noqa: BLE001
        raise ZucError("ZUC-128 需要 gmalg 库（pip install gmalg）。") from exc
    engine = ZUC(bytes(key), bytes(iv))
    out = bytearray()
    while len(out) < length:
        out.extend(engine.generate())
    return bytes(out[:length])


def crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    data = bytes(data)
    return bytes(a ^ b for a, b in zip(data, keystream(key, iv, len(data))))
