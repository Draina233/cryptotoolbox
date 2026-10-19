"""GCM 认证加密：AES-GCM（PyCryptodome）与 SM4-GCM（tongsuopy）。"""
from __future__ import annotations

GCM_ALGORITHMS = ["SM4-GCM", "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"]

KEY_SIZES = {
    "SM4-GCM": [16],
    "AES-128-GCM": [16],
    "AES-192-GCM": [24],
    "AES-256-GCM": [32],
}


class GcmError(ValueError):
    pass


class GcmAuthError(GcmError):
    pass


def _check(alg: str, key: bytes, iv: bytes, tag_len: int | None) -> None:
    if alg not in KEY_SIZES:
        raise GcmError(f"未知 GCM 算法：{alg}")
    if len(key) not in KEY_SIZES[alg]:
        raise GcmError(f"{alg} 的密钥长度应为 {KEY_SIZES[alg][0]} 字节，当前 {len(key)} 字节。")
    if not iv:
        raise GcmError("GCM 需要 IV（nonce），当前为空。")
    if len(iv) > 16:
        raise GcmError(f"GCM 的 IV 建议 12 字节，最长 16 字节；当前 {len(iv)} 字节。")
    if tag_len is not None and not (4 <= tag_len <= 16):
        raise GcmError("GCM 认证标签长度应在 4–16 字节之间。")


def encrypt(alg: str, data: bytes, key: bytes, iv: bytes, aad: bytes = b"",
            tag_len: int = 16) -> tuple[bytes, bytes]:
    """返回 (密文, 认证标签)。"""
    _check(alg, key, iv, tag_len)
    data = bytes(data)
    aad = bytes(aad)
    if alg == "SM4-GCM":
        try:
            from tongsuopy.crypto.ciphers import Cipher, algorithms, modes
        except Exception as exc:  # noqa: BLE001
            raise GcmError("SM4-GCM 需要 tongsuopy 库。") from exc
        cipher = Cipher(algorithms.SM4(bytes(key)), modes.GCM(bytes(iv)))
        enc = cipher.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(data) + enc.finalize()
        return ct, bytes(enc.tag)
    from Crypto.Cipher import AES

    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(iv), mac_len=tag_len)
    if aad:
        cipher.update(aad)
    return cipher.encrypt_and_digest(data)


def decrypt(alg: str, data: bytes, tag: bytes, key: bytes, iv: bytes, aad: bytes = b"",
            tag_len: int = 16) -> bytes:
    _check(alg, key, iv, tag_len)
    data = bytes(data)
    tag = bytes(tag)
    aad = bytes(aad)
    if not tag:
        raise GcmError("缺少认证标签（Tag）。")
    if alg == "SM4-GCM":
        try:
            from tongsuopy.crypto.ciphers import Cipher, algorithms, modes
        except Exception as exc:  # noqa: BLE001
            raise GcmError("SM4-GCM 需要 tongsuopy 库。") from exc
        try:
            cipher = Cipher(algorithms.SM4(bytes(key)), modes.GCM(bytes(iv), tag))
            dec = cipher.decryptor()
            if aad:
                dec.authenticate_additional_data(aad)
            return dec.update(data) + dec.finalize()
        except Exception as exc:  # noqa: BLE001
            raise GcmAuthError(f"SM4-GCM 认证失败：密文、AAD、Tag 或密钥不匹配（{exc}）。") from exc
    from Crypto.Cipher import AES

    try:
        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(iv), mac_len=tag_len)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(data, tag)
    except ValueError as exc:
        raise GcmAuthError(f"AES-GCM 认证失败：密文、AAD、Tag 或密钥不匹配（{exc}）。") from exc
