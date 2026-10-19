"""哈希与 HMAC。

SM3 优先使用 tongsuopy 的 C 实现（快），并用纯 Python 实现作为后备与交叉验证；
HMAC-SM3 按 RFC 2104 / GB/T 15852.1 的 ipad/opad 结构实现（修复原项目 H(K‖M) 的错误）。
"""
from __future__ import annotations

import hashlib
import hmac

# ---------------------------------------------------------------- SM3 常量
_SM3_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
           0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
_SM3_T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
_MASK32 = 0xFFFFFFFF


def _rol(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _p0(x: int) -> int:
    return x ^ _rol(x, 9) ^ _rol(x, 17)


def _p1(x: int) -> int:
    return x ^ _rol(x, 15) ^ _rol(x, 23)


def _ff(x: int, y: int, z: int, j: int) -> int:
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(x: int, y: int, z: int, j: int) -> int:
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x) & z) & _MASK32)


def sm3_pure(data: bytes) -> bytes:
    """纯 Python SM3（GB/T 32905-2016），用于后备与自检。"""
    data = bytes(data)
    bit_len = len(data) * 8
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded += bit_len.to_bytes(8, "big")

    state = list(_SM3_IV)
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rol(w[j - 3], 15)) ^ _rol(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = state
        for j in range(64):
            ss1 = _rol((_rol(a, 12) + e + _rol(_SM3_T[j], j)) & _MASK32, 7)
            ss2 = ss1 ^ _rol(a, 12)
            tt1 = (_ff(a, b, c, j) + d + ss2 + w1[j]) & _MASK32
            tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & _MASK32
            d = c
            c = _rol(b, 9)
            b = a
            a = tt1
            h = g
            g = _rol(f, 19)
            f = e
            e = _p0(tt2)
        state = [x ^ y for x, y in zip(state, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in state)


# ---------------------------------------------------------------- SM3 hashlib 适配
_HAS_TONGSUO = False
try:  # pragma: no cover - 环境相关
    from tongsuopy.crypto import hashes as _tsh
    from tongsuopy.crypto.hashes import SM3 as _TongsuoSM3

    _HAS_TONGSUO = True
except Exception:  # noqa: BLE001
    _tsh = None
    _TongsuoSM3 = None


class SM3Hash:
    """hashlib 风格的 SM3，可直接用于 hmac.new(key, data, digestmod=SM3Hash)。"""

    block_size = 64
    digest_size = 32
    name = "sm3"

    def __init__(self, data: bytes = b""):
        self._buffer = bytearray()
        self._native = None
        if _HAS_TONGSUO:
            try:
                self._native = _tsh.Hash(_TongsuoSM3())
            except Exception:  # noqa: BLE001
                self._native = None
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        data = bytes(data)
        if self._native is not None:
            try:
                self._native.update(data)
                return
            except Exception:  # noqa: BLE001
                self._native = None
        self._buffer.extend(data)

    def digest(self) -> bytes:
        if self._native is not None:
            try:
                clone = self._native.copy()
                return bytes(clone.finalize())
            except Exception:  # noqa: BLE001
                pass
        return sm3_pure(bytes(self._buffer))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "SM3Hash":
        new = SM3Hash()
        if self._native is not None:
            try:
                new._native = self._native.copy()
                return new
            except Exception:  # noqa: BLE001
                new._native = None
        new._buffer = bytearray(self._buffer)
        return new


# ---------------------------------------------------------------- 统一接口
ALGORITHMS = ["SM3", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
              "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "MD5"]

_HASHLIB_MAP = {
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "SHA3-224": hashlib.sha3_224,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
    "MD5": hashlib.md5,
    "SM3": SM3Hash,
}

DIGEST_SIZES = {name: (32 if name == "SM3" else _HASHLIB_MAP[name]().digest_size) for name in ALGORITHMS}


def digest(algo: str, data: bytes) -> bytes:
    if algo not in _HASHLIB_MAP:
        raise ValueError(f"未知哈希算法：{algo}")
    if algo == "SM3":
        hasher = SM3Hash()
        hasher.update(data)
        return hasher.digest()
    return _HASHLIB_MAP[algo](bytes(data)).digest()


def digest_hex(algo: str, data: bytes, upper: bool = True) -> str:
    text = digest(algo, data).hex()
    return text.upper() if upper else text


def hmac_digest(algo: str, key: bytes, data: bytes) -> bytes:
    if algo not in _HASHLIB_MAP:
        raise ValueError(f"未知哈希算法：{algo}")
    return hmac.new(bytes(key), bytes(data), _HASHLIB_MAP[algo]).digest()


def hmac_hex(algo: str, key: bytes, data: bytes, upper: bool = True) -> str:
    text = hmac_digest(algo, key, data).hex()
    return text.upper() if upper else text


def sm3(data: bytes) -> bytes:
    return digest("SM3", data)


def hmac_sm3(key: bytes, data: bytes) -> bytes:
    return hmac_digest("SM3", key, data)
