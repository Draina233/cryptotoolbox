"""SM2 椭圆曲线公钥密码算法（GB/T 32918 / GM/T 0003）。

实现范围：
- 密钥生成、公钥派生（含用户标识 UID）
- 签名/验签（支持自定义 UID，修复原项目 UID 被库静默忽略的问题）
- 加密/解密（C1C3C2 与 C1C2C3 两种密文格式）
- ZA / e 值计算，DER(r,s) 编解码

本实现按标准公式独立实现曲线运算，并用 GM/T 0003.5-2012 附录 A 示例曲线向量、
官方推荐曲线向量（Botan 测试数据）以及 gmalg 交叉验证。
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional

from .der import DerError, build_integer, build_sequence, parse_tlv
from .digest import sm3

# 官方推荐曲线参数（GB/T 32918.5-2017 / GM/T 0003.5-2012）
DEFAULT_PARAMS = dict(
    p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
    gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
)

# GM/T 0003.5-2012 附录 A 的示例曲线（测试向量使用）
EXAMPLE_PARAMS = dict(
    p=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
    a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
    b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
    n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
    gx=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
    gy=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2,
)

DEFAULT_UID = b"1234567812345678"


class SM2Error(ValueError):
    pass


@dataclass
class Point:
    x: int
    y: int


class Curve:
    def __init__(self, params: dict | None = None):
        p = params or DEFAULT_PARAMS
        self.p = p["p"]
        self.a = p["a"]
        self.b = p["b"]
        self.n = p["n"]
        self.gx = p["gx"]
        self.gy = p["gy"]
        self.g = Point(self.gx, self.gy)

    # ------------------------------------------------------------ 曲线运算
    def is_on_curve(self, point: Point) -> bool:
        return (point.y * point.y - (point.x * point.x * point.x + self.a * point.x + self.b)) % self.p == 0

    def add(self, p1: Optional[Point], p2: Optional[Point]) -> Optional[Point]:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        p = self.p
        if p1.x == p2.x:
            if (p1.y + p2.y) % p == 0:
                return None
            lam = (3 * p1.x * p1.x + self.a) * pow(2 * p1.y, -1, p) % p
        else:
            lam = (p2.y - p1.y) * pow(p2.x - p1.x, -1, p) % p
        x3 = (lam * lam - p1.x - p2.x) % p
        return Point(x3, (lam * (p1.x - x3) - p1.y) % p)

    def mul(self, k: int, point: Point) -> Optional[Point]:
        k %= self.n
        if k == 0:
            return None
        acc: Optional[Point] = None
        addend: Optional[Point] = point
        while k:
            if k & 1:
                acc = self.add(acc, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return acc


DEFAULT_CURVE = Curve(DEFAULT_PARAMS)
EXAMPLE_CURVE = Curve(EXAMPLE_PARAMS)


# ---------------------------------------------------------------- 编解码
def _bytes32(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _int32(raw: bytes) -> int:
    if len(raw) != 32:
        raise SM2Error(f"期望 32 字节整数，实际 {len(raw)} 字节。")
    return int.from_bytes(raw, "big")


def encode_point(point: Point) -> bytes:
    return b"\x04" + _bytes32(point.x) + _bytes32(point.y)


def decode_point(raw: bytes, curve: Curve = DEFAULT_CURVE) -> Point:
    raw = bytes(raw or b"")
    if len(raw) == 65 and raw[0] == 0x04:
        x, y = int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
    elif len(raw) == 64:
        x, y = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    else:
        raise SM2Error(f"公钥长度应为 65 字节（04||X||Y）或 64 字节（X||Y），实际 {len(raw)} 字节。")
    point = Point(x, y)
    if not curve.is_on_curve(point):
        raise SM2Error("公钥不在 SM2 曲线上（可能不是有效公钥）。")
    return point


def normalize_public_key(raw: bytes) -> bytes:
    return encode_point(decode_point(raw))


def normalize_private_key(raw: bytes, curve: Curve = DEFAULT_CURVE) -> int:
    if isinstance(raw, int):
        d = raw
    else:
        raw = bytes(raw or b"")
        if len(raw) != 32:
            raise SM2Error(f"SM2 私钥应为 32 字节（64 个十六进制字符），实际 {len(raw)} 字节。")
        d = int.from_bytes(raw, "big")
    if not 1 <= d <= curve.n - 1:
        raise SM2Error("SM2 私钥超出范围 [1, n-1]。")
    return d


# ---------------------------------------------------------------- 密钥
def generate_keypair(curve: Curve = DEFAULT_CURVE) -> tuple[bytes, bytes]:
    """返回 (私钥 32 字节, 公钥 65 字节 04||X||Y)。"""
    d = secrets.randbelow(curve.n - 1) + 1
    pub = curve.mul(d, curve.g)
    if pub is None:
        raise SM2Error("密钥生成失败（极低概率事件），请重试。")
    return _bytes32(d), encode_point(pub)


def derive_public_key(private: bytes | int, curve: Curve = DEFAULT_CURVE) -> bytes:
    d = normalize_private_key(private, curve)
    pub = curve.mul(d, curve.g)
    if pub is None:
        raise SM2Error("私钥无效。")
    return encode_point(pub)


# ---------------------------------------------------------------- ZA / e
def z_value(uid: bytes, public_key: bytes, curve: Curve = DEFAULT_CURVE) -> bytes:
    """ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA)，ENTL 为 ID 位长的 2 字节大端。"""
    uid = bytes(uid or b"")
    if len(uid) * 8 >= 0x10000:
        raise SM2Error("用户标识过长。")
    entl = (len(uid) * 8).to_bytes(2, "big")
    point = decode_point(public_key, curve)
    data = (
        entl + uid
        + _bytes32(curve.a) + _bytes32(curve.b)
        + _bytes32(curve.gx) + _bytes32(curve.gy)
        + _bytes32(point.x) + _bytes32(point.y)
    )
    return sm3(data)


def e_value(message: bytes, uid: bytes, public_key: bytes, curve: Curve = DEFAULT_CURVE) -> bytes:
    return sm3(z_value(uid, public_key, curve) + bytes(message))


# ---------------------------------------------------------------- 签名
def sign(message: bytes, private: bytes | int, uid: bytes = DEFAULT_UID,
         curve: Curve = DEFAULT_CURVE, k: int | None = None) -> tuple[int, int]:
    d = normalize_private_key(private, curve)
    public = derive_public_key(d, curve)
    e = int.from_bytes(e_value(message, uid, public, curve), "big")
    n = curve.n
    for _ in range(64):
        kk = k if k is not None else secrets.randbelow(n - 1) + 1
        if not 1 <= kk <= n - 1:
            raise SM2Error("随机数 k 超出范围 [1, n-1]。")
        point = curve.mul(kk, curve.g)
        if point is None:
            if k is not None:
                raise SM2Error("k 与 G 运算得到无穷远点，请更换 k。")
            continue
        r = (e + point.x) % n
        if r == 0 or (r + kk) % n == 0:
            if k is not None:
                raise SM2Error("k 导致 r=0 或 r+k=n，请更换 k。")
            continue
        s = pow(1 + d, -1, n) * (kk - r * d) % n
        if s == 0:
            if k is not None:
                raise SM2Error("k 导致 s=0，请更换 k。")
            continue
        return r, s
    raise SM2Error("签名失败：随机数重试次数过多。")  # pragma: no cover


def verify(message: bytes, signature_rs: tuple[int, int], public_key: bytes,
           uid: bytes = DEFAULT_UID, curve: Curve = DEFAULT_CURVE) -> bool:
    r, s = signature_rs
    point = decode_point(public_key, curve)
    e = int.from_bytes(e_value(message, uid, public_key, curve), "big")
    return _verify_raw(e, point, r, s, curve)


def verify_e(e: bytes, signature_rs: tuple[int, int], public_key: bytes, curve: Curve = DEFAULT_CURVE) -> bool:
    """基于预先计算好的 e 值验签（对应原项目“基于 e 值验签”模式）。"""
    if len(e) != 32:
        raise SM2Error("e 值应为 32 字节（SM3 输出）。")
    point = decode_point(public_key, curve)
    return _verify_raw(int.from_bytes(e, "big"), point, signature_rs[0], signature_rs[1], curve)


def _verify_raw(e: int, public: Point, r: int, s: int, curve: Curve) -> bool:
    n = curve.n
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    t = (r + s) % n
    if t == 0:
        return False
    p1 = curve.mul(s, curve.g)
    p2 = curve.mul(t, public)
    p3 = curve.add(p1, p2)
    if p3 is None:
        return False
    return (e + p3.x) % n == r


# ---------------------------------------------------------------- DER (r,s)
def rs_to_der(r: int, s: int) -> bytes:
    return build_sequence(build_integer(r), build_integer(s))


def der_to_rs(der: bytes) -> tuple[int, int]:
    der = bytes(der)
    top = parse_tlv(der)
    if top.tag != 16:
        raise SM2Error("签名值不是 DER SEQUENCE。")
    items = top.children()
    if len(items) != 2:
        raise SM2Error("签名 DER 应包含 r、s 两个 INTEGER。")
    return items[0].as_int(), items[1].as_int()


def raw_rs(signature: bytes) -> tuple[int, int]:
    """解析 64 字节 r||s。"""
    signature = bytes(signature)
    if len(signature) != 64:
        raise SM2Error(f"r||s 签名应为 64 字节，实际 {len(signature)} 字节。")
    return int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")


def signature_to_der(signature: bytes) -> bytes:
    return rs_to_der(*raw_rs(signature))


def signature_from_der(der: bytes) -> bytes:
    r, s = der_to_rs(der)
    return _bytes32(r) + _bytes32(s)


# ---------------------------------------------------------------- 加密
def kdf(z: bytes, klen: int) -> bytes:
    """SM2 密钥派生函数（基于 SM3 计数器模式）。"""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out.extend(sm3(bytes(z) + ct.to_bytes(4, "big")))
        ct += 1
    return bytes(out[:klen])


def encrypt(message: bytes, public_key: bytes, mode: str = "C1C3C2",
            curve: Curve = DEFAULT_CURVE) -> bytes:
    message = bytes(message)
    public = decode_point(public_key, curve)
    for _ in range(64):
        k = secrets.randbelow(curve.n - 1) + 1
        c1 = curve.mul(k, curve.g)
        if c1 is None:
            continue
        p2 = curve.mul(k, public)
        if p2 is None:
            continue
        x2, y2 = _bytes32(p2.x), _bytes32(p2.y)
        t = kdf(x2 + y2, len(message))
        if not any(t):
            continue
        c2 = bytes(a ^ b for a, b in zip(message, t))
        c3 = sm3(x2 + message + y2)
        if mode == "C1C2C3":
            return encode_point(c1) + c2 + c3
        return encode_point(c1) + c3 + c2
    raise SM2Error("加密失败：随机数重试次数过多。")  # pragma: no cover


def split_cipher(cipher: bytes, mode: str = "C1C3C2") -> tuple[bytes, bytes, bytes]:
    """返回 (C1 65 字节, C3 32 字节, C2)，与 mode 无关的规范化拆分。"""
    cipher = bytes(cipher)
    if len(cipher) < 65 + 32:
        raise SM2Error(f"SM2 密文至少 97 字节（含 65 字节 C1 与 32 字节 C3），实际 {len(cipher)} 字节。")
    c1 = cipher[:65]
    if c1[0] != 0x04:
        raise SM2Error("SM2 密文 C1 应以 0x04 开头。")
    rest = cipher[65:]
    if mode == "C1C2C3":
        c2, c3 = rest[:-32], rest[-32:]
    else:
        c3, c2 = rest[:32], rest[32:]
    return c1, c3, c2


def decrypt(cipher: bytes, private: bytes | int, mode: str = "C1C3C2",
            curve: Curve = DEFAULT_CURVE) -> bytes:
    d = normalize_private_key(private, curve)
    c1_raw, c3, c2 = split_cipher(cipher, mode)
    c1 = decode_point(c1_raw, curve)
    p2 = curve.mul(d, c1)
    if p2 is None:
        raise SM2Error("C1 与私钥运算得到无穷远点，密文无效。")
    x2, y2 = _bytes32(p2.x), _bytes32(p2.y)
    t = kdf(x2 + y2, len(c2))
    if not any(t):
        raise SM2Error("KDF 输出全零，密文无效。")
    message = bytes(a ^ b for a, b in zip(c2, t))
    if sm3(x2 + message + y2) != c3:
        raise SM2Error("C3 校验失败：密文被篡改、密钥不匹配或密文格式选择错误。")
    return message
