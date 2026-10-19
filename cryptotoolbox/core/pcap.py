"""纯 Python PCAP / PCAPNG 解析与 TLS/TLCP 加密材料提取。

功能：
- 支持 pcap 与 pcapng 文件（Ethernet / Linux SLL / raw IP / loopback）
- IPv4 / IPv6、TCP 重组、UDP
- TLS/TLCP 记录解析：ClientHello（SNI/版本/套件）、ServerHello、Certificate、application data（保留记录边界）
- IKE（UDP 500/4500）证书扫描、IPsec ESP 加密载荷提取
- 按 IP 对筛选（双向）

不依赖 tshark / Wireshark。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .x509 import parse_certificate

# ---------------------------------------------------------------- 常量
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23
TLS_ALERT = 21
TLS_CHANGE_CIPHER_SPEC = 20

HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_CERTIFICATE = 11

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xE011: "ECDHE_SM4_CBC_SM3", 0xE051: "ECDHE_SM4_GCM_SM3",
    0xE013: "ECC_SM4_CBC_SM3", 0xE053: "ECC_SM4_GCM_SM3",
    0xE001: "ECC_SM1_SM3", 0xE003: "ECDHE_SM4_CBC_SM3", 0xE005: "ECC_SM4_CBC_SM3",
}

TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
    0x0304: "TLS 1.3", 0x0101: "TLCP (GM/T 0024)",
}
SUPPORTED_VERSION_NAMES = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0",
                           0x0101: "TLCP", 0x0102: "TLCP 1.1"}

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113
LINKTYPE_SLL2 = 276
LINKTYPE_LOOP = 0
LINKTYPE_LOOP_ALT = 108
LINKTYPE_PPP = 9


class PcapError(ValueError):
    pass


@dataclass
class Packet:
    index: int
    timestamp: Optional[datetime]
    linktype: int
    raw: bytes


@dataclass
class EncryptedRecord:
    protocol: str          # TLS / TLCP / ESP
    stream: str
    source: str
    destination: str
    sport: int
    dport: int
    detail: str
    payload: bytes
    record_type: int = 0
    record_version: str = ""
    packet_index: int = 0


@dataclass
class CertificateRecord:
    source: str
    destination: str
    der: bytes
    sha256: str
    subject: str
    issuer: str
    signature_algorithm: str
    error: str = ""


@dataclass
class HandshakeRecord:
    kind: str              # ClientHello / ServerHello / Certificate
    stream: str
    source: str
    destination: str
    version: str
    details: dict = field(default_factory=dict)


@dataclass
class CaptureResult:
    encrypted: list[EncryptedRecord] = field(default_factory=list)
    certificates: list[CertificateRecord] = field(default_factory=list)
    handshakes: list[HandshakeRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def cipher_suites(self) -> list[str]:
        seen: list[str] = []
        for hs in self.handshakes:
            suites = hs.details.get("cipher_suites") or []
            selected = hs.details.get("selected_cipher")
            for item in suites:
                if item not in seen:
                    seen.append(item)
            if selected and selected not in seen:
                seen.append(selected)
        return seen


# ---------------------------------------------------------------- 文件解析
def read_packets(data: bytes) -> tuple[list[Packet], list[str]]:
    if len(data) < 4:
        raise PcapError("文件过小，不是有效的 pcap/pcapng 文件。")
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0x0A0D0D0A:
        return _read_pcapng(data)
    return _read_pcap(data)


def _read_pcap(data: bytes) -> tuple[list[Packet], list[str]]:
    if len(data) < 24:
        raise PcapError("pcap 文件头不完整。")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise PcapError(f"无法识别的 pcap 魔数：{magic.hex()}")
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    packets: list[Packet] = []
    offset = 24
    index = 0
    warnings: list[str] = []
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if offset + incl_len > len(data):
            warnings.append(f"第 {index + 1} 个报文被截断，已停止解析。")
            break
        payload = data[offset:offset + incl_len]
        offset += incl_len
        ts = datetime.fromtimestamp(ts_sec + ts_frac / 1_000_000, tz=timezone.utc)
        packets.append(Packet(index=index, timestamp=ts, linktype=linktype, raw=payload))
        index += 1
    return packets, warnings


def _read_pcapng(data: bytes) -> tuple[list[Packet], list[str]]:
    packets: list[Packet] = []
    warnings: list[str] = []
    offset = 0
    endian = "<"
    linktypes: list[int] = []
    tsresol: list[float] = []
    index = 0
    while offset + 12 <= len(data):
        btype_raw = data[offset:offset + 4]
        if btype_raw == b"\x0a\x0d\x0d\x0a":
            shb_len_raw = data[offset + 4:offset + 8]
            # 字节序由 SHB 中 0x1A2B3C4D 的位置决定
            if data[offset + 8:offset + 12] == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                endian = ">"
            block_len = struct.unpack(endian + "I", shb_len_raw)[0]
            if block_len < 12 or offset + block_len > len(data):
                warnings.append("pcapng 区块长度异常。")
                break
            offset += block_len
            continue
        block_type = struct.unpack(endian + "I", btype_raw)[0]
        block_len = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]
        if block_len < 12 or offset + block_len > len(data):
            warnings.append("pcapng 区块长度异常。")
            break
        body = data[offset + 8:offset + block_len - 4]
        if block_type == 1:  # IDB
            if len(body) >= 8:
                linktypes.append(struct.unpack(endian + "H", body[0:2])[0])
                tsresol.append(_parse_tsresol(body[8:], endian))
        elif block_type == 6:  # EPB
            if len(body) >= 20:
                iface, ts_high, ts_low, caplen, origlen = struct.unpack(endian + "IIIII", body[0:20])
                pkt = body[20:20 + caplen]
                link = linktypes[iface] if iface < len(linktypes) else LINKTYPE_ETHERNET
                res = tsresol[iface] if iface < len(tsresol) else 1e-6
                ts = datetime.fromtimestamp(((ts_high << 32) | ts_low) * res, tz=timezone.utc)
                packets.append(Packet(index=index, timestamp=ts, linktype=link, raw=pkt))
                index += 1
        elif block_type == 3:  # SPB
            if len(body) >= 4:
                origlen = struct.unpack(endian + "I", body[0:4])[0]
                pkt = body[4:4 + origlen]
                link = linktypes[0] if linktypes else LINKTYPE_ETHERNET
                packets.append(Packet(index=index, timestamp=None, linktype=link, raw=pkt))
                index += 1
        elif block_type == 2:  # PB（旧格式）
            if len(body) >= 20:
                iface, drops, ts_high, ts_low, caplen = struct.unpack(endian + "HHIII", body[0:16])
                pkt = body[16:16 + caplen]
                link = linktypes[iface] if iface < len(linktypes) else LINKTYPE_ETHERNET
                ts = datetime.fromtimestamp(((ts_high << 32) | ts_low) * 1e-6, tz=timezone.utc)
                packets.append(Packet(index=index, timestamp=ts, linktype=link, raw=pkt))
                index += 1
        offset += block_len
    return packets, warnings


def _parse_tsresol(options: bytes, endian: str) -> float:
    """解析 IDB 的 if_tsresol 选项（默认 1e-6）。"""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        if code == 0:
            break
        value = options[offset + 4:offset + 4 + length]
        if code == 9 and value:
            raw = value[0]
            if raw & 0x80:
                return 2.0 ** -(raw & 0x7F)
            return 10.0 ** -raw
        offset += 4 + length + ((4 - length % 4) % 4)
    return 1e-6


# ---------------------------------------------------------------- 链路层
def _parse_l2(packet: Packet) -> tuple[Optional[bytes], Optional[int], str]:
    """返回 (IP 负载, EtherType/协议, 错误)。"""
    raw = packet.raw
    lt = packet.linktype
    if lt == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return None, None, "以太网帧过短"
        ethertype = struct.unpack(">H", raw[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(raw) >= offset + 4:
            ethertype = struct.unpack(">H", raw[offset + 2:offset + 4])[0]
            offset += 4
        return raw[offset:], ethertype, ""
    if lt == LINKTYPE_SLL:
        if len(raw) < 16:
            return None, None, "SLL 帧过短"
        protocol = struct.unpack(">H", raw[14:16])[0]
        return raw[16:], protocol, ""
    if lt == LINKTYPE_SLL2:
        if len(raw) < 20:
            return None, None, "SLL2 帧过短"
        protocol = struct.unpack(">H", raw[0:2])[0]
        return raw[20:], protocol, ""
    if lt in (LINKTYPE_RAW, LINKTYPE_PPP):
        if raw and raw[0] >> 4 in (4, 6):
            return raw, struct.unpack(">H", raw[0:2])[0] if len(raw) >= 2 else None, ""
        return None, None, "未知 IP 版本"
    if lt in (LINKTYPE_LOOP, LINKTYPE_LOOP_ALT):
        if len(raw) < 4:
            return None, None, "Loopback 帧过短"
        return raw[4:], 0x0800, ""
    return None, None, f"不支持的链路层类型 {lt}"


def _parse_l3(ip: bytes) -> tuple[Optional[dict], str]:
    if not ip:
        return None, "空 IP 负载"
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            return None, "IPv4 头过短"
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl:
            return None, "IPv4 头长度非法"
        total_len = struct.unpack(">H", ip[2:4])[0]
        proto = ip[9]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        frag_offset = struct.unpack(">H", ip[6:8])[0] & 0x1FFF
        payload = ip[ihl:total_len] if total_len and total_len <= len(ip) else ip[ihl:]
        return {"version": 4, "proto": proto, "src": src, "dst": dst,
                "payload": payload, "frag_offset": frag_offset}, ""
    if version == 6:
        if len(ip) < 40:
            return None, "IPv6 头过短"
        next_header = ip[6]
        payload_len = struct.unpack(">H", ip[4:6])[0]
        src = ":".join(f"{int.from_bytes(ip[i:i + 2], 'big'):x}" for i in range(8, 24, 2))
        dst = ":".join(f"{int.from_bytes(ip[i:i + 2], 'big'):x}" for i in range(24, 40, 2))
        payload = ip[40:40 + payload_len] if payload_len and payload_len <= len(ip) - 40 else ip[40:]
        return {"version": 6, "proto": next_header, "src": src, "dst": dst,
                "payload": payload, "frag_offset": 0}, ""
    return None, f"未知 IP 版本 {version}"


# ---------------------------------------------------------------- TCP 重组
@dataclass
class _Segment:
    seq: int
    data: bytes


def _reassemble_runs(segments: list[_Segment]) -> tuple[list[bytes], bool]:
    """按序号合并 TCP 分段，返回连续数据段列表（遇缺口切分）与是否存在缺口。"""
    if not segments:
        return [], False
    base = min(seg.seq for seg in segments)
    ordered = sorted(segments, key=lambda s: (s.seq - base) & 0xFFFFFFFF)
    mask = 0xFFFFFFFF
    runs: list[bytearray] = []
    cursor = None
    gap = False
    for seg in ordered:
        if cursor is None:
            runs.append(bytearray(seg.data))
            cursor = (seg.seq + len(seg.data)) & mask
            continue
        delta = (seg.seq - cursor) & mask
        if delta == 0:
            runs[-1].extend(seg.data)
        elif delta < 1 << 31:  # 缺口：新连续段
            gap = True
            runs.append(bytearray(seg.data))
        else:  # 重传/重叠：只追加未见过的部分
            start = (cursor - seg.seq) & mask
            if start < len(seg.data):
                runs[-1].extend(seg.data[start:])
        cursor = (seg.seq + len(seg.data)) & mask
    return [bytes(run) for run in runs], gap


# ---------------------------------------------------------------- TLS 解析
def _parse_tls_stream(data: bytes, stream_id: str, src: str, dst: str, sport: int, dport: int,
                      result: CaptureResult) -> None:
    offset = 0
    while offset + 5 <= len(data):
        record_type = data[offset]
        version = struct.unpack(">H", data[offset + 1:offset + 3])[0]
        length = struct.unpack(">H", data[offset + 3:offset + 5])[0]
        if offset + 5 + length > len(data):
            result.warnings.append(f"TLS 记录不完整（流 {stream_id}，偏移 {offset}）。")
            break
        content = data[offset + 5:offset + 5 + length]
        version_name = TLS_VERSION_NAMES.get(version, f"0x{version:04X}")
        protocol = "TLCP" if version in (0x0101, 0x0102) else "TLS"
        if record_type == TLS_APPLICATION_DATA:
            result.encrypted.append(EncryptedRecord(
                protocol=protocol, stream=stream_id, source=src, destination=dst,
                sport=sport, dport=dport,
                detail=f"记录版本 {version_name}，长度 {length} 字节",
                payload=content, record_type=record_type, record_version=version_name,
            ))
        elif record_type == TLS_HANDSHAKE:
            _parse_handshake(content, stream_id, src, dst, version_name, protocol, result)
        offset += 5 + length


def _parse_handshake(data: bytes, stream_id: str, src: str, dst: str, version_name: str,
                     protocol: str, result: CaptureResult) -> None:
    offset = 0
    while offset + 4 <= len(data):
        hs_type = data[offset]
        hs_len = int.from_bytes(data[offset + 1:offset + 4], "big")
        if offset + 4 + hs_len > len(data):
            break
        body = data[offset + 4:offset + 4 + hs_len]
        if hs_type == HANDSHAKE_CLIENT_HELLO:
            details = _parse_client_hello(body)
            details["protocol"] = protocol
            result.handshakes.append(HandshakeRecord(
                kind="ClientHello", stream=stream_id, source=src, destination=dst,
                version=details.get("legacy_version", version_name), details=details,
            ))
        elif hs_type == HANDSHAKE_SERVER_HELLO:
            details = _parse_server_hello(body)
            details["protocol"] = protocol
            result.handshakes.append(HandshakeRecord(
                kind="ServerHello", stream=stream_id, source=src, destination=dst,
                version=details.get("legacy_version", version_name), details=details,
            ))
        elif hs_type == HANDSHAKE_CERTIFICATE:
            _parse_certificate_message(body, src, dst, result)
        offset += 4 + hs_len


def _parse_client_hello(body: bytes) -> dict:
    if len(body) < 35:
        return {}
    version = struct.unpack(">H", body[0:2])[0]
    random = body[2:34].hex()
    pos = 34
    session_len = body[pos]
    pos += 1 + session_len
    details = {
        "legacy_version": TLS_VERSION_NAMES.get(version, f"0x{version:04X}"),
        "random": random,
        "cipher_suites": [],
        "sni": [],
        "supported_versions": [],
        "alpn": [],
    }
    if pos + 2 <= len(body):
        suites_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        suites = []
        for i in range(pos, min(pos + suites_len, len(body)), 2):
            if i + 2 > len(body):
                break
            code = struct.unpack(">H", body[i:i + 2])[0]
            name = CIPHER_SUITES.get(code, f"0x{code:04X}")
            suites.append(f"{name} (0x{code:04X})")
        details["cipher_suites"] = suites
        pos += suites_len
    if pos + 1 <= len(body):
        comp_len = body[pos]
        pos += 1 + comp_len
    if pos + 2 <= len(body):
        ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_len, len(body))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", body[pos:pos + 4])
            pos += 4
            ext = body[pos:pos + ext_len]
            pos += ext_len
            if ext_type == 0x0000:  # server_name
                _parse_sni(ext, details["sni"])
            elif ext_type == 0x002B:  # supported_versions
                if ext_len >= 1:
                    count = ext[0]
                    versions = []
                    for i in range(1, 1 + count * 2, 2):
                        if i + 2 <= len(ext):
                            code = struct.unpack(">H", ext[i:i + 2])[0]
                            versions.append(SUPPORTED_VERSION_NAMES.get(code, f"0x{code:04X}"))
                    details["supported_versions"] = versions
            elif ext_type == 0x0010:  # ALPN
                if ext_len >= 2:
                    list_len = struct.unpack(">H", ext[0:2])[0]
                    p = 2
                    while p + 1 <= min(2 + list_len, len(ext)):
                        item_len = ext[p]
                        p += 1
                        details["alpn"].append(ext[p:p + item_len].decode("latin-1"))
                        p += item_len
    return details


def _parse_sni(ext: bytes, target: list[str]) -> None:
    if len(ext) < 2:
        return
    list_len = struct.unpack(">H", ext[0:2])[0]
    pos = 2
    end = min(2 + list_len, len(ext))
    while pos + 3 <= end:
        name_type = ext[pos]
        name_len = struct.unpack(">H", ext[pos + 1:pos + 3])[0]
        pos += 3
        if name_type == 0:
            target.append(ext[pos:pos + name_len].decode("latin-1", errors="replace"))
        pos += name_len


def _parse_server_hello(body: bytes) -> dict:
    if len(body) < 38:
        return {}
    version = struct.unpack(">H", body[0:2])[0]
    pos = 34
    session_len = body[pos]
    pos += 1 + session_len
    details = {"legacy_version": TLS_VERSION_NAMES.get(version, f"0x{version:04X}"),
               "random": body[2:34].hex(), "selected_cipher": ""}
    if pos + 2 <= len(body):
        code = struct.unpack(">H", body[pos:pos + 2])[0]
        details["selected_cipher"] = f"{CIPHER_SUITES.get(code, f'0x{code:04X}')} (0x{code:04X})"
        pos += 2
    if pos + 1 <= len(body):
        comp_len = body[pos]
        pos += 1 + comp_len
    if pos + 2 <= len(body):
        ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_len, len(body))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", body[pos:pos + 4])
            pos += 4
            ext = body[pos:pos + ext_len]
            pos += ext_len
            if ext_type == 0x002B and ext_len >= 2:  # supported_versions
                code = struct.unpack(">H", ext[0:2])[0]
                details["negotiated_version"] = SUPPORTED_VERSION_NAMES.get(code, f"0x{code:04X}")
    return details


def _parse_certificate_message(body: bytes, src: str, dst: str, result: CaptureResult) -> None:
    if len(body) < 3:
        return
    total = int.from_bytes(body[0:3], "big")
    pos = 3
    end = min(3 + total, len(body))
    while pos + 3 <= end:
        cert_len = int.from_bytes(body[pos:pos + 3], "big")
        pos += 3
        der = body[pos:pos + cert_len]
        pos += cert_len
        if not der:
            continue
        try:
            cert = parse_certificate(der)
            import hashlib

            result.certificates.append(CertificateRecord(
                source=src, destination=dst, der=der, sha256=hashlib.sha256(der).hexdigest().upper(),
                subject=cert.subject.text(), issuer=cert.issuer.text(),
                signature_algorithm=cert.signature_alg_label,
            ))
        except Exception as exc:  # noqa: BLE001
            result.certificates.append(CertificateRecord(
                source=src, destination=dst, der=der, sha256="", subject="", issuer="",
                signature_algorithm="", error=str(exc),
            ))


# ---------------------------------------------------------------- 主分析
def analyze_capture(path: str, *, ip_filter: tuple[str, str] | None = None,
                    include_tls: bool = True, include_esp: bool = True,
                    progress: Callable[[int, str], None] | None = None,
                    cancel=None) -> CaptureResult:
    with open(path, "rb") as fh:
        data = fh.read()
    result = CaptureResult()
    packets, warnings = read_packets(data)
    result.warnings.extend(warnings)
    result.stats["报文总数"] = len(packets)

    src_filter, dst_filter = (ip_filter or ("", ""))
    filter_set = {src_filter, dst_filter} if src_filter and dst_filter else None

    tcp_streams: dict[tuple, list[_Segment]] = {}
    stream_meta: dict[tuple, tuple[str, str, int, int]] = {}
    esp_count = 0
    ike_count = 0

    total = max(1, len(packets))
    for packet in packets:
        if cancel is not None and cancel.is_set():
            result.warnings.append("解析已取消（结果可能不完整）。")
            break
        if progress and packet.index % 200 == 0:
            progress(int(packet.index * 100 / total), f"已解析 {packet.index}/{total} 个报文")
        ip_bytes, _, l2_err = _parse_l2(packet)
        if ip_bytes is None:
            continue
        l3, l3_err = _parse_l3(ip_bytes)
        if l3 is None:
            continue
        src, dst = l3["src"], l3["dst"]
        if filter_set is not None and {src, dst} != filter_set:
            continue
        proto = l3["proto"]
        payload = l3["payload"]
        if proto == 6:  # TCP
            if len(payload) < 20:
                continue
            sport = struct.unpack(">H", payload[0:2])[0]
            dport = struct.unpack(">H", payload[2:4])[0]
            offset = (payload[12] >> 4) * 4
            flags = payload[13]
            seq = struct.unpack(">I", payload[4:8])[0]
            tcp_payload = payload[offset:]
            key = (src, sport, dst, dport)
            stream_meta.setdefault(key, (src, dst, sport, dport))
            if tcp_payload:
                tcp_streams.setdefault(key, []).append(_Segment(seq=seq, data=tcp_payload))
            elif flags & 0x01:  # FIN：结束该流
                pass
        elif proto == 17:  # UDP
            if len(payload) < 8:
                continue
            sport, dport = struct.unpack(">HH", payload[0:4])
            udp_payload = payload[8:]
            if include_tls and (sport in (500, 4500) or dport in (500, 4500)):
                ike_count += 1
                _scan_ike_certificates(udp_payload, src, dst, result)
        elif proto == 50:  # ESP
            if include_esp and len(payload) >= 8:
                esp_count += 1
                spi = struct.unpack(">I", payload[0:4])[0]
                seq = struct.unpack(">I", payload[4:8])[0]
                result.encrypted.append(EncryptedRecord(
                    protocol="ESP", stream=f"{src}->{dst}", source=src, destination=dst,
                    sport=0, dport=0, detail=f"SPI {spi:#010x} · 序列号 {seq}",
                    payload=payload[8:], record_type=50,
                ))

    if include_tls:
        for key, segments in tcp_streams.items():
            runs, gap = _reassemble_runs(segments)
            if gap:
                result.warnings.append(
                    f"流 {key[0]}:{key[1]} -> {key[2]}:{key[3]} 存在未捕获的 TCP 分段，"
                    "缺口处已切分为独立连续段解析。"
                )
            src, dst, sport, dport = stream_meta[key]
            stream_id = f"{src}:{sport} -> {dst}:{dport}"
            for run in runs:
                if run:
                    _parse_tls_stream(run, stream_id, src, dst, sport, dport, result)

    result.stats["TCP 流数量"] = len(tcp_streams)
    result.stats["加密记录数"] = len(result.encrypted)
    result.stats["证书数"] = len(result.certificates)
    result.stats["IKE 报文数"] = ike_count
    result.stats["ESP 报文数"] = esp_count
    return result


def _scan_ike_certificates(payload: bytes, src: str, dst: str, result: CaptureResult) -> None:
    """在 UDP 载荷中按 DER TLV 边界扫描证书（IKE CERT 载荷）。"""
    import hashlib

    from .der import DerError, parse_tlv

    offset = 0
    while offset < len(payload) - 4:
        if payload[offset] != 0x30:
            offset += 1
            continue
        try:
            tlv = parse_tlv(payload, offset)
        except DerError:
            offset += 1
            continue
        try:
            cert = parse_certificate(tlv.raw)
            result.certificates.append(CertificateRecord(
                source=src, destination=dst, der=tlv.raw,
                sha256=hashlib.sha256(tlv.raw).hexdigest().upper(),
                subject=cert.subject.text(), issuer=cert.issuer.text(),
                signature_algorithm=cert.signature_alg_label,
            ))
            offset = tlv.end
        except Exception:  # noqa: BLE001
            offset += 1
