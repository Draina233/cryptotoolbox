"""合成 PCAP/PCAPNG 测试样本的辅助模块（仅测试使用）。"""
from __future__ import annotations

import struct

from cryptotoolbox.core.keys import parse_certificates_text


def _ip4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0,
                         bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split(".")))
    return header + payload


def _tcp(sport: int, dport: int, seq: int, payload: bytes, flags: int = 0x18) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return bytes.fromhex("020000000002" "020000000001") + struct.pack(">H", ethertype) + payload


def tls_record(content_type: int, payload: bytes, version: int = 0x0303) -> bytes:
    return bytes([content_type]) + struct.pack(">HH", version, len(payload)) + payload


def handshake(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + len(body).to_bytes(3, "big") + body


def client_hello_body(sni: str = "leaf.example.com") -> bytes:
    suites = [0x1301, 0x1302, 0xC02F, 0xE051, 0xE011]
    ext = b""
    # SNI
    name = sni.encode()
    server_name = struct.pack(">H", len(name) + 3) + b"\x00" + struct.pack(">H", len(name)) + name
    ext += struct.pack(">HH", 0x0000, len(server_name)) + server_name
    # supported_versions
    versions = bytes([4]) + struct.pack(">HH", 0x0304, 0x0303)
    ext += struct.pack(">HH", 0x002B, len(versions)) + versions
    body = struct.pack(">H", 0x0303) + bytes(range(32)) + b"\x00"
    body += struct.pack(">H", len(suites) * 2) + b"".join(struct.pack(">H", s) for s in suites)
    body += b"\x01\x00"
    body += struct.pack(">H", len(ext)) + ext
    return body


def server_hello_body(cipher: int = 0xC02F) -> bytes:
    body = struct.pack(">H", 0x0303) + bytes(range(32, 64)) + b"\x00"
    body += struct.pack(">H", cipher) + b"\x00"
    return body


def certificate_message(der: bytes) -> bytes:
    entry = len(der).to_bytes(3, "big") + der
    return handshake(11, len(entry).to_bytes(3, "big") + entry)


def make_tls_flow() -> list[bytes]:
    """返回若干以太网帧：ClientHello+app_data(同段两记录)、ServerHello、Certificate、ESP、IKE。"""
    cert_pem = None
    frames = []
    ch = tls_record(22, handshake(1, client_hello_body()))
    app1 = tls_record(23, b"ENCRYPTED-RECORD-ONE")
    app2 = tls_record(23, b"ENCRYPTED-RECORD-TWO")
    tcp_payload = ch + app1 + app2
    frames.append(_eth(_ip4(6, "10.0.0.1", "10.0.0.2", _tcp(50000, 443, 1000, tcp_payload))))
    sh = tls_record(22, handshake(2, server_hello_body()))
    frames.append(_eth(_ip4(6, "10.0.0.2", "10.0.0.1", _tcp(443, 50000, 2000, sh))))
    return frames


def make_certificate_flow(der: bytes) -> bytes:
    msg = certificate_message(der)
    tcp = _tcp(8443, 50001, 0, tls_record(22, msg))
    return _eth(_ip4(6, "10.0.0.2", "10.0.0.1", tcp))


def make_esp_packet() -> bytes:
    payload = struct.pack(">II", 0x12345678, 1) + b"ESP-ENCRYPTED-PAYLOAD"
    return _eth(_ip4(50, "10.0.0.3", "10.0.0.4", payload))


def make_ike_packet(der: bytes) -> bytes:
    udp = struct.pack(">HHHH", 500, 500, 8 + len(der), 0) + der
    return _eth(_ip4(17, "10.0.0.5", "10.0.0.6", udp))


def write_pcap(path: str, frames: list[bytes]) -> None:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, frame in enumerate(frames):
        records.append(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)) + frame)
    with open(path, "wb") as fh:
        fh.write(header + b"".join(records))


def write_pcapng(path: str, frames: list[bytes]) -> None:
    def block(block_type: int, body: bytes) -> bytes:
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = block(0x0A0D0D0A, shb_body)
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb = block(1, idb_body)
    blocks = [shb, idb]
    for index, frame in enumerate(frames):
        ts = 1_700_000_000 + index
        epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame))
        pad = (4 - len(frame) % 4) % 4
        epb_body += frame + b"\x00" * pad
        blocks.append(block(6, epb_body))
    with open(path, "wb") as fh:
        fh.write(b"".join(blocks))


def load_cert_der(fixtures_dir, name: str) -> bytes:
    from pathlib import Path

    text = (Path(fixtures_dir) / name).read_text(encoding="utf-8")
    entries = parse_certificates_text(text, "PEM/DER")
    for der, cert, err in entries:
        if cert is not None:
            return der
    raise AssertionError(f"无法加载证书 {name}")


