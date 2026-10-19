"""GitHub Releases 更新检查（不阻塞启动，离线时静默失败）。"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Optional

API_URL = "https://api.github.com/repos/Draina233/cryptotoolbox/releases/latest"
API_LIST_URL = "https://api.github.com/repos/Draina233/cryptotoolbox/releases?per_page=10"
ATOM_URL = "https://github.com/Draina233/cryptotoolbox/releases.atom"
RELEASES_URL = "https://github.com/Draina233/cryptotoolbox/releases"


@dataclass
class ReleaseInfo:
    tag: str
    version: str
    name: str
    html_url: str
    body: str = ""
    published_at: str = ""
    prerelease: bool = False

    @property
    def notes(self) -> str:
        text = (self.body or "").strip()
        return text


def parse_version(text: str) -> tuple[int, ...]:
    numbers = [int(part) for part in re.findall(r"\d+", text or "")[:4]]
    return tuple(numbers) if numbers else (0,)


def is_newer(remote: str, current: str) -> bool:
    """比较版本号，支持 v2.0.1、2.0.1-beta 等形式（只比较数字段）。"""
    a = list(parse_version(remote))
    b = list(parse_version(current))
    size = max(len(a), len(b))
    a += [0] * (size - len(a))
    b += [0] * (size - len(b))
    return a > b


def parse_release(payload: dict[str, Any]) -> Optional[ReleaseInfo]:
    tag = str(payload.get("tag_name") or "").strip()
    url = str(payload.get("html_url") or "").strip()
    if not tag or not url.startswith("https://github.com/"):
        return None
    return ReleaseInfo(
        tag=tag,
        version=tag.lstrip("vV"),
        name=str(payload.get("name") or tag),
        html_url=url,
        body=str(payload.get("body") or ""),
        published_at=str(payload.get("published_at") or ""),
        prerelease=bool(payload.get("prerelease")),
    )


def parse_atom(xml_bytes: bytes) -> Optional[ReleaseInfo]:
    """解析 GitHub Releases Atom（不消耗 API 配额，作为 API 限流/预发布时的兜底）。"""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    ns = {"a": "http://www.w3.org/2005/Atom"}
    candidates: list[ReleaseInfo] = []
    for entry in root.findall("a:entry", ns):
        title = (entry.findtext("a:title", default="", namespaces=ns) or "").strip()
        link = ""
        for link_node in entry.findall("a:link", ns):
            href = link_node.get("href") or ""
            if "/releases/tag/" in href:
                link = href
                break
        if not link:
            continue
        updated = (entry.findtext("a:updated", default="", namespaces=ns) or "").strip()
        content = entry.findtext("a:content", default="", namespaces=ns) or ""
        body = re.sub(r"<[^>]+>", "", content)
        body = re.sub(r"&nbsp;", " ", body).strip()
        tag = link.rsplit("/", 1)[-1]
        candidates.append(ReleaseInfo(tag=tag, version=tag.lstrip("vV"), name=title or tag,
                                      html_url=link, body=body[:4000], published_at=updated))
    if not candidates:
        return None
    return max(candidates, key=lambda info: parse_version(info.version))


def pick_latest(payload: Any) -> Optional[ReleaseInfo]:
    """从 releases 列表中选出版本号最大的非草稿发布（含预发布，供内测更新）。"""
    if not isinstance(payload, list):
        return None
    candidates: list[ReleaseInfo] = []
    for item in payload:
        if not isinstance(item, dict) or item.get("draft"):
            continue
        info = parse_release(item)
        if info is not None:
            candidates.append(info)
    if not candidates:
        return None
    return max(candidates, key=lambda info: parse_version(info.version))


class UpdateChecker:
    """基于 QtNetwork 的异步检查器；调用 check() 后通过回调返回 ReleaseInfo 或 None。"""

    def __init__(self, callback=None, parent=None):
        from PySide6.QtCore import QObject, QUrl, Signal
        from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest

        class _Signal(QObject):
            finished = Signal(object)

        self._signal = _Signal(parent)
        self._signal.finished.connect(callback)
        # 支持通过环境变量使用本地代理（例如 Clash: http://127.0.0.1:7897）
        proxy_url = (
            os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        )
        if proxy_url:
            try:
                from PySide6.QtNetwork import QNetworkProxy

                parsed = urllib.parse.urlparse(proxy_url)
                if parsed.hostname:
                    proxy = QNetworkProxy(QNetworkProxy.ProxyType.HttpProxy, parsed.hostname, parsed.port or 8080)
                    if parsed.username:
                        proxy.setUser(parsed.username)
                    if parsed.password:
                        proxy.setPassword(parsed.password)
                    QNetworkProxy.setApplicationProxy(proxy)
            except Exception:  # noqa: BLE001
                pass
        self._manager = QNetworkAccessManager(parent)
        self._manager.finished.connect(self._on_reply)
        self._stage = "latest"
        self.error = ""

    @staticmethod
    def _request(manager, url: str):
        from PySide6.QtCore import QUrl
        from PySide6.QtNetwork import QNetworkRequest

        request = QNetworkRequest(QUrl(url))
        request.setHeader(QNetworkRequest.KnownHeaders.UserAgentHeader, "cryptotoolbox-updater")
        request.setRawHeader(b"Accept", b"application/vnd.github+json")
        request.setTransferTimeout(8000)
        request.setAttribute(
            QNetworkRequest.Attribute.RedirectPolicyAttribute,
            QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy,
        )
        return manager.get(request)

    def check(self) -> None:
        self._stage = "latest"
        self.error = ""
        self._request(self._manager, API_URL)

    def _advance(self) -> bool:
        """当前请求失败时切换到下一数据源；返回是否已发起新请求。"""
        if self._stage == "latest":
            self._stage = "list"
            self._request(self._manager, API_LIST_URL)
            return True
        if self._stage == "list":
            self._stage = "atom"
            self._request(self._manager, ATOM_URL)
            return True
        return False

    def _on_reply(self, reply) -> None:
        from PySide6.QtNetwork import QNetworkRequest

        info = None
        status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        error_code = reply.error()
        error_text = reply.errorString()
        try:
            raw = bytes(reply.readAll())
        finally:
            reply.deleteLater()
        if status == 200:
            if self._stage == "atom":
                info = parse_atom(raw)
            else:
                try:
                    payload = json.loads(raw.decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    payload = None
                if self._stage == "latest" and isinstance(payload, dict):
                    info = parse_release(payload)
                elif self._stage == "list":
                    info = pick_latest(payload)
        if info is None and status in (401, 403, 429) and self._stage != "atom":
            # API 限流/鉴权问题：直接走不消耗 API 配额的 Atom 发布源
            self._stage = "atom"
            self._request(self._manager, ATOM_URL)
            return
        if info is None and self._advance():
            return
        if info is None:
            from PySide6.QtNetwork import QNetworkReply

            if error_code != QNetworkReply.NetworkError.NoError:
                self.error = error_text or "网络请求失败"
            elif status:
                self.error = f"GitHub 返回 HTTP {status}"
            else:
                self.error = "未获取到发布信息"
        else:
            self.error = ""
        self._signal.finished.emit(info)
