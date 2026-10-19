"""GitHub Releases 更新检查（不阻塞启动，离线时静默失败）。"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional

API_URL = "https://api.github.com/repos/Draina233/cryptotoolbox/releases/latest"
RELEASES_URL = "https://github.com/Draina233/cryptotoolbox/releases"


@dataclass
class ReleaseInfo:
    tag: str
    version: str
    name: str
    html_url: str
    body: str = ""
    published_at: str = ""

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
    )


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
        self._request = QNetworkRequest(QUrl(API_URL))
        self._request.setHeader(QNetworkRequest.KnownHeaders.UserAgentHeader, "cryptotoolbox-updater")
        self._request.setRawHeader(b"Accept", b"application/vnd.github+json")
        self._request.setTransferTimeout(8000)
        self._request.setAttribute(
            QNetworkRequest.Attribute.RedirectPolicyAttribute,
            QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy,
        )
        self._manager.finished.connect(self._on_reply)

    def check(self) -> None:
        self._manager.get(self._request)

    def _on_reply(self, reply) -> None:
        from PySide6.QtNetwork import QNetworkRequest

        info = None
        try:
            status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
            if status == 200:
                payload = json.loads(bytes(reply.readAll()).decode("utf-8", "replace"))
                if isinstance(payload, dict):
                    info = parse_release(payload)
        except Exception:  # noqa: BLE001 - 更新检查失败不影响主程序
            info = None
        finally:
            reply.deleteLater()
        self._signal.finished.emit(info)
