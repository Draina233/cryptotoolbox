"""界面层共享状态：当前主题调色板与字体缩放。

页面渲染结果颜色时从这里取色，主题切换后由 MainWindow 通知各页面重新渲染。
"""
from __future__ import annotations

from ..theme import DEFAULT_ACCENT, PALETTES, DARK, LIGHT, palette_for

_current_palette = palette_for("light", DEFAULT_ACCENT)
_current_theme = "light"
_font_scale = 1.0
_accent = DEFAULT_ACCENT

STATUS_TEXT = {
    "pass": "通过",
    "fail": "未通过",
    "unknown": "未知",
    "skip": "不适用",
}


def set_theme(name: str, font_scale: float | None = None, accent: str | None = None) -> None:
    global _current_palette, _current_theme, _font_scale, _accent
    _current_theme = name if name in PALETTES else "light"
    if accent is not None:
        _accent = accent.strip()
    from ..theme import palette_for

    _current_palette = palette_for(_current_theme, _accent)
    if font_scale is not None:
        _font_scale = max(0.85, min(1.3, font_scale))


def accent() -> str:
    return _accent


def theme_name() -> str:
    return _current_theme


def font_scale() -> float:
    return _font_scale


def palette() -> dict:
    return _current_palette


def status_color(status: str) -> str:
    p = _current_palette
    return {
        "pass": p["success"],
        "fail": p["danger"],
        "unknown": p["unknown"],
        "skip": p["text_tertiary"],
    }.get(status, p["text_secondary"])


def status_bg(status: str) -> str:
    p = _current_palette
    return {
        "pass": p["success_soft"],
        "fail": p["danger_soft"],
        "unknown": p["unknown_soft"],
        "skip": p["surface_alt"],
    }.get(status, p["surface_alt"])


def status_text(status: str) -> str:
    return STATUS_TEXT.get(status, status)
