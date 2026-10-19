"""矢量图标：全部用 QPainter 绘制，避免依赖系统字体图标与 emoji（离屏渲染也稳定）。"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap,
)


def _pen(p: QPainter, color: QColor, width: float) -> None:
    pen = QPen(color, width)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)


def make_icon(name: str, color: str = "#8FA3BD", size: int = 18, stroke: float = 1.5) -> QIcon:
    """绘制并返回图标。坐标系按 size 归一化（0..size）。"""
    scale = 2  # 高 DPI
    pm = QPixmap(size * scale, size * scale)
    pm.setDevicePixelRatio(float(scale))
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    c = QColor(color)
    s = float(size)
    w = max(1.0, stroke)
    _pen(p, c, w)
    p.setBrush(Qt.NoBrush)

    if name == "home":
        path = QPainterPath()
        path.moveTo(s * 0.16, s * 0.46)
        path.lineTo(s * 0.5, s * 0.16)
        path.lineTo(s * 0.84, s * 0.46)
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.28, s * 0.40), QPointF(s * 0.28, s * 0.84))
        p.drawLine(QPointF(s * 0.28, s * 0.84), QPointF(s * 0.72, s * 0.84))
        p.drawLine(QPointF(s * 0.72, s * 0.84), QPointF(s * 0.72, s * 0.40))

    elif name == "tools":
        for i, (y, knob) in enumerate(((0.28, 0.66), (0.5, 0.34), (0.72, 0.58))):
            p.drawLine(QPointF(s * 0.16, s * y), QPointF(s * 0.84, s * y))
            p.setBrush(c)
            p.drawEllipse(QPointF(s * knob, s * y), s * 0.09, s * 0.09)
            p.setBrush(Qt.NoBrush)

    elif name == "lock":
        body = QRectF(s * 0.24, s * 0.44, s * 0.52, s * 0.40)
        p.drawRoundedRect(body, s * 0.08, s * 0.08)
        path = QPainterPath()
        path.moveTo(s * 0.34, s * 0.46)
        path.arcTo(QRectF(s * 0.30, s * 0.14, s * 0.40, s * 0.52), 0, 180)
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.5, s * 0.56), QPointF(s * 0.5, s * 0.70))

    elif name == "network":
        pts = [(0.5, 0.20), (0.22, 0.76), (0.78, 0.76)]
        for a, b in ((pts[0], pts[1]), (pts[0], pts[2]), (pts[1], pts[2])):
            p.drawLine(QPointF(s * a[0], s * a[1]), QPointF(s * b[0], s * b[1]))
        p.setBrush(c)
        for x, y in pts:
            p.drawEllipse(QPointF(s * x, s * y), s * 0.10, s * 0.10)
        p.setBrush(Qt.NoBrush)

    elif name == "cert":
        path = QPainterPath()
        path.moveTo(s * 0.24, s * 0.14)
        path.lineTo(s * 0.62, s * 0.14)
        path.lineTo(s * 0.78, s * 0.30)
        path.lineTo(s * 0.78, s * 0.86)
        path.lineTo(s * 0.24, s * 0.86)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.60, s * 0.15), QPointF(s * 0.60, s * 0.31))
        p.drawLine(QPointF(s * 0.60, s * 0.31), QPointF(s * 0.76, s * 0.31))
        p.drawLine(QPointF(s * 0.34, s * 0.52), QPointF(s * 0.66, s * 0.52))
        p.drawLine(QPointF(s * 0.34, s * 0.64), QPointF(s * 0.58, s * 0.64))
        p.drawEllipse(QPointF(s * 0.40, s * 0.76), s * 0.05, s * 0.05)

    elif name == "dice":
        p.drawRoundedRect(QRectF(s * 0.2, s * 0.2, s * 0.6, s * 0.6), s * 0.12, s * 0.12)
        p.setBrush(c)
        for x, y in ((0.36, 0.36), (0.64, 0.36), (0.5, 0.5), (0.36, 0.64), (0.64, 0.64)):
            p.drawEllipse(QPointF(s * x, s * y), s * 0.055, s * 0.055)
        p.setBrush(Qt.NoBrush)

    elif name == "seal":
        p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.32, s * 0.32)
        path = QPainterPath()
        cx, cy, r = s * 0.5, s * 0.52, s * 0.19
        for i in range(5):
            ang = -1.5707963 + i * 1.256637
            x, y = cx + r * __import__("math").cos(ang), cy + r * __import__("math").sin(ang)
            path.moveTo(x, y) if i == 0 else path.lineTo(x, y)
        path.closeSubpath()
        p.setBrush(c)
        p.drawPath(path)
        p.setBrush(Qt.NoBrush)

    elif name == "sun":
        p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.16, s * 0.16)
        for i in range(8):
            import math
            ang = i * math.pi / 4
            p.drawLine(
                QPointF(s * 0.5 + s * 0.26 * math.cos(ang), s * 0.5 + s * 0.26 * math.sin(ang)),
                QPointF(s * 0.5 + s * 0.38 * math.cos(ang), s * 0.5 + s * 0.38 * math.sin(ang)),
            )

    elif name == "moon":
        path = QPainterPath()
        path.addEllipse(QPointF(s * 0.52, s * 0.5), s * 0.30, s * 0.30)
        cut = QPainterPath()
        cut.addEllipse(QPointF(s * 0.66, s * 0.42), s * 0.26, s * 0.26)
        p.drawPath(path.subtracted(cut))

    elif name == "gear":
        # 齿轮：外圈 + 8 个方形齿 + 中心孔（与太阳图标明显区分）
        from PySide6.QtGui import QBrush
        center = QPointF(s * 0.5, s * 0.5)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(c))
        for i in range(8):
            p.save()
            p.translate(center)
            p.rotate(i * 45.0)
            p.drawRoundedRect(QRectF(-s * 0.06, -s * 0.47, s * 0.12, s * 0.15), s * 0.025, s * 0.025)
            p.restore()
        p.setBrush(Qt.NoBrush)
        _pen(p, c, w * 1.15)
        p.drawEllipse(center, s * 0.30, s * 0.30)
        p.drawEllipse(center, s * 0.11, s * 0.11)

    elif name == "search":
        p.drawEllipse(QPointF(s * 0.44, s * 0.44), s * 0.24, s * 0.24)
        p.drawLine(QPointF(s * 0.62, s * 0.62), QPointF(s * 0.84, s * 0.84))

    elif name == "copy":
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.30, s * 0.44, s * 0.54), s * 0.06, s * 0.06)
        p.drawRoundedRect(QRectF(s * 0.38, s * 0.16, s * 0.44, s * 0.54), s * 0.06, s * 0.06)

    elif name == "export":
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.56, s * 0.64, s * 0.28), s * 0.05, s * 0.05)
        p.drawLine(QPointF(s * 0.5, s * 0.16), QPointF(s * 0.5, s * 0.52))
        p.drawLine(QPointF(s * 0.34, s * 0.34), QPointF(s * 0.5, s * 0.16))
        p.drawLine(QPointF(s * 0.66, s * 0.34), QPointF(s * 0.5, s * 0.16))

    elif name == "refresh":
        path = QPainterPath()
        path.arcMoveTo(QRectF(s * 0.2, s * 0.2, s * 0.6, s * 0.6), 30)
        path.arcTo(QRectF(s * 0.2, s * 0.2, s * 0.6, s * 0.6), 30, 300)
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.76, s * 0.22), QPointF(s * 0.76, s * 0.44))
        p.drawLine(QPointF(s * 0.76, s * 0.44), QPointF(s * 0.54, s * 0.44))

    elif name == "check":
        p.drawLine(QPointF(s * 0.18, s * 0.52), QPointF(s * 0.42, s * 0.76))
        p.drawLine(QPointF(s * 0.42, s * 0.76), QPointF(s * 0.84, s * 0.26))

    elif name == "cross":
        p.drawLine(QPointF(s * 0.26, s * 0.26), QPointF(s * 0.74, s * 0.74))
        p.drawLine(QPointF(s * 0.74, s * 0.26), QPointF(s * 0.26, s * 0.74))

    elif name == "play":
        path = QPainterPath()
        path.moveTo(s * 0.30, s * 0.20)
        path.lineTo(s * 0.30, s * 0.80)
        path.lineTo(s * 0.80, s * 0.50)
        path.closeSubpath()
        p.setBrush(c)
        p.drawPath(path)
        p.setBrush(Qt.NoBrush)

    elif name == "plus":
        p.drawLine(QPointF(s * 0.5, s * 0.24), QPointF(s * 0.5, s * 0.76))
        p.drawLine(QPointF(s * 0.24, s * 0.5), QPointF(s * 0.76, s * 0.5))

    elif name == "trash":
        p.drawLine(QPointF(s * 0.22, s * 0.30), QPointF(s * 0.78, s * 0.30))
        p.drawRect(QRectF(s * 0.30, s * 0.30, s * 0.40, s * 0.50))
        p.drawLine(QPointF(s * 0.40, s * 0.30), QPointF(s * 0.40, s * 0.22))
        p.drawLine(QPointF(s * 0.40, s * 0.22), QPointF(s * 0.60, s * 0.22))
        p.drawLine(QPointF(s * 0.60, s * 0.22), QPointF(s * 0.60, s * 0.30))
        p.drawLine(QPointF(s * 0.42, s * 0.42), QPointF(s * 0.42, s * 0.70))
        p.drawLine(QPointF(s * 0.58, s * 0.42), QPointF(s * 0.58, s * 0.70))

    elif name == "eye":
        path = QPainterPath()
        path.moveTo(s * 0.14, s * 0.5)
        path.quadTo(s * 0.5, s * 0.18, s * 0.86, s * 0.5)
        path.quadTo(s * 0.5, s * 0.82, s * 0.14, s * 0.5)
        p.drawPath(path)
        p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.11, s * 0.11)

    elif name == "info":
        p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.32, s * 0.32)
        p.drawLine(QPointF(s * 0.5, s * 0.46), QPointF(s * 0.5, s * 0.70))
        p.setBrush(c)
        p.drawEllipse(QPointF(s * 0.5, s * 0.34), s * 0.045, s * 0.045)
        p.setBrush(Qt.NoBrush)

    else:  # fallback: dot
        p.setBrush(c)
        p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.16, s * 0.16)

    p.end()
    return QIcon(pm)
