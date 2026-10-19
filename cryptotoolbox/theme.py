"""主题系统：调色板 + QSS 生成。

设计原则：
- 侧边栏在明暗主题下都保持深色（品牌识别），内容区随主题切换
- 所有组件颜色、圆角、间距集中定义，避免各页面硬编码样式
- 字体：中文使用 Microsoft YaHei UI，等宽结果区使用 Cascadia Mono / Consolas
"""
from __future__ import annotations

from string import Template

FONT_FAMILY = "Microsoft YaHei UI"
FONT_MONO = "Cascadia Mono, Consolas, Microsoft YaHei UI"

DEFAULT_ACCENT = "#5500FF"

LIGHT = {
    "name": "light",
    "app_bg": "#EEF2F8",
    "surface": "#FFFFFF",
    "surface_alt": "#F7FAFD",
    "surface_hover": "#F0F5FC",
    "border": "#DFE7F1",
    "border_strong": "#C9D6E6",
    "text": "#14283F",
    "text_secondary": "#5A6B80",
    "text_tertiary": "#8A98AB",
    "primary": "#1F6FE0",
    "primary_hover": "#185FC4",
    "primary_pressed": "#17559F",
    "primary_soft": "#E8F1FE",
    "primary_text": "#FFFFFF",
    "success": "#15803D",
    "success_soft": "#E8F6ED",
    "danger": "#B91C1C",
    "danger_soft": "#FDEDED",
    "warn": "#B45309",
    "warn_soft": "#FEF4E6",
    "unknown": "#64748B",
    "unknown_soft": "#EEF2F7",
    "sidebar_bg": "#101C2C",
    "sidebar_bg_alt": "#16263B",
    "sidebar_text": "#B7C5D8",
    "sidebar_text_active": "#FFFFFF",
    "sidebar_accent": "#2F7BEA",
    "sidebar_border": "#1E3049",
    "selection": "#DCEBFF",
    "table_header": "#F2F6FB",
    "table_alt": "#F8FAFD",
    "scrollbar": "#C3D0E0",
    "scrollbar_hover": "#9FB2C8",
    "tooltip_bg": "#16283F",
    "tooltip_text": "#FFFFFF",
}

DARK = {
    "name": "dark",
    "app_bg": "#0E1520",
    "surface": "#151F2D",
    "surface_alt": "#1A2636",
    "surface_hover": "#20304A",
    "border": "#26374D",
    "border_strong": "#344A66",
    "text": "#E6EEF8",
    "text_secondary": "#9DB0C6",
    "text_tertiary": "#6F849D",
    "primary": "#5B9BF5",
    "primary_hover": "#74ABF8",
    "primary_pressed": "#4A87DF",
    "primary_soft": "#1B2F4C",
    "primary_text": "#0B1624",
    "success": "#4ADE80",
    "success_soft": "#123521",
    "danger": "#F87171",
    "danger_soft": "#3A1818",
    "warn": "#FBBF24",
    "warn_soft": "#3A2B10",
    "unknown": "#94A3B8",
    "unknown_soft": "#22303F",
    "sidebar_bg": "#0A121D",
    "sidebar_bg_alt": "#101B2A",
    "sidebar_text": "#AFC0D6",
    "sidebar_text_active": "#FFFFFF",
    "sidebar_accent": "#3D8BF0",
    "sidebar_border": "#1A2A40",
    "selection": "#1B3353",
    "table_header": "#1C2A3C",
    "table_alt": "#182433",
    "scrollbar": "#33465E",
    "scrollbar_hover": "#47607E",
    "tooltip_bg": "#E6EEF8",
    "tooltip_text": "#101C2C",
}

PALETTES = {"light": LIGHT, "dark": DARK}


def palette(name: str) -> dict:
    return DARK if name == "dark" else LIGHT


def qss(p: dict, font_scale: float = 1.0) -> str:
    """根据调色板生成全局 QSS。"""
    base = max(11, round(13 * font_scale))

    t = Template(
        """
* { outline: none; }
QMainWindow, QDialog { background: $APP_BG; }
QWidget { color: $TEXT; font-family: "$FONT"; font-size: ${BASE}px; }
QLabel { background: transparent; color: $TEXT; }
QLabel#pageTitle { font-size: ${TITLE}px; font-weight: 700; color: $TEXT; background: transparent; }
QLabel#pageSubtitle { color: $TEXT_SECONDARY; font-size: ${BASE}px; background: transparent; }
QLabel#sectionTitle { font-weight: 700; color: $TEXT; font-size: ${BASE}px; background: transparent; }
QLabel#hintText { color: $TEXT_TERTIARY; font-size: ${SMALL}px; background: transparent; }
QLabel#fieldLabel { color: $TEXT_SECONDARY; font-size: ${BASE}px; background: transparent; }
QLabel#brandTitle { color: $SIDEBAR_TEXT_ACTIVE; font-size: ${BRAND}px; font-weight: 700; background: transparent; }
QLabel#brandSub { color: $SIDEBAR_TEXT; font-size: ${SMALL}px; letter-spacing: 1px; background: transparent; }
QLabel#statusText { color: $TEXT_SECONDARY; background: transparent; }
QLabel#crumb { color: $TEXT_SECONDARY; background: transparent; }

QFrame#card { background: $SURFACE; border: 1px solid $BORDER; border-radius: 10px; }
QFrame#heroCard { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 $PRIMARY, stop:1 $PRIMARY_HOVER); border-radius: 12px; }
QFrame#cardTitle { background: transparent; border: none; }
QFrame#sidebar { background: $SIDEBAR_BG; }
QFrame#sidebarHeader { background: $SIDEBAR_BG; border-bottom: 1px solid $SIDEBAR_BORDER; }
QFrame#topbar { background: $SURFACE; border-bottom: 1px solid $BORDER; }
QFrame#statusbar { background: $SURFACE_ALT; border-top: 1px solid $BORDER; }
QFrame#dropArea { background: $SURFACE_ALT; border: 2px dashed $BORDER_STRONG; border-radius: 10px; }
QFrame#dropArea:hover { border-color: $PRIMARY; background: $PRIMARY_SOFT; }

QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background: $SURFACE; color: $TEXT; border: 1px solid $BORDER_STRONG;
    border-radius: 7px; padding: 6px 8px; selection-background-color: $SELECTION;
    selection-color: $TEXT;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus { border: 1px solid $PRIMARY; }
QLineEdit:disabled, QPlainTextEdit:disabled, QTextEdit:disabled, QComboBox:disabled {
    background: $SURFACE_ALT; color: $TEXT_TERTIARY;
}
QPlainTextEdit#mono, QTextEdit#mono { font-family: "${MONO}"; font-size: ${BASE}px; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: $SURFACE; color: $TEXT; border: 1px solid $BORDER_STRONG;
    selection-background-color: $PRIMARY_SOFT; selection-color: $TEXT; padding: 4px;
}
QSpinBox::up-button, QSpinBox::down-button { width: 16px; }

QPushButton {
    background: $PRIMARY; color: $PRIMARY_TEXT; border: none; border-radius: 7px;
    padding: 7px 16px; font-weight: 600;
}
QPushButton:hover { background: $PRIMARY_HOVER; }
QPushButton:pressed { background: $PRIMARY_PRESSED; }
QPushButton:disabled { background: $BORDER_STRONG; color: $TEXT_TERTIARY; }
QPushButton#secondary, QPushButton:flat {
    background: transparent; color: $TEXT; border: 1px solid $BORDER_STRONG;
}
QPushButton#secondary:hover { background: $SURFACE_HOVER; border-color: $PRIMARY; }
QPushButton#danger { background: $DANGER; color: #FFFFFF; }
QPushButton#danger:hover { background: #A11818; }
QPushButton#linkBtn { background: transparent; color: $PRIMARY; border: none; padding: 2px 4px; }
QPushButton#linkBtn:hover { text-decoration: underline; }
QToolButton { background: transparent; border: none; border-radius: 6px; padding: 5px; }
QToolButton:hover { background: $SURFACE_HOVER; }
QToolButton:checked { background: $PRIMARY_SOFT; }

QCheckBox, QRadioButton { spacing: 7px; background: transparent; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; }
QCheckBox::indicator { border: 1px solid $BORDER_STRONG; border-radius: 4px; background: $SURFACE; }
QCheckBox::indicator:checked { background: $PRIMARY; border-color: $PRIMARY; }
QRadioButton::indicator { border: 1px solid $BORDER_STRONG; border-radius: 8px; background: $SURFACE; }
QRadioButton::indicator:checked { background: $PRIMARY; border: 4px solid $SURFACE; }

QTableWidget, QTableView, QTreeWidget, QTreeView, QListWidget {
    background: $SURFACE; color: $TEXT; border: 1px solid $BORDER;
    border-radius: 8px; gridline-color: $BORDER;
    alternate-background-color: $TABLE_ALT;
    selection-background-color: $PRIMARY_SOFT; selection-color: $TEXT;
}
QHeaderView::section {
    background: $TABLE_HEADER; color: $TEXT_SECONDARY; border: none;
    border-bottom: 1px solid $BORDER; padding: 7px 8px; font-weight: 600;
}
QTableWidget::item { padding: 4px 6px; }

QTreeWidget#navTree { background: $SIDEBAR_BG; border: none; border-radius: 0; show-decoration-selected: 0; }
QTreeWidget#navTree::item {
    color: $SIDEBAR_TEXT; padding: 7px 10px; border-radius: 6px; margin: 1px 8px;
}
QTreeWidget#navTree::item:hover { background: $SIDEBAR_BG_ALT; color: $SIDEBAR_TEXT_ACTIVE; }
QTreeWidget#navTree::item:selected { background: $SIDEBAR_ACCENT; color: $SIDEBAR_TEXT_ACTIVE; }
QTreeWidget#navTree::branch { background: transparent; }
QTreeWidget#navTree::branch:selected { background: $SIDEBAR_BG; }
QTreeWidget#navTree::item:selected { border: none; }
QTreeWidget#navTree::item { border: none; }

QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QAbstractScrollArea { background: transparent; }
QStackedWidget { background: $APP_BG; }
QStackedWidget#inputStack, QWidget#inputPage { background: transparent; }
QWidget#pageContent, QWidget#pageHeader { background: transparent; }
QTabWidget::pane { background: $SURFACE; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: $SCROLLBAR; min-height: 30px; border-radius: 5px; }
QScrollBar::handle:vertical:hover { background: $SCROLLBAR_HOVER; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: $SCROLLBAR; min-width: 30px; border-radius: 5px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QTabWidget::pane { border: 1px solid $BORDER; border-radius: 8px; background: $SURFACE; }
QTabBar::tab {
    background: transparent; color: $TEXT_SECONDARY; padding: 7px 16px;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:selected { color: $PRIMARY; border-bottom: 2px solid $PRIMARY; font-weight: 600; }
QTabBar::tab:hover { color: $TEXT; }

QProgressBar { background: $SURFACE_ALT; border: 1px solid $BORDER; border-radius: 6px;
    text-align: center; color: $TEXT_SECONDARY; height: 14px; font-size: ${SMALL}px; }
QProgressBar::chunk { background: $PRIMARY; border-radius: 5px; }

QToolTip { background: $TOOLTIP_BG; color: $TOOLTIP_TEXT; border: none; padding: 5px 8px; }
QSplitter::handle { background: $BORDER; width: 4px; }
QMenu { background: $SURFACE; border: 1px solid $BORDER_STRONG; padding: 4px; }
QMenu::item { padding: 6px 22px; border-radius: 4px; }
QMenu::item:selected { background: $PRIMARY_SOFT; }
QGroupBox { border: 1px solid $BORDER; border-radius: 8px; margin-top: 10px; padding-top: 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: $TEXT_SECONDARY; }
QDialog QLabel { color: $TEXT; }
QStatusBar { background: $SURFACE_ALT; }
"""
    )
    return t.substitute(
        APP_BG=p["app_bg"],
        SURFACE=p["surface"],
        SURFACE_ALT=p["surface_alt"],
        SURFACE_HOVER=p["surface_hover"],
        BORDER=p["border"],
        BORDER_STRONG=p["border_strong"],
        TEXT=p["text"],
        TEXT_SECONDARY=p["text_secondary"],
        TEXT_TERTIARY=p["text_tertiary"],
        PRIMARY=p["primary"],
        PRIMARY_HOVER=p["primary_hover"],
        PRIMARY_PRESSED=p["primary_pressed"],
        PRIMARY_SOFT=p["primary_soft"],
        PRIMARY_TEXT=p["primary_text"],
        SUCCESS=p["success"],
        DANGER=p["danger"],
        WARN=p["warn"],
        UNKNOWN=p["unknown"],
        SIDEBAR_BG=p["sidebar_bg"],
        SIDEBAR_BG_ALT=p["sidebar_bg_alt"],
        SIDEBAR_TEXT=p["sidebar_text"],
        SIDEBAR_TEXT_ACTIVE=p["sidebar_text_active"],
        SIDEBAR_ACCENT=p["sidebar_accent"],
        SIDEBAR_BORDER=p["sidebar_border"],
        SELECTION=p["selection"],
        TABLE_HEADER=p["table_header"],
        TABLE_ALT=p["table_alt"],
        SCROLLBAR=p["scrollbar"],
        SCROLLBAR_HOVER=p["scrollbar_hover"],
        TOOLTIP_BG=p["tooltip_bg"],
        TOOLTIP_TEXT=p["tooltip_text"],
        FONT=FONT_FAMILY,
        MONO=FONT_MONO,
        BASE=base,
        SMALL=max(10, base - 2),
        TITLE=base + 5,
        BRAND=base + 6,
    )


# ---------------------------------------------------------------- 强调色与调色板
def _rgb(hex_color: str) -> tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#%02X%02X%02X" % rgb


def _mix(a: str, b: str, t: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return _hex(tuple(round(ra[i] * (1 - t) + rb[i] * t) for i in range(3)))


def _shade(color: str, factor: float, lighten: bool) -> str:
    if lighten:
        return _mix(color, "#FFFFFF", factor)
    return _mix(color, "#000000", factor)


def _luminance(color: str) -> float:
    r, g, b = _rgb(color)
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255.0


def with_accent(p: dict, accent: str | None = None) -> dict:
    """在基础主题上应用强调色（派生悬停/按下/浅色底/侧栏选中色）。"""
    q = dict(p)
    if not accent:
        return q
    accent = accent.strip()
    if not (len(accent) == 7 and accent.startswith("#")):
        return q
    light = p["name"] == "light"
    q["primary"] = accent
    q["primary_hover"] = _shade(accent, 0.10, not light)
    q["primary_pressed"] = _shade(accent, 0.22, not light)
    q["primary_soft"] = _mix(accent, p["surface"], 0.86 if light else 0.82)
    q["primary_text"] = "#FFFFFF" if _luminance(accent) < 0.62 else "#0B1624"
    q["sidebar_accent"] = accent if light else _shade(accent, 0.10, True)
    q["selection"] = _mix(accent, p["surface"], 0.84 if light else 0.80)
    return q


def palette_for(name: str, accent: str | None = None) -> dict:
    return with_accent(PALETTES.get(name, LIGHT), accent)


def build_qt_palette(p: dict):
    """构建与主题一致的 QPalette，避免深色模式下滚动区/视口出现白底。"""
    from PySide6.QtGui import QColor, QPalette

    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(p["app_bg"]))
    pal.setColor(QPalette.WindowText, QColor(p["text"]))
    pal.setColor(QPalette.Base, QColor(p["surface"]))
    pal.setColor(QPalette.AlternateBase, QColor(p["surface_alt"]))
    pal.setColor(QPalette.Text, QColor(p["text"]))
    pal.setColor(QPalette.Button, QColor(p["surface"]))
    pal.setColor(QPalette.ButtonText, QColor(p["text"]))
    pal.setColor(QPalette.ToolTipBase, QColor(p["tooltip_bg"]))
    pal.setColor(QPalette.ToolTipText, QColor(p["tooltip_text"]))
    pal.setColor(QPalette.Highlight, QColor(p["primary"]))
    pal.setColor(QPalette.HighlightedText, QColor(p["primary_text"]))
    pal.setColor(QPalette.PlaceholderText, QColor(p["text_tertiary"]))
    return pal
