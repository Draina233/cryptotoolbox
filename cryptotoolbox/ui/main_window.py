"""主窗口：侧栏 + 顶栏 + 内容栈 + 状态栏，负责页面懒加载、主题与后台任务。"""
from __future__ import annotations

import os
import traceback
from pathlib import Path

from PySide6.QtCore import QSettings, QSize, Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QColor, QIcon, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QColorDialog,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from .pages import GROUPS, find_spec, load_page
from .pages.home import HomePage
from .sidebar import Sidebar
from .state import palette, set_theme, theme_name
from ..theme import DEFAULT_ACCENT, build_qt_palette, qss
from ..update_check import UpdateChecker, is_newer
from .assets import app_icon_path
from .update_dialog import UpdateDialog
from .widgets import HintLabel, MonoText
from .workers import Task
from .icons import make_icon


class MainWindow(QMainWindow):
    theme_changed = Signal(str)

    @staticmethod
    def _make_settings() -> QSettings:
        """配置文件优先放到用户配置目录；受限环境回退到项目内 .config（INI 格式，便于迁移）。"""
        candidates = []
        env_dir = os.environ.get("CRYPTOTOOLBOX_CONFIG_DIR")
        if env_dir:
            candidates.append(Path(env_dir))
        from PySide6.QtCore import QStandardPaths

        app_dir = QStandardPaths.writableLocation(QStandardPaths.AppConfigLocation)
        if app_dir:
            candidates.append(Path(app_dir))
        candidates.append(Path(__file__).resolve().parents[2] / ".config")
        for folder in candidates:
            try:
                folder.mkdir(parents=True, exist_ok=True)
                probe = folder / ".write_test"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
                return QSettings(str(folder / "settings.ini"), QSettings.IniFormat)
            except Exception:  # noqa: BLE001
                continue
        return QSettings(str(Path(__file__).resolve().parents[2] / "settings.ini"), QSettings.IniFormat)

    def __init__(self):
        super().__init__()
        self._settings = self._make_settings()
        self._pages: dict[str, QWidget] = {}
        self._task: Task | None = None
        self._current_page_id = "home"

        theme = str(self._settings.value("theme", "light"))
        try:
            scale = float(self._settings.value("font_scale", 1.0))
        except (TypeError, ValueError):
            scale = 1.0
        accent = str(self._settings.value("accent", DEFAULT_ACCENT)) or DEFAULT_ACCENT
        set_theme(theme, scale, accent)

        self.setWindowTitle(f"密评工具箱 · V{__version__}")
        self.setWindowIcon(QIcon(app_icon_path()))
        self._apply_window_geometry()
        self.setMinimumSize(980, 620)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.page_selected.connect(self.open_page)
        self.sidebar.home_requested.connect(lambda: self.open_page("home"))
        root.addWidget(self.sidebar)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)

        rv.addWidget(self._build_topbar())
        self.stack = QStackedWidget()
        rv.addWidget(self.stack, 1)
        rv.addWidget(self._build_statusbar())

        root.addWidget(right, 1)
        self.setCentralWidget(central)

        # 首页
        self.home = HomePage(self)
        self.home.navigate.connect(self.open_page)
        self.stack.addWidget(self.home)
        self._pages["home"] = self.home

        self._apply_theme()
        shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        shortcut.activated.connect(self._focus_search)
        self._restore_window_state()
        QTimer.singleShot(1500, self._check_for_updates)

    # ------------------------------------------------------------ 构建
    def _build_topbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("topbar")
        bar.setFixedHeight(54)
        h = QHBoxLayout(bar)
        h.setContentsMargins(18, 8, 12, 8)
        h.setSpacing(8)

        self.crumb = QLabel("首页")
        self.crumb.setObjectName("crumb")
        h.addWidget(self.crumb)
        h.addStretch(1)

        self.theme_btn = QToolButton()
        self.theme_btn.setToolTip("切换深色 / 浅色主题")
        self.theme_btn.setIconSize(QSize(18, 18))
        self.theme_btn.clicked.connect(self.toggle_theme)
        h.addWidget(self.theme_btn)

        settings_btn = QToolButton()
        self.settings_btn = settings_btn
        settings_btn.setToolTip("设置")
        settings_btn.setIconSize(QSize(18, 18))
        settings_btn.setIcon(make_icon("gear", palette()["text_secondary"], 18))
        settings_btn.clicked.connect(self.open_settings)
        h.addWidget(settings_btn)

        about_btn = QToolButton()
        self.about_btn = about_btn
        about_btn.setToolTip("关于")
        about_btn.setIconSize(QSize(18, 18))
        about_btn.setIcon(make_icon("info", palette()["text_secondary"], 18))
        about_btn.clicked.connect(self.show_about)
        h.addWidget(about_btn)
        return bar

    def _build_statusbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("statusbar")
        bar.setFixedHeight(34)
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 4, 14, 4)
        h.setSpacing(10)

        self.status_label = QLabel("就绪")
        self.status_label.setObjectName("statusText")
        h.addWidget(self.status_label, 1)

        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setFixedHeight(14)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        h.addWidget(self.progress)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.setObjectName("secondary")
        self.cancel_btn.setFixedHeight(24)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel_task)
        h.addWidget(self.cancel_btn)

        ver = QLabel(f"密评工具箱V{__version__}   ©Draina")
        ver.setObjectName("statusText")
        h.addWidget(ver)
        return bar

    # ------------------------------------------------------------ 主题
    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setPalette(build_qt_palette(palette()))
            app.setStyleSheet(qss(palette(), self._scale()))
        icon = "sun" if theme_name() == "dark" else "moon"
        dark = theme_name() == "dark"
        icon_color = palette()["primary"] if dark else palette()["text_secondary"]
        self.theme_btn.setIcon(make_icon(icon, icon_color, 18))
        if hasattr(self, "settings_btn"):
            self.settings_btn.setIcon(make_icon("gear", icon_color, 18))
        if hasattr(self, "about_btn"):
            self.about_btn.setIcon(make_icon("info", icon_color, 18))
        self.theme_btn.setToolTip("切换到浅色主题" if theme_name() == "dark" else "切换到深色主题")

    def _scale(self) -> float:
        try:
            return float(self._settings.value("font_scale", 1.0))
        except (TypeError, ValueError):
            return 1.0

    def toggle_theme(self) -> None:
        from .state import accent as current_accent

        new = "light" if theme_name() == "dark" else "dark"
        self._settings.setValue("theme", new)
        set_theme(new, self._scale(), current_accent())
        self._apply_theme()
        self.theme_changed.emit(new)
        for page in self._pages.values():
            try:
                page.refresh_theme()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------ 页面
    def _focus_search(self) -> None:
        self.sidebar.search.setFocus()
        self.sidebar.search.selectAll()

    def open_page(self, page_id: str) -> None:
        if page_id == "home":
            self.stack.setCurrentWidget(self.home)
            self._current_page_id = "home"
            self.crumb.setText("首页")
            self.sidebar.select("")
            return

        page = self._pages.get(page_id)
        if page is None:
            self.status_label.setText("正在打开页面…")
            try:
                page = load_page(page_id, self)
            except Exception as exc:  # noqa: BLE001
                self._pages[page_id] = self._error_page(page_id, exc)
                page = self._pages[page_id]
            self._pages[page_id] = page
            self.stack.addWidget(page)
        self.stack.setCurrentWidget(page)
        self._current_page_id = page_id
        spec = find_spec(page_id)
        group_title = page_id
        for group in GROUPS:
            if any(i.id == page_id for i in group.items):
                group_title = group.title
                break
        title = spec.title if spec else page_id
        self.crumb.setText(f"{group_title} / {title}")
        self.sidebar.select(page_id)
        self.status_label.setText(f"当前功能：{title}")

    def _error_page(self, page_id: str, exc: BaseException) -> QWidget:
        spec = find_spec(page_id)
        widget = QWidget()
        v = QVBoxLayout(widget)
        v.setContentsMargins(22, 18, 22, 18)
        title = QLabel(f"页面加载失败：{spec.title if spec else page_id}")
        title.setObjectName("pageTitle")
        v.addWidget(title)
        detail = MonoText()
        detail.setPlainText("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        v.addWidget(detail, 1)
        return widget

    # ------------------------------------------------------------ 后台任务
    def run_task(self, fn, on_result=None, on_error=None, busy_text: str = "正在处理…",
                 cancellable: bool = False, on_progress=None, on_cancel=None):
        if self._task is not None:
            self.notify("已有任务正在执行，请稍候")
            return None
        task = Task(fn, with_progress=cancellable or on_progress is not None)
        self._task = task
        self.status_label.setText(busy_text)
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        if cancellable:
            self.cancel_btn.setVisible(True)
        task.signals.result.connect(lambda r: on_result(r) if on_result else None)
        if on_error is not None:
            task.signals.error.connect(on_error)
        if on_progress is not None:
            task.signals.progress.connect(on_progress)

        def _finished() -> None:
            self._task = None
            self.progress.setVisible(False)
            self.cancel_btn.setVisible(False)
            self.status_label.setText("就绪")

        task.signals.finished.connect(_finished)
        QThreadPool.globalInstance().start(task)
        return task

    def _cancel_task(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self.notify("已请求取消，等待当前步骤结束…")

    def notify(self, message: str) -> None:
        self.status_label.setText(message)
        QTimer.singleShot(4000, lambda: self.status_label.setText("就绪") if self._task is None else None)

    # ------------------------------------------------------------ 设置/关于
    def open_settings(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("设置")
        dlg.setMinimumWidth(500)
        form = QFormLayout(dlg)
        theme = QComboBox()
        theme.addItems(["light", "dark"])
        theme.setCurrentText(theme_name())
        form.addRow("主题：", theme)
        scale = QComboBox()
        for text, value in (("90%", 0.9), ("100%", 1.0), ("110%", 1.1), ("125%", 1.25)):
            scale.addItem(text, value)
        current_scale = self._scale()
        for i in range(scale.count()):
            if abs(scale.itemData(i) - current_scale) < 1e-6:
                scale.setCurrentIndex(i)
                break
        form.addRow("字体缩放：", scale)
        from ..theme import palette_for

        current_accent = str(self._settings.value("accent", DEFAULT_ACCENT)) or DEFAULT_ACCENT
        accent_row = QWidget()
        accent_layout = QHBoxLayout(accent_row)
        accent_layout.setContentsMargins(0, 0, 0, 0)
        swatch = QLabel()
        swatch.setFixedSize(26, 26)
        swatch.setStyleSheet(f"border-radius: 6px; border: 1px solid #999; background: {current_accent or self._current_primary()};")
        choice = {"accent": current_accent}

        def pick_accent() -> None:
            initial = QColor(choice["accent"] or self._current_primary())
            color = QColorDialog.getColor(initial, dlg, "选择强调色")
            if color.isValid():
                choice["accent"] = color.name().upper()
                swatch.setStyleSheet(f"border-radius: 6px; border: 1px solid #999; background: {choice['accent']};")

        def reset_accent() -> None:
            # 恢复默认：浅色主题 + 100% 字号 + 默认强调色，并立即保存/应用
            choice["accent"] = DEFAULT_ACCENT
            theme.setCurrentText("light")
            for i in range(scale.count()):
                try:
                    if abs(float(scale.itemData(i)) - 1.0) < 1e-6:
                        scale.setCurrentIndex(i)
                        break
                except (TypeError, ValueError):
                    continue
            swatch.setStyleSheet(f"border-radius: 6px; border: 1px solid #999; background: {DEFAULT_ACCENT};")
            self._settings.setValue("theme", "light")
            self._settings.setValue("font_scale", 1.0)
            self._settings.setValue("accent", DEFAULT_ACCENT)
            self._settings.setValue("check_updates", True)
            self._update_cb.setChecked(True)
            set_theme("light", 1.0, DEFAULT_ACCENT)
            self._apply_theme()

        pick_btn = QPushButton("选择强调色…")
        pick_btn.clicked.connect(pick_accent)
        reset_btn = QPushButton("恢复默认")
        reset_btn.clicked.connect(reset_accent)
        accent_layout.addWidget(swatch)
        accent_layout.addWidget(pick_btn)
        accent_layout.addWidget(reset_btn)
        accent_layout.addStretch(1)
        form.addRow("强调色：", accent_row)
        form.addRow("当前版本：", QLabel(f"v{__version__}"))
        self._update_cb = QCheckBox("启动时自动检查更新（GitHub Releases）")
        self._update_cb.setChecked(self._setting_bool("check_updates", True))
        form.addRow("自动更新：", self._update_cb)
        manual_row = QWidget()
        manual_layout = QHBoxLayout(manual_row)
        manual_layout.setContentsMargins(0, 0, 0, 0)
        manual_layout.setSpacing(8)
        manual_btn = QPushButton("立即检查更新")
        manual_btn.setObjectName("secondary")
        status_label = QLabel("可手动检查更新")
        status_label.setObjectName("hintText")
        status_label.setWordWrap(True)
        status_label.setMinimumWidth(300)
        manual_layout.addWidget(manual_btn)
        manual_layout.addWidget(status_label, 1)
        form.addRow("手动检查：", manual_row)

        def set_update_status(text: str, color_key: str) -> None:
            status_label.setStyleSheet(f"color: {palette()[color_key]};")
            status_label.setText(text)

        def run_manual_check() -> None:
            manual_btn.setEnabled(False)
            set_update_status("正在检查 GitHub Releases…", "text_secondary")
            checker = UpdateChecker(on_manual_result, dlg)
            dlg._manual_checker = checker
            checker.check()

        def on_manual_result(info) -> None:
            if not dlg.isVisible():
                return
            manual_btn.setEnabled(True)
            checker = getattr(dlg, "_manual_checker", None)
            error = getattr(checker, "error", "") if checker else ""
            if error:
                set_update_status(f"检查失败：{error}\n请检查网络或代理设置后重试。", "danger")
                return
            if info is None:
                set_update_status("检查失败：未获取到发布信息，请确认仓库已发布 Release。", "danger")
                return
            if is_newer(info.version, __version__):
                set_update_status(f"发现新版本 {info.version}（当前 v{__version__}）", "primary")
                UpdateDialog(info, __version__, dlg).exec()
            else:
                set_update_status(f"已是最新版本（当前 v{__version__}，远端 v{info.version}）", "success")

        manual_btn.clicked.connect(run_manual_check)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_button = buttons.button(QDialogButtonBox.Ok)
        if ok_button is not None:
            ok_button.setText("确定")
        cancel_button = buttons.button(QDialogButtonBox.Cancel)
        if cancel_button is not None:
            cancel_button.setText("取消")
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if dlg.exec() == QDialog.Accepted:
            self._settings.setValue("theme", theme.currentText())
            self._settings.setValue("font_scale", float(scale.currentData()))
            self._settings.setValue("accent", choice["accent"])
            self._settings.setValue("check_updates", self._update_cb.isChecked())
            set_theme(theme.currentText(), float(scale.currentData()), choice["accent"])
            self._apply_theme()
            self.theme_changed.emit(theme.currentText())
            for page in self._pages.values():
                try:
                    page.refresh_theme()
                except Exception:  # noqa: BLE001
                    pass
            self.notify("设置已保存")

    def show_about(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(f"关于{__app_name__}")
        dlg.setWindowIcon(QIcon(app_icon_path()))
        dlg.setMinimumWidth(500)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(22, 20, 22, 16)
        layout.setSpacing(12)

        top = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QPixmap(app_icon_path("app_icon_256.png")).scaled(
            72, 72, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        icon.setFixedSize(72, 72)
        top.addWidget(icon)
        title_box = QVBoxLayout()
        title = QLabel(f"{__app_name__} v{__version__}")
        title_font = title.font()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        title_box.addWidget(title)
        subtitle = QLabel("离线密码评估与验证工具箱")
        subtitle.setObjectName("hintText")
        title_box.addWidget(subtitle)
        title_box.addStretch(1)
        top.addLayout(title_box, 1)
        layout.addLayout(top)

        desc = QLabel(
            "面向商用密码应用安全性评估：算法校验、证书与签章核验、协议取证、随机性检测。\n\n"
            "技术栈：PySide6 / gmalg / tongsuopy / PyCryptodome；ASN.1 解析为自研实现，"
            "支持国密 SM2 证书。\n"
            "参考标准：GM/T 0005-2021；随机性检测参考 guojuntang/gmt_randomness_test（BSD-3-Clause）。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        dev = QLabel("开发者：Draina ｜ draina@qq.com ｜ https://github.com/Draina233")
        dev.setObjectName("hintText")
        layout.addWidget(dev)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        close_button = buttons.button(QDialogButtonBox.Close)
        if close_button is not None:
            close_button.setText("关闭")
        buttons.rejected.connect(dlg.reject)
        buttons.clicked.connect(dlg.accept)
        layout.addWidget(buttons)
        dlg.exec()

    def _setting_bool(self, key: str, default: bool) -> bool:
        value = self._settings.value(key, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    def _check_for_updates(self) -> None:
        """启动后异步检查 GitHub Releases；离线/测试环境静默跳过。"""
        if getattr(self, "_update_checked", False):
            return
        self._update_checked = True
        if QApplication.platformName() == "offscreen":
            return
        if os.environ.get("CRYPTOTOOLBOX_NO_UPDATE_CHECK"):
            return
        if not self._setting_bool("check_updates", True):
            return
        try:
            self._update_checker = UpdateChecker(self._on_update_checked, self)
            self._update_checker.check()
        except Exception:  # noqa: BLE001 - 更新检查失败不影响主程序
            import logging

            logging.getLogger(__name__).exception("update check failed to start")

    def _on_update_checked(self, info) -> None:
        if info is None or not self.isVisible():
            return
        if not is_newer(info.version, __version__):
            return
        dialog = UpdateDialog(info, __version__, self)
        dialog.exec()

    def _current_primary(self) -> str:
        return palette()["primary"]

    def _apply_window_geometry(self) -> None:
        """根据屏幕可用区域计算合适窗口大小并居中。"""
        from PySide6.QtCore import QPoint

        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1280, 800)
            self.move(60, 40)
            return
        available = screen.availableGeometry()
        width = min(1340, max(1000, available.width() - 120))
        height = min(860, max(640, available.height() - 140))
        self.resize(width, height)
        x = available.x() + max(0, (available.width() - width) // 2)
        y = available.y() + max(0, (available.height() - height) // 2)
        self.move(QPoint(x, y))

    def _restore_window_state(self) -> None:
        geo = self._settings.value("geometry")
        if geo is None:
            return
        try:
            from PySide6.QtCore import QRect

            self.restoreGeometry(geo)
            screen = QApplication.primaryScreen()
            if screen is not None:
                visible = screen.availableGeometry()
                rect = self.frameGeometry()
                if not visible.intersects(rect) or rect.width() > visible.width() + 40 or rect.height() > visible.height() + 40:
                    self._apply_window_geometry()
        except Exception:  # noqa: BLE001
            self._apply_window_geometry()

    def closeEvent(self, event) -> None:  # noqa: N802
        try:
            self._settings.setValue("geometry", self.saveGeometry())
        except Exception:  # noqa: BLE001
            pass
        if self._task is not None:
            self._task.cancel()
        super().closeEvent(event)

