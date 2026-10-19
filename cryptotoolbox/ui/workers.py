"""后台任务：QThreadPool + QRunnable，支持进度与取消。"""
from __future__ import annotations

import threading
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, Signal


class TaskSignals(QObject):
    result = Signal(object)
    error = Signal(object)
    progress = Signal(int, str)   # 百分比（-1 表示不确定）与描述
    finished = Signal()


class Task(QRunnable):
    """可取消的后台任务。

    fn 若需要进度/取消，签名可包含 progress=callable(percent, msg) 与 cancel=threading.Event。
    """

    def __init__(self, fn: Callable[..., Any], *args, with_progress: bool = False, **kwargs):
        super().__init__()
        self.signals = TaskSignals()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._with_progress = with_progress
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def _emit_progress(self, percent: int, message: str = "") -> None:
        self.signals.progress.emit(int(percent), message)

    def run(self) -> None:
        try:
            if self._with_progress:
                result = self._fn(*self._args, progress=self._emit_progress, cancel=self._cancel,
                                  **self._kwargs)
            else:
                result = self._fn(*self._args, **self._kwargs)
            if not self._cancel.is_set():
                self.signals.result.emit(result)
        except Exception as exc:  # noqa: BLE001 - 统一交给界面展示
            self.signals.error.emit(exc)
        finally:
            self.signals.finished.emit()
