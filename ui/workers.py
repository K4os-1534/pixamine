"""Worker threads: all heavy processing runs off the UI thread."""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6.QtCore import QThread, Signal

import pipeline


class AnalysisWorker(QThread):
    """Runs pipeline.analyze_file on a worker thread.

    progress(str, float)   — stage name and 0..1 fraction
    finished_ok(object)    — the full results dict
    failed(str)            — plain-language failure message
    """

    progress = Signal(str, float)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, path: str, parent=None) -> None:
        super().__init__(parent)
        self._path = path

    def run(self) -> None:
        try:
            results = pipeline.analyze_file(
                self._path,
                progress=lambda stage, frac: self.progress.emit(stage, frac),
            )
            self.finished_ok.emit(results)
        except Exception as exc:
            traceback.print_exc()
            self.failed.emit(
                f"{self._path} could not be analyzed.\n\nReason: {exc}\n\n"
                "The file may be corrupt, incomplete, or in an unsupported format."
            )


class MapWorker(QThread):
    """Renders one analysis map off the UI thread."""

    finished_ok = Signal(str, object)   # (map_key, MapResult)
    failed = Signal(str, str)           # (map_key, reason)

    def __init__(self, key: str, func: Callable[[], Any], parent=None) -> None:
        super().__init__(parent)
        self._key = key
        self._func = func

    def run(self) -> None:
        try:
            self.finished_ok.emit(self._key, self._func())
        except Exception as exc:
            traceback.print_exc()
            self.failed.emit(self._key, str(exc))


class LabWorker(QThread):
    """Runs a named lab computation (LSB extraction, chi-square, entropy...)."""

    finished_ok = Signal(str, object)   # (job_name, payload)
    failed = Signal(str, str)           # (job_name, reason)

    def __init__(self, name: str, func: Callable[[], Any], parent=None) -> None:
        super().__init__(parent)
        self._name = name
        self._func = func

    def run(self) -> None:
        try:
            self.finished_ok.emit(self._name, self._func())
        except Exception as exc:
            traceback.print_exc()
            self.failed.emit(self._name, str(exc))
