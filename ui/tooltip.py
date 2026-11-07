"""Hover tooltip with plain-language explanations of technical terms.

Faithful port of the pre-redesign Tkinter Tooltip: same 500ms delay, same
below-widget placement with on-screen clamping, hidden on leave/press.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QTimer, Qt
from PySide6.QtWidgets import QFrame, QLabel, QToolTip, QVBoxLayout, QWidget

from ui import theme

SHOW_DELAY_MS = 500


class Tooltip(QObject):
    """Attaches a hover tooltip to any widget via an event filter."""

    def __init__(self, widget: QWidget, text: str) -> None:
        super().__init__(widget)
        self.widget = widget
        self.text = text
        self._tip: QFrame | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(SHOW_DELAY_MS)
        self._timer.timeout.connect(self._show)
        widget.installEventFilter(self)

    def set_text(self, text: str) -> None:
        self.text = text

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if watched is self.widget:
            if event.type() == QEvent.Enter:
                self._timer.start()
            elif event.type() in (QEvent.Leave, QEvent.MouseButtonPress,
                                  QEvent.Destroy, QEvent.Hide):
                self._hide()
        return False

    def _hide(self) -> None:
        self._timer.stop()
        if self._tip is not None:
            self._tip.deleteLater()
            self._tip = None

    def _show(self) -> None:
        if self._tip is not None or not self.widget.isVisible():
            return
        QToolTip.hideText()

        self._tip = QFrame(None, Qt.ToolTip | Qt.FramelessWindowHint)
        self._tip.setAttribute(Qt.WA_TranslucentBackground, False)
        layout = QVBoxLayout(self._tip)
        layout.setContentsMargins(1, 1, 1, 1)
        inner = QFrame(self._tip)
        inner.setStyleSheet(
            f"background: {theme.BG_CARD}; border: none; color: {theme.FG};")
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(8, 5, 8, 5)
        label = QLabel(self.text, inner)
        label.setWordWrap(True)
        label.setMaximumWidth(320)
        label.setAlignment(Qt.AlignLeft)
        inner_layout.addWidget(label)
        layout.addWidget(inner)
        self._tip.setStyleSheet(
            f"background: {theme.BG_CONTROL_HOVER}; border: 1px solid {theme.BG_CONTROL_HOVER};")

        self._tip.adjustSize()
        base = self.widget.mapToGlobal(self.widget.rect().bottomLeft())
        x, y = base.x() + 12, base.y() + 6
        screen = self.widget.screen()
        if screen is not None:
            right = screen.geometry().right()
            if x + self._tip.width() > right - 8:
                x = max(8, right - self._tip.width() - 8)
        self._tip.move(x, y)
        self._tip.show()
