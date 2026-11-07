"""EvidenceViewer: the zoom/pan image display used by every visual view.

Faithful Qt port of the pre-redesign ZoomPanCanvas: cursor-anchored wheel
zoom, drag panning, fit sizing, arrow-key panning, nearest-neighbor sampling
past 2.5x so real pixels stay sharp, empty-state guidance text, and the same
zoom control strip (minus / Fit / plus + zoom % + hint).
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap, QTransform
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ui import theme

ZOOM_STEP = 1.25
ZOOM_MIN, ZOOM_MAX = 0.2, 16.0
FIT_MAX = 12.0


class _View(QGraphicsView):
    zoomChanged = Signal(float)

    def __init__(self, empty_text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self._pixmap_item = None
        self._base_pixmap: QPixmap | None = None
        self._zoom = 1.0
        self._fit_scale = 1.0
        self._has_image = False
        self._empty_text = empty_text
        self._panning = False
        self._pan_start = QPointF()

        self.setBackgroundBrush(QColor(theme.VIEWER_BG))
        self.setFrameShape(QFrame.NoFrame)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

    # -- image management ----------------------------------------------------
    def set_pixmap(self, pixmap: QPixmap | None) -> None:
        self._scene.clear()
        self._pixmap_item = None
        self._base_pixmap = pixmap
        self._has_image = pixmap is not None
        if pixmap is not None:
            self._pixmap_item = self._scene.addPixmap(pixmap)
            self._pixmap_item.setTransformationMode(Qt.SmoothTransformation)
            self._scene.setSceneRect(0, 0, pixmap.width(), pixmap.height())
            self._zoom = 1.0
            self.fit()
        else:
            self._scene.setSceneRect(0, 0, max(self.width(), 1), max(self.height(), 1))
            self.viewport().update()
        self.zoomChanged.emit(self.effective_scale())

    def paintEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        super().paintEvent(event)
        if not self._has_image and self._empty_text:
            painter = QPainter(self.viewport())
            font = QFont(theme.UI_FONT, 11)
            painter.setFont(font)
            painter.setPen(QColor(theme.FG_FAINT))
            lines = self._empty_text.split("\n")
            y = int(self.viewport().height() / 2 - (len(lines) - 1) * 14)
            for line in lines:
                width = painter.fontMetrics().horizontalAdvance(line)
                painter.drawText(int((self.viewport().width() - width) / 2), y, line)
                y += 26
            painter.end()

    # -- zoom / fit ----------------------------------------------------------
    def effective_scale(self) -> float:
        return self._fit_scale * self._zoom

    def _compute_fit_scale(self) -> float:
        if self._base_pixmap is None:
            return 1.0
        vw, vh = self.viewport().width() - 8, self.viewport().height() - 8
        iw, ih = self._base_pixmap.width(), self._base_pixmap.height()
        if iw <= 0 or ih <= 0 or vw <= 0 or vh <= 0:
            return 1.0
        return min(vw / iw, vh / ih, FIT_MAX)

    def fit(self) -> None:
        if not self._has_image:
            return
        self._zoom = 1.0
        self._fit_scale = self._compute_fit_scale()
        self._apply_transform()
        self.centerOn(self.sceneRect().center())
        self.zoomChanged.emit(self.effective_scale())

    def zoom_by(self, factor: float) -> None:
        if not self._has_image:
            return
        self._zoom = max(ZOOM_MIN, min(ZOOM_MAX, self._zoom * factor))
        self._apply_transform()
        self.zoomChanged.emit(self.effective_scale())

    def _apply_transform(self) -> None:
        eff = self.effective_scale()
        self.setTransform(QTransform().scale(eff, eff))
        mode = Qt.FastTransformation if eff > 2.5 else Qt.SmoothTransformation
        if self._pixmap_item is not None:
            self._pixmap_item.setTransformationMode(mode)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if self._has_image:
            # Re-anchor the fit without resetting the user's zoom multiplier.
            self._fit_scale = self._compute_fit_scale()
            self._apply_transform()

    # -- interaction ---------------------------------------------------------
    def wheelEvent(self, event) -> None:  # noqa: N802
        if not self._has_image:
            event.ignore()
            return
        self.zoom_by(ZOOM_STEP if event.angleDelta().y() > 0 else 1 / ZOOM_STEP)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton and self._has_image:
            self._panning = True
            self._pan_start = event.position()
            self.setCursor(Qt.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if self._panning:
            delta = event.position() - self._pan_start
            self._pan_start = event.position()
            self._translate_view(delta)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        key = event.key()
        if key in (Qt.Key_Plus, Qt.Key_Equal):
            self.zoom_by(ZOOM_STEP)
        elif key in (Qt.Key_Minus, Qt.Key_Underscore):
            self.zoom_by(1 / ZOOM_STEP)
        elif key == Qt.Key_0:
            self.fit()
        elif key == Qt.Key_Left:
            self._translate_view(QPointF(-32, 0))
        elif key == Qt.Key_Right:
            self._translate_view(QPointF(32, 0))
        elif key == Qt.Key_Up:
            self._translate_view(QPointF(0, -32))
        elif key == Qt.Key_Down:
            self._translate_view(QPointF(0, 32))
        else:
            super().keyPressEvent(event)

    def _translate_view(self, delta: QPointF) -> None:
        self.horizontalScrollBar().setValue(
            self.horizontalScrollBar().value() - int(delta.x()))
        self.verticalScrollBar().setValue(
            self.verticalScrollBar().value() - int(delta.y()))


class EvidenceViewer(QWidget):
    """Viewer with the same control strip as the pre-redesign UI."""

    def __init__(self, empty_text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self.view = _View(empty_text, self)
        layout.addWidget(self.view, 1)

        strip = QHBoxLayout()
        strip.setContentsMargins(0, 4, 0, 0)
        strip.setSpacing(4)

        self.btn_out = QPushButton("−")
        self.btn_out.setObjectName("smallButton")
        self.btn_out.setFixedWidth(32)
        self.btn_out.setToolTip("Zoom out (also Ctrl+scroll or the − key when the image has focus).")
        self.btn_fit = QPushButton("Fit")
        self.btn_fit.setObjectName("smallButton")
        self.btn_fit.setFixedWidth(48)
        self.btn_fit.setToolTip("Fit the image to the view and reset panning (key: 0).")
        self.btn_in = QPushButton("+")
        self.btn_in.setObjectName("smallButton")
        self.btn_in.setFixedWidth(32)
        self.btn_in.setToolTip("Zoom in (also Ctrl+scroll or the + key when the image has focus).")
        self.zoom_label = QLabel("—")
        self.zoom_label.setObjectName("hintLabel")
        self.zoom_label.setMinimumWidth(48)
        self.zoom_label.setAlignment(Qt.AlignCenter)

        self.btn_out.clicked.connect(lambda: self.view.zoom_by(1 / ZOOM_STEP))
        self.btn_in.clicked.connect(lambda: self.view.zoom_by(ZOOM_STEP))
        self.btn_fit.clicked.connect(self.view.fit)
        self.view.zoomChanged.connect(
            lambda s: self.zoom_label.setText(f"{s * 100:.0f}%" if self.view._has_image else "—"))

        strip.addWidget(self.btn_out)
        strip.addWidget(self.btn_fit)
        strip.addWidget(self.btn_in)
        strip.addWidget(self.zoom_label)
        strip.addStretch(1)
        self.hint = QLabel("drag to pan · Ctrl+scroll or +/− to zoom · 0 to fit")
        self.hint.setObjectName("hintLabel")
        strip.addWidget(self.hint)
        layout.addLayout(strip)

    def set_pixmap(self, pixmap: QPixmap | None) -> None:
        self.view.set_pixmap(pixmap)
