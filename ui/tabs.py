"""The five workspace tabs, ported widget-for-widget from the pre-redesign
Tkinter UI: Overview, Metadata, Tampering, Steganography, Structure & Carving.

Same layout, same texts, same tooltips, same enable/disable behavior — built
natively in Qt with the same controller/worker plumbing.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from PIL import Image
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSlider,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

import carver
import stego
from ui import theme
from ui.controller import MAP_LABEL_TO_KEY, MAP_MODES, MAP_TOOLTIPS, AppController, pil_to_pixmap
from ui.models import MetadataFilterProxy, MetadataModel, SignaturesModel
from ui.tooltip import Tooltip
from ui.viewer import EvidenceViewer


def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("sectionLabel")
    return lbl


def heading_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("headingLabel")
    return lbl


def muted_label(text: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("mutedLabel")
    lbl.setWordWrap(True)
    return lbl


def text_panel(fg: str = theme.FG, bg: str = theme.BG_SUNKEN, height: int = 0) -> QPlainTextEdit:
    widget = QPlainTextEdit()
    widget.setReadOnly(True)
    widget.setStyleSheet(
        f"QPlainTextEdit {{ background: {bg}; color: {fg}; border: none; }}")
    if height:
        widget.setFixedHeight(height)
    return widget


class PlotCanvas(QWidget):
    """Canvas that renders a PIL plot at the current widget size and
    re-renders on resize — the Qt equivalent of the old
    ``canvas.bind("<Configure>", redraw)`` behavior."""

    def __init__(self, renderer: Callable[[int, int], Image.Image],
                 min_w: int, min_h: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._renderer = renderer
        self._pixmap: QPixmap | None = None
        self.setMinimumSize(min_w, min_h)
        self.setStyleSheet(f"background: {theme.BG_SUNKEN};")

    def set_renderer(self, renderer: Callable[[int, int], Image.Image] | None) -> None:
        self._renderer = renderer
        self._render()

    def clear(self, text: str = "") -> None:
        self.set_renderer(None)
        self.update()

    def _render(self) -> None:
        if self._renderer is None or not self.isVisible():
            self._pixmap = None
            return
        w = max(self.width(), self.minimumWidth())
        h = max(self.height(), self.minimumHeight())
        try:
            self._pixmap = pil_to_pixmap(self._renderer(w, h))
        except Exception:
            self._pixmap = None
        self.update()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._render()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._render()

    def paintEvent(self, event) -> None:  # noqa: N802
        super().paintEvent(event)
        if self._pixmap is not None:
            from PySide6.QtGui import QPainter
            painter = QPainter(self)
            x = (self.width() - self._pixmap.width()) // 2
            y = (self.height() - self._pixmap.height()) // 2
            painter.drawPixmap(x, y, self._pixmap)
            painter.end()


# ---------------------------------------------------------------------------
# Tab 1: Overview
# ---------------------------------------------------------------------------
class OverviewTab(QWidget):
    def __init__(self, controller: AppController, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.controller = controller
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter)

        # Left: image preview
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(heading_label("Image Preview"))
        self.viewer = EvidenceViewer("No image loaded\nOpen an image to begin (Ctrl+O)")
        left_layout.addWidget(self.viewer, 1)
        splitter.addWidget(left)

        # Right: pillars, timestamps, findings
        right = QFrame()
        right.setObjectName("card")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(14, 10, 14, 10)
        right_layout.setSpacing(6)

        right_layout.addWidget(section_label("FORENSIC PILLAR BREAKDOWN"))
        pillar_row = QHBoxLayout()
        pillar_row.setSpacing(6)
        self.pillar_values: dict[str, QLabel] = {}
        pillar_tooltips = {
            "Metadata": "EXIF/XMP presence and internal consistency of timestamps, "
                        "camera tags, and dimension fields.",
            "Compression": "Whether JPEG quantization tables match a normal camera or "
                           "editor save (IJG quality tables).",
            "Container": "Structural integrity of the file: trailing data after the "
                         "image, embedded binaries, marker ordering.",
            "Stego": "Statistical signs of LSB steganography (chi-square, sample-pair "
                     "analysis) and embedded payloads.",
            "Tampering": "Pixel-level tampering evidence. Run the copy-move map in the "
                         "Tampering tab for visual confirmation.",
        }
        for name in ("Metadata", "Compression", "Container", "Stego", "Tampering"):
            box = QFrame()
            box.setStyleSheet(
                f"QFrame {{ background: {theme.BG_SUNKEN}; border: 1px solid {theme.BORDER}; }}")
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(6, 4, 6, 4)
            box_layout.setSpacing(2)
            name_lbl = QLabel(name)
            name_lbl.setAlignment(Qt.AlignCenter)
            name_lbl.setStyleSheet(
                f"color: {theme.FG_MUTED}; font-size: 11px; background: transparent;")
            value_lbl = QLabel("--%")
            value_lbl.setAlignment(Qt.AlignCenter)
            value_lbl.setStyleSheet(
                f"color: {theme.FG}; font-size: 14px; font-weight: 700; background: transparent;")
            box_layout.addWidget(name_lbl)
            box_layout.addWidget(value_lbl)
            pillar_row.addWidget(box, 1)
            self.pillar_values[name] = value_lbl
            Tooltip(box, pillar_tooltips[name])
        right_layout.addLayout(pillar_row)

        ts_label = section_label("TIMESTAMPS & PROVENANCE")
        right_layout.addWidget(ts_label)
        self.timestamps = text_panel()
        self.timestamps.setFixedHeight(96)
        right_layout.addWidget(self.timestamps)

        findings_label = section_label("FINDINGS & RISK FACTORS")
        findings_label.setStyleSheet(
            f"color: {theme.WARN}; font-size: 12px; font-weight: 700; letter-spacing: 1px;")
        right_layout.addWidget(findings_label)
        self.findings = text_panel()
        from PySide6.QtGui import QTextOption
        self.findings.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        right_layout.addWidget(self.findings, 1)

        splitter.addWidget(right)
        splitter.setSizes([420, 560])
        self.show_empty_state()

    # -- view fonts for word wrap on findings ---------------------------------
    def show_empty_state(self) -> None:
        self._update_pillars(None)
        self.timestamps.setPlainText(
            "Timestamps appear here after an image is loaded.\n"
            "Capture, digitized, modified, and filesystem times are compared for consistency.")
        self.findings.setPlainText(
            "Findings appear here after an image is loaded.\n"
            "Each entry lists a severity (INFO / WARNING / CRITICAL) and what it means.")

    def show_results(self, results: dict[str, Any]) -> None:
        meta = results["meta"]
        sc = results["scorecard"]
        self.viewer.set_pixmap(pil_to_pixmap(results["src_image"]))
        self._update_pillars(sc)

        ts_lines = []
        for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime", "FileModified",
                    "PNG:EmbeddedModifiedTime"):
            if key in meta:
                ts_lines.append(f"{key:26} {meta[key]}")
        if not ts_lines:
            ts_lines.append("No embedded capture timestamps present in the container.")
        self.timestamps.setPlainText("\n".join(ts_lines))

        if sc.risk_factors:
            lines = []
            for rf in sc.risk_factors:
                conf = rf.get("confidence")
                conf_txt = f" (confidence {conf * 100:.0f}%)" if conf is not None else ""
                lines.append(f"• [{rf['severity']}] {rf['category']}{conf_txt}: {rf['detail']}\n")
            self.findings.setPlainText("\n".join(lines))
        else:
            self.findings.setPlainText(
                "No metadata or container anomalies detected.\n"
                "This does not prove the pixels are authentic — "
                "check the Tampering tab maps as well.")

    def _update_pillars(self, sc) -> None:
        values = {
            "Metadata": sc.metadata_score if sc else None,
            "Compression": sc.compression_score if sc else None,
            "Container": sc.container_score if sc else None,
            "Stego": sc.stego_score if sc else None,
            "Tampering": sc.tamper_score if sc else None,
        }
        for name, value in values.items():
            self.pillar_values[name].setText("--%" if value is None else f"{value}%")


# ---------------------------------------------------------------------------
# Tab 2: Metadata
# ---------------------------------------------------------------------------
class MetadataTab(QWidget):
    def __init__(self, controller: AppController, export_csv: Callable[[], None],
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        ctrl = QHBoxLayout()
        lbl = QLabel("Filter tags:")
        lbl.setToolTip("Show only tags whose name or value contains this text.")
        ctrl.addWidget(lbl)
        self.filter_edit = QLineEdit()
        self.filter_edit.setMaximumWidth(240)
        self.filter_edit.setToolTip("Show only tags whose name or value contains this text.")
        self.filter_edit.setClearButtonEnabled(True)
        ctrl.addWidget(self.filter_edit)
        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("smallButton")
        clear_btn.clicked.connect(self.filter_edit.clear)
        ctrl.addWidget(clear_btn)
        ctrl.addStretch(1)
        csv_btn = QPushButton("Export CSV…")
        csv_btn.setObjectName("smallButton")
        csv_btn.clicked.connect(export_csv)
        ctrl.addWidget(csv_btn)
        layout.addLayout(ctrl)
        self.filter_edit.textChanged.connect(lambda _t: self.proxy.set_filter(self.filter_edit.text()))

        # GPS summary bar
        self.gps_bar = QFrame()
        self.gps_bar.setObjectName("card")
        gps_layout = QHBoxLayout(self.gps_bar)
        gps_layout.setContentsMargins(10, 6, 10, 6)
        self.gps_label = QLabel("GPS: no coordinates in file")
        self.gps_label.setObjectName("cardMuted")
        gps_layout.addWidget(self.gps_label)
        gps_layout.addStretch(1)
        self.osm_btn = QPushButton("Open in OpenStreetMap")
        self.osm_btn.setObjectName("smallButton")
        self.osm_btn.setEnabled(False)
        self.osm_btn.setToolTip("Opens the extracted GPS coordinates on openstreetmap.org "
                                "(requires internet access).")
        self.osm_btn.clicked.connect(self.controller.open_map_link)
        gps_layout.addWidget(self.osm_btn)
        layout.addWidget(self.gps_bar)

        self.model = MetadataModel(self)
        self.proxy = MetadataFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 300)
        self.table.setToolTip("Every tag extracted from the container: EXIF, XMP, IPTC, "
                              "ICC profile, MakerNotes, PNG/WebP chunks, computed hashes, "
                              "and GPS links.")
        layout.addWidget(self.table, 1)

    def show_empty_state(self) -> None:
        self.model.set_meta({})
        self.gps_label.setText("GPS: no coordinates in file")
        self.osm_btn.setEnabled(False)

    def show_results(self, results: dict[str, Any]) -> None:
        meta = results["meta"]
        self.model.set_meta(meta)
        if "GPSLatitude" in meta and "GPSLongitude" in meta:
            lat, lon = meta["GPSLatitude"], meta["GPSLongitude"]
            alt = meta.get("GPSAltitude", "N/A")
            self.gps_label.setText(
                f"GPS coordinates: {lat:.6f}, {lon:.6f} (altitude: {alt} m)")
            self.osm_btn.setEnabled(True)
        else:
            self.gps_label.setText("GPS: no geolocation tags embedded in file")
            self.osm_btn.setEnabled(False)


# ---------------------------------------------------------------------------
# Tab 3: Tampering
# ---------------------------------------------------------------------------
class TamperingTab(QWidget):
    def __init__(self, controller: AppController, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        ctrl = QHBoxLayout()
        ctrl.setSpacing(6)
        map_lbl = QLabel("Analysis map:")
        map_lbl.setToolTip("Choose the pixel-level analysis to render. Hover each control "
                           "for an explanation of what the map shows and when it misleads.")
        ctrl.addWidget(map_lbl)
        self.map_combo = QComboBox()
        for _key, label, *_rest in MAP_MODES:
            self.map_combo.addItem(label)
        self.map_combo.currentTextChanged.connect(self._on_map_changed)
        ctrl.addWidget(self.map_combo)
        self.maps_tooltip = Tooltip(self.map_combo, MAP_TOOLTIPS["ela"])

        self.colormap_label = QLabel("Colormap:")
        ctrl.addWidget(self.colormap_label)
        self.colormap_combo = QComboBox()
        self.colormap_combo.addItems(["inferno", "jet", "viridis", "hot", "raw"])
        self.colormap_combo.setCurrentText("inferno")
        self.colormap_combo.currentTextChanged.connect(self._on_colormap)
        self.colormap_combo.setToolTip("False-color palette for the heatmap. 'raw' shows "
                                       "the amplified grayscale difference instead.")
        ctrl.addWidget(self.colormap_combo)

        self.quality_label = QLabel("ELA quality:")
        ctrl.addWidget(self.quality_label)
        self.quality_slider = QSlider(Qt.Horizontal)
        self.quality_slider.setRange(50, 100)
        self.quality_slider.setValue(controller.ela_quality)
        self.quality_slider.setFixedWidth(130)
        self.quality_slider.setToolTip("JPEG quality used for the re-save in ELA. "
                                       "Try a few values; 90-95 suits most camera photos.")
        self.quality_slider.valueChanged.connect(
            lambda v: self.quality_val_label.setText(str(int(v))))
        self.quality_slider.sliderReleased.connect(self._on_quality_released)
        ctrl.addWidget(self.quality_slider)
        self.quality_val_label = QLabel(str(controller.ela_quality))
        ctrl.addWidget(self.quality_val_label)

        self.compare_check = QCheckBox("Side-by-side with original")
        self.compare_check.setChecked(True)
        self.compare_check.setToolTip("Show the untouched original next to the analysis view.")
        self.compare_check.toggled.connect(self._on_compare)
        ctrl.addWidget(self.compare_check)

        self.blend_label = QLabel("Map opacity: 100%")
        ctrl.addWidget(self.blend_label)
        self.blend_slider = QSlider(Qt.Horizontal)
        self.blend_slider.setRange(0, 100)
        self.blend_slider.setValue(100)
        self.blend_slider.setFixedWidth(110)
        self.blend_slider.setToolTip("Blend the map over the original image. 0% shows the "
                                     "original, 100% the pure analysis map.")
        self.blend_slider.valueChanged.connect(self._on_blend)
        ctrl.addWidget(self.blend_slider)
        ctrl.addStretch(1)
        layout.addLayout(ctrl)

        self.desc_label = muted_label()
        layout.addWidget(self.desc_label)

        self.viewer = EvidenceViewer("Load an image, then pick an analysis map")
        layout.addWidget(self.viewer, 1)

        self._set_controls_enabled("ela")

    # -- per-map control states (same capability table as before) -------------
    def _set_controls_enabled(self, key: str) -> None:
        caps = {m[0]: m[2:] for m in MAP_MODES}
        colormap_ok, quality_ok, blend_ok, compare_ok = caps.get(key, (False, False, False, False))
        self.colormap_combo.setEnabled(colormap_ok)
        self.colormap_label.setEnabled(colormap_ok)
        self.quality_slider.setEnabled(quality_ok)
        self.quality_label.setEnabled(quality_ok)
        self.blend_slider.setEnabled(blend_ok)
        self.blend_label.setEnabled(blend_ok)
        self.compare_check.setEnabled(compare_ok)

    def show_empty_state(self) -> None:
        self.viewer.set_pixmap(None)
        self.desc_label.setText("")
        self.select_map("ela")

    def select_map(self, key: str) -> None:
        """Make the given view active: keep the combobox authoritative and
        request the map (re-selecting the current entry still re-renders)."""
        label = next((lbl for k, lbl, *_ in MAP_MODES if k == key), MAP_MODES[0][1])
        if self.map_combo.currentText() == label:
            self.controller.request_map(key)
        else:
            self.map_combo.setCurrentText(label)  # fires _on_map_changed

    def _on_map_changed(self, label: str) -> None:
        key = MAP_LABEL_TO_KEY.get(label, "ela")
        self._set_controls_enabled(key)
        self.maps_tooltip.set_text(MAP_TOOLTIPS[key])
        self.controller.request_map(key)

    def _on_colormap(self, value: str) -> None:
        self.controller.colormap = value
        self.controller.invalidate_maps(["ela", "noise", "ghost"])

    def _on_quality_released(self) -> None:
        self.controller.ela_quality = int(self.quality_slider.value())
        self.controller.invalidate_maps(["ela"])

    def _on_compare(self, checked: bool) -> None:
        self.controller.compare = checked
        self.compose_display()

    def _on_blend(self, value: int) -> None:
        self.controller.blend = float(value)
        self.blend_label.setText(f"Map opacity: {value}%")
        self.compose_display()

    # -- composition (same logic as the pre-redesign _compose_map_display) ----
    def show_map(self, key: str) -> None:
        # Keep the combobox in sync with whatever view was actually rendered.
        label = next((lbl for k, lbl, *_ in MAP_MODES if k == key), None)
        if label is not None and self.map_combo.currentText() != label:
            self.map_combo.blockSignals(True)
            self.map_combo.setCurrentText(label)
            self.map_combo.blockSignals(False)
        self._set_controls_enabled(key)
        result = self.controller.maps.get(key)
        if result is None:
            return
        parts = []
        legend = getattr(result, "legend", "")
        notes = getattr(result, "notes", [])
        conf = getattr(result, "confidence", None)
        if conf is not None:
            parts.append(f"Confidence: {conf * 100:.0f}%")
        if legend:
            parts.append(legend)
        parts.extend(notes)
        if key == "clone":
            count = len(getattr(result, "clusters", []))
            if count:
                parts.append(f"Detected {count} geometrically verified cloned cluster(s) "
                             "— review highlighted regions before concluding.")
            else:
                parts.append("No geometrically verified cloned clusters were detected.")
        self.desc_label.setText("\n\n".join(p for p in parts if p))
        self.compose_display()

    def compose_display(self) -> None:
        controller = self.controller
        if not controller.has_image:
            return
        key = controller.active_view
        result = controller.maps.get(key)
        if result is None:
            self.viewer.set_pixmap(pil_to_pixmap(controller.src_image))
            return
        map_img = getattr(result, "image", None)
        if map_img is None:
            self.viewer.set_pixmap(pil_to_pixmap(controller.src_image))
            return

        caps = {m[0]: m[2:] for m in MAP_MODES}
        _cmap_ok, _qual_ok, blend_ok, compare_ok = caps.get(key, (False, False, False, False))
        img = map_img

        if blend_ok and controller.blend < 100:
            orig = controller.src_image.resize(img.size, Image.Resampling.BILINEAR)
            img = Image.blend(orig.convert("RGB"), img.convert("RGB"), controller.blend / 100.0)

        if compare_ok and controller.compare:
            orig = controller.src_image.resize(img.size, Image.Resampling.BILINEAR)
            gap = 8
            strip = Image.new("RGB", (img.width + gap + orig.width,
                                      max(img.height, orig.height)), theme.VIEWER_BG)
            strip.paste(orig.convert("RGB"), (0, 0))
            strip.paste(img.convert("RGB"), (orig.width + gap, 0))
            img = strip

        self.viewer.set_pixmap(pil_to_pixmap(img))


# ---------------------------------------------------------------------------
# Tab 4: Steganography
# ---------------------------------------------------------------------------
class SteganographyTab(QWidget):
    def __init__(self, controller: AppController, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.controller = controller
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter)

        # Left: bit planes
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        bp_ctrl = QHBoxLayout()
        bp_lbl = QLabel("Bit plane:")
        bp_lbl.setToolTip("0 is the least significant bit (LSB) where hidden data is "
                          "usually embedded; 7 is the most significant bit. Noise-like "
                          "patterns in plane 0 can indicate steganography.")
        bp_ctrl.addWidget(bp_lbl)
        self.plane_buttons: list[QRadioButton] = []
        for b in range(8):
            rb = QRadioButton(str(b))
            rb.setChecked(b == 0)
            rb.clicked.connect(self._render_plane)
            self.plane_buttons.append(rb)
            bp_ctrl.addWidget(rb)
        ch_lbl = QLabel("Channel:")
        ch_lbl.setToolTip("Which color channel(s) to visualize. RGB combines all three; "
                          "A shows the alpha channel when present.")
        bp_ctrl.addWidget(ch_lbl)
        self.channel_combo = QComboBox()
        self.channel_combo.addItems(["RGB", "R", "G", "B", "A"])
        self.channel_combo.setToolTip("Which color channel(s) to visualize. RGB combines "
                                      "all three; A shows the alpha channel when present.")
        self.channel_combo.currentTextChanged.connect(lambda _t: self._render_plane())
        bp_ctrl.addWidget(self.channel_combo)
        self.montage_btn = QPushButton("8-Plane Montage")
        self.montage_btn.setObjectName("smallButton")
        self.montage_btn.setToolTip("Render all eight bit planes at once. Hidden data "
                                    "usually shows as structured noise in the low planes (0-1).")
        self.montage_btn.clicked.connect(self._render_montage)
        bp_ctrl.addWidget(self.montage_btn)
        bp_ctrl.addStretch(1)
        left_layout.addLayout(bp_ctrl)

        self.plane_viewer = EvidenceViewer("Load an image to inspect its bit planes")
        left_layout.addWidget(self.plane_viewer, 1)
        splitter.addWidget(left)

        # Right: chi-square + LSB extraction
        right = QFrame()
        right.setObjectName("card")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 10, 12, 10)
        right_layout.setSpacing(6)

        chi_lbl = section_label("CHI-SQUARE (χ²) LSB ATTACK")
        chi_lbl.setObjectName("cardSection")
        chi_lbl.setToolTip("Tests whether pairs of pixel values that differ only in the "
                           "least significant bit are suspiciously equalized — a common "
                           "side effect of LSB steganography. Noisy images can trigger "
                           "false positives.")
        right_layout.addWidget(chi_lbl)
        self.chi_canvas = PlotCanvas(self._chi_renderer, 380, 160)
        self.chi_canvas.setStyleSheet(
            f"background: {theme.BG_SUNKEN}; border: 1px solid {theme.BORDER};")
        right_layout.addWidget(self.chi_canvas)
        self.chi_readout = QLabel("χ²: run after loading an image")
        self.chi_readout.setObjectName("cardMuted")
        self.chi_readout.setWordWrap(True)
        right_layout.addWidget(self.chi_readout)

        lsb_lbl = section_label("LSB PAYLOAD & STRING EXTRACTION")
        lsb_lbl.setObjectName("cardSection")
        right_layout.addWidget(lsb_lbl)
        lsb_tools = QHBoxLayout()
        self.extract_btn = QPushButton("Extract LSB Strings")
        self.extract_btn.setObjectName("smallButton")
        self.extract_btn.setToolTip("Reads the LSB bitstream row by row and reports its "
                                    "entropy, any embedded file signatures, and printable strings.")
        self.extract_btn.clicked.connect(self._extract_lsb)
        self.dump_btn = QPushButton("Dump Raw LSB Bytes…")
        self.dump_btn.setObjectName("smallButton")
        self.dump_btn.setToolTip("Saves the raw LSB bitstream to a .bin file for external tools.")
        self.dump_btn.clicked.connect(self._dump_lsb)
        lsb_tools.addWidget(self.extract_btn)
        lsb_tools.addWidget(self.dump_btn)
        lsb_tools.addStretch(1)
        right_layout.addLayout(lsb_tools)

        self.lsb_text = text_panel(fg=theme.FG_MUTED)
        right_layout.addWidget(self.lsb_text, 1)
        splitter.addWidget(right)
        splitter.setSizes([440, 420])

    # -- rendering -------------------------------------------------------------
    def show_empty_state(self) -> None:
        self.plane_viewer.set_pixmap(None)
        self.chi_canvas.set_renderer(None)
        self.chi_readout.setText("χ²: run after loading an image")
        self.chi_readout.setStyleSheet(f"color: {theme.FG_MUTED}; background: {theme.BG_CARD};")
        self.lsb_text.clear()

    def show_results(self, results: dict[str, Any]) -> None:
        self._render_plane()
        self._update_chi()

    def _selected_plane(self) -> int:
        return next(b for b, rb in enumerate(self.plane_buttons) if rb.isChecked())

    def _render_plane(self) -> None:
        if not self.controller.has_image:
            return
        img = stego.slice_bit_plane(self.controller.src_image, plane=self._selected_plane(),
                                    channel=self.channel_combo.currentText())
        self.plane_viewer.set_pixmap(pil_to_pixmap(img))

    def _render_montage(self) -> None:
        if not self.controller.has_image:
            return
        img = stego.bit_plane_gallery(self.controller.src_image,
                                      channel=self.channel_combo.currentText())
        self.plane_viewer.set_pixmap(pil_to_pixmap(img))

    def _update_chi(self) -> None:
        if not self.controller.has_image:
            return
        results = self.controller.results
        prob = results["chi2_prob"]
        self._chi_data = (results["chi_profile"], prob)
        self.chi_canvas.set_renderer(self._chi_renderer)
        if prob > 0.6:
            verdict, color = "high LSB-stego risk", theme.CRIT
        elif prob > 0.3:
            verdict, color = "suspicious LSB distribution — verify with LSB extraction", theme.WARN
        else:
            verdict, color = "low — natural LSB distribution", theme.OK
        self.chi_readout.setText(f"χ² LSB-stego probability: {prob * 100:.0f}% — {verdict}")
        self.chi_readout.setStyleSheet(f"color: {color}; background: {theme.BG_CARD};")

    def _chi_renderer(self, w: int, h: int) -> Image.Image:
        profile, prob = self._chi_data
        return stego.render_chi_square_plot(profile, width=w, height=h, overall_prob=prob)

    # -- LSB jobs ----------------------------------------------------------------
    def _extract_lsb(self) -> None:
        if not self.controller.has_image:
            self.controller.status.emit("Load an image first")
            return
        self.controller.status.emit("Extracting LSB payload …")
        self.controller.run_lab("lsb_report", self._lsb_job)

    def _lsb_job(self) -> Any:
        src = self.controller.src_image
        raw = stego.extract_lsb_bytes(src, channels="RGB", bits_per_channel=1, max_bytes=65536)
        report = stego.inspect_lsb_payload(raw)
        spa = stego.sample_pair_analysis(src)
        return (report, spa)

    def _dump_lsb(self) -> None:
        if not self.controller.has_image:
            self.controller.status.emit("Load an image first")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Dump raw LSB bytes", "lsb_dump.bin", "Binary (*.bin);;All files (*)")
        if not path:
            return
        self.controller.run_lab("lsb_dump", lambda: self._write_lsb(path))

    def _write_lsb(self, path: str) -> str:
        raw = stego.extract_lsb_bytes(self.controller.src_image, max_bytes=1024 * 1024)
        with open(path, "wb") as f:
            f.write(raw)
        return path

    def show_lsb_report(self) -> None:
        payload = self.controller.lab_result("lsb_report")
        if payload is None:
            return
        report, spa = payload
        lines = [
            f"=== LSB extracted analysis ({report['size']:,} bytes analyzed) ===",
            f"Estimated hidden capacity (SPA): {spa * 100:.1f}%",
            f"Extracted bitstream entropy: {report['entropy']:.3f} bits/byte "
            "(~7.5+ suggests encrypted/compressed content)",
            "",
            "--- Embedded file signatures in LSB stream ---",
        ]
        if report["signatures"]:
            lines += [f"• 0x{s.offset:04x}: {s.name} ({s.category})"
                      for s in report["signatures"]]
        else:
            lines.append("(no magic file headers discovered)")
        lines += ["", "--- Printable ASCII / UTF-8 strings ---"]
        if report["strings"]:
            lines += [f"  {s!r}" for s in report["strings"][:40]]
        else:
            lines.append("(no printable string sequences found)")
        lines += [
            "",
            "Interpretation: high entropy with no strings/signatures usually means "
            "compressed or encrypted data — or simply a natural image's noise. Strings "
            "in a predictable order are stronger evidence of hidden text.",
        ]
        self.lsb_text.setPlainText("\n".join(lines))

    def show_dump_done(self) -> None:
        path = self.controller.lab_result("lsb_dump")
        if path is None:
            return
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        self.controller.status.emit(
            f"Saved {size:,} bytes of raw LSB data to {os.path.basename(path)}")
        QMessageBox.information(self, "LSB dump saved",
                                f"Saved {size:,} bytes of raw LSB data to:\n{path}")


# ---------------------------------------------------------------------------
# Tab 5: Structure & Carving
# ---------------------------------------------------------------------------
class CarverTab(QWidget):
    def __init__(self, controller: AppController, carve_action: Callable[[], None],
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        ent_box = QFrame()
        ent_box.setObjectName("card")
        ent_layout = QVBoxLayout(ent_box)
        ent_layout.setContentsMargins(8, 6, 8, 6)
        ent_layout.setSpacing(4)
        ent_lbl = section_label("SHANNON ENTROPY PROFILE (SLIDING WINDOW)")
        ent_lbl.setObjectName("cardSection")
        ent_lbl.setToolTip("Byte-level entropy per 1 KB window. Sustained values above "
                           "the red 7.2 line usually mean encrypted or compressed data "
                           "is embedded at that offset.")
        ent_layout.addWidget(ent_lbl)
        self.entropy_canvas = PlotCanvas(self._render_entropy, 700, 180)
        self.entropy_canvas.setStyleSheet(f"background: {theme.BG_SUNKEN};")
        ent_layout.addWidget(self.entropy_canvas)
        self.entropy_readout = QLabel("Entropy: run after loading an image")
        self.entropy_readout.setObjectName("cardMuted")
        self.entropy_readout.setWordWrap(True)
        ent_layout.addWidget(self.entropy_readout)
        layout.addWidget(ent_box)

        mid = QHBoxLayout()
        sig_lbl = heading_label("Detected binary signatures & overlays:")
        sig_lbl.setToolTip("Known file headers found inside the image bytes (Binwalk-style). "
                           "'Medium' confidence matches occur before the image's end of "
                           "file and lack a structural validator.")
        mid.addWidget(sig_lbl)
        mid.addStretch(1)
        self.carve_btn = QPushButton("Carve Payloads to Folder…")
        self.carve_btn.setObjectName("accentButton")
        self.carve_btn.setToolTip("Extract embedded payloads and trailing overlays to a "
                                  "folder for separate inspection.")
        self.carve_btn.clicked.connect(carve_action)
        mid.addWidget(self.carve_btn)
        layout.addLayout(mid)

        self.sig_model = SignaturesModel(self)
        self.sig_table = QTableView()
        self.sig_table.setModel(self.sig_model)
        self.sig_table.verticalHeader().hide()
        self.sig_table.setShowGrid(False)
        self.sig_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.sig_table.setFixedHeight(150)
        for col, width in ((0, 100), (1, 110), (2, 180), (3, 95)):
            self.sig_table.setColumnWidth(col, width)
        self.sig_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.sig_table.setToolTip("Matches at byte offsets in the file. 'Appended Overlay' "
                                  "is data hidden after the image's legitimate end.")
        layout.addWidget(self.sig_table)

        hex_ctrl = QHBoxLayout()
        hex_lbl = QLabel("Hex inspector offset:")
        hex_lbl.setToolTip("Jump to a byte offset (hex like 0x2c00, or decimal).")
        hex_ctrl.addWidget(hex_lbl)
        self.offset_edit = QLineEdit("0x000000")
        self.offset_edit.setFixedWidth(110)
        self.offset_edit.setToolTip("Jump to a byte offset (hex like 0x2c00, or decimal).")
        hex_ctrl.addWidget(self.offset_edit)
        jump_btn = QPushButton("Jump")
        jump_btn.setObjectName("smallButton")
        jump_btn.clicked.connect(self._jump)
        hex_ctrl.addWidget(jump_btn)
        prev_btn = QPushButton("< Prev 256 B")
        prev_btn.setObjectName("smallButton")
        prev_btn.clicked.connect(lambda: self._page(-256))
        hex_ctrl.addWidget(prev_btn)
        next_btn = QPushButton("Next 256 B >")
        next_btn.setObjectName("smallButton")
        next_btn.clicked.connect(lambda: self._page(256))
        hex_ctrl.addWidget(next_btn)
        hex_ctrl.addStretch(1)
        layout.addLayout(hex_ctrl)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setStyleSheet(
            f"QPlainTextEdit {{ background: {theme.BG_WINDOW}; color: #89dceb; border: none; }}")
        layout.addWidget(self.hex_view, 1)

        self._hex_offset = 0

    # -- entropy ---------------------------------------------------------------
    def _render_entropy(self, w: int, h: int) -> Image.Image:
        raw = self.controller.results["raw_bytes"]
        return carver.render_entropy_plot(raw, width=w, height=h)

    def show_empty_state(self) -> None:
        self.entropy_canvas.set_renderer(None)
        self.entropy_readout.setText("Entropy: run after loading an image")
        self.sig_model.clear()
        self.hex_view.clear()
        self._hex_offset = 0

    def show_results(self, results: dict[str, Any]) -> None:
        self.sig_model.set_signatures(results["signatures"])
        self.entropy_canvas.set_renderer(self._render_entropy)
        overall = carver.shannon_entropy(results["raw_bytes"])
        self.entropy_readout.setText(
            f"Overall entropy: {overall:.3f} bits/byte (scale 0-8). Windows above the "
            "red 7.2 line suggest encrypted or compressed payloads at those offsets.")
        self._display_hex(0)

    # -- hex -------------------------------------------------------------------
    def _display_hex(self, offset: int) -> None:
        if not self.controller.has_image:
            return
        raw = self.controller.results["raw_bytes"]
        self._hex_offset = max(0, min(offset, len(raw) - 1))
        self.hex_view.setPlainText(
            carver.format_hex_dump(raw, offset=self._hex_offset, length=192))
        self.offset_edit.setText(f"0x{self._hex_offset:06x}")

    def _jump(self) -> None:
        text = self.offset_edit.text().strip()
        try:
            offset = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            QMessageBox.warning(self, "Invalid offset",
                                "Enter a valid byte offset in hex (e.g. 0x2c00) or "
                                "decimal (e.g. 11264).")
            return
        self._display_hex(offset)

    def _page(self, delta: int) -> None:
        self._display_hex(self._hex_offset + delta)
