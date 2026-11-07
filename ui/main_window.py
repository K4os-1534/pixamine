"""MainWindow: faithful Qt port of the pre-redesign workspace.

Toolbar (import left, export/cleanup right) -> verdict banner -> the five-tab
notebook (Overview / Metadata / Tampering / Steganography / Structure &
Carving) -> status bar. No menu bar, no docks - exactly the old layout. All
heavy work still runs on worker threads through the controller.
"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ui import theme
from ui.controller import AppController
from ui.tabs import CarverTab, MetadataTab, OverviewTab, SteganographyTab, TamperingTab
from ui.tooltip import Tooltip

IMAGE_FILTER = "Images (*.jpg *.jpeg *.png *.tif *.tiff *.webp *.bmp *.gif);;All files (*)"


class MainWindow(QMainWindow):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        self.setWindowTitle("Pixamine")
        self.setMinimumSize(1024, 700)
        self.resize(1280, 850)

        self._build_toolbar()
        self._build_banner()
        self._build_tabs()
        self._build_statusbar()
        self._connect_controller()

        QShortcut(QKeySequence("Ctrl+O"), self, activated=self._open_dialog)
        self._show_empty_state()

    # -- construction ----------------------------------------------------------
    def _build_toolbar(self) -> None:
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        self.btn_open = QPushButton("Open Image")
        self.btn_open.setObjectName("accentButton")
        self.btn_open.setToolTip("Open an image file for analysis (Ctrl+O). "
                                 "All analyses run automatically on load.")
        self.btn_open.clicked.connect(self._open_dialog)
        layout.addWidget(self.btn_open)
        layout.addStretch(1)

        self.btn_sanitize = QPushButton("Sanitize Copy")
        self.btn_sanitize.setToolTip("Write a metadata-free copy of the loaded image "
                                     "(EXIF, XMP, IPTC, ICC removed).")
        self.btn_sanitize.clicked.connect(self._sanitize)
        layout.addWidget(self.btn_sanitize)

        self.btn_json = QPushButton("JSON Audit")
        self.btn_json.setToolTip("Export a machine-readable JSON audit (scorecard, "
                                 "signatures, metadata) for pipelines and case files.")
        self.btn_json.clicked.connect(self._export_json)
        layout.addWidget(self.btn_json)

        self.btn_report = QPushButton("HTML Report")
        self.btn_report.setToolTip("Generate a self-contained HTML forensic report with "
                                   "embedded analysis images, hashes, and findings.")
        self.btn_report.clicked.connect(self._export_html)
        layout.addWidget(self.btn_report)

        self._toolbar = toolbar  # added as the first row of the central layout

    def _build_banner(self) -> None:
        self.banner = QFrame()
        self.banner.setObjectName("card")
        layout = QHBoxLayout(self.banner)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(4)

        self.score_label = QLabel("--")
        self.score_label.setObjectName("scoreLabel")
        self.score_label.setStyleSheet(f"color: {theme.FG_FAINT};")
        layout.addWidget(self.score_label)
        score_suffix = QLabel("/100")
        score_suffix.setObjectName("mutedLabel")
        layout.addWidget(score_suffix)
        layout.addSpacing(12)
        Tooltip(self.score_label,
                "Heuristic 0-100 authenticity score aggregated over five pillars "
                "(metadata, compression, container, stego, tampering). Not proof  "
                "review the findings.")

        info = QWidget()
        info_layout = QVBoxLayout(info)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(1)

        self.title_label = QLabel("No image loaded")
        self.title_label.setObjectName("valueLabel")
        self.status_label = QLabel("Open an image to start a forensic audit")
        self.status_label.setObjectName("mutedLabel")
        self.hash_label = QLabel("")
        self.hash_label.setObjectName("monoLabel")
        self.caveat_label = QLabel(
            "Heuristic screening: results indicate consistency anomalies, "
            "not proof of authenticity or manipulation.")
        self.caveat_label.setObjectName("caveatLabel")
        self.caveat_label.setWordWrap(True)
        info_layout.addWidget(self.title_label)
        info_layout.addWidget(self.status_label)
        info_layout.addWidget(self.hash_label)
        info_layout.addWidget(self.caveat_label)
        layout.addWidget(info, 1)

        central = QWidget()
        self.central_layout = QVBoxLayout(central)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(8)
        banner_wrap = QWidget()
        banner_layout = QHBoxLayout(banner_wrap)
        banner_layout.setContentsMargins(12, 8, 12, 0)
        banner_layout.addWidget(self.banner)
        self.central_layout.addWidget(self._toolbar)
        self.central_layout.addWidget(banner_wrap)
        self.setCentralWidget(central)

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.overview_tab = OverviewTab(self.controller)
        self.metadata_tab = MetadataTab(self.controller, export_csv=self._export_csv)
        self.tampering_tab = TamperingTab(self.controller)
        self.stego_tab = SteganographyTab(self.controller)
        self.carver_tab = CarverTab(self.controller, carve_action=self._carve)
        self.tabs.addTab(self.overview_tab, "Overview")
        self.tabs.addTab(self.metadata_tab, "Metadata")
        self.tabs.addTab(self.tampering_tab, "Tampering")
        self.tabs.addTab(self.stego_tab, "Steganography")
        self.tabs.addTab(self.carver_tab, "Structure & Carving")
        self.central_layout.addWidget(self.tabs, 1)

    def _build_statusbar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        self.statusbar = QLabel("Ready")
        bar.addWidget(self.statusbar, 1)

    # -- controller wiring ------------------------------------------------------
    def _connect_controller(self) -> None:
        c = self.controller
        c.status.connect(self.statusbar.setText)
        c.analysisStarted.connect(self._on_analysis_started)
        c.progress.connect(lambda stage, frac: self.statusbar.setText(f"Analyzing  {stage}"))
        c.analysisFinished.connect(self._on_analysis_finished)
        c.analysisFailed.connect(self._on_analysis_failed)
        c.mapReady.connect(self._on_map_ready)
        c.mapFailed.connect(self._on_map_failed)
        c.labReady.connect(self._on_lab_ready)
        c.labFailed.connect(self._on_lab_failed)

    # -- state -------------------------------------------------------------------
    def _show_empty_state(self) -> None:
        self.score_label.setText("--")
        self.score_label.setStyleSheet(f"color: {theme.FG_FAINT};")
        self.title_label.setText("No image loaded")
        self.status_label.setText("Open an image to start a forensic audit")
        self.status_label.setStyleSheet(f"color: {theme.FG_MUTED}; background: transparent;")
        self.hash_label.setText("")
        self.overview_tab.show_empty_state()
        self.metadata_tab.show_empty_state()
        self.tampering_tab.show_empty_state()
        self.stego_tab.show_empty_state()
        self.carver_tab.show_empty_state()
        self._set_actions_enabled(False)

    def _set_actions_enabled(self, enabled: bool) -> None:
        for btn in (self.btn_report, self.btn_json, self.btn_sanitize):
            btn.setEnabled(enabled)

    def _on_analysis_started(self, path: str) -> None:
        QApplication.setOverrideCursor(Qt.WaitCursor)
        self._set_actions_enabled(False)

    def _on_analysis_finished(self) -> None:
        QApplication.restoreOverrideCursor()
        results = self.controller.results
        self._set_actions_enabled(True)
        sc = results["scorecard"]
        self.score_label.setText(str(sc.overall_score))
        self.score_label.setStyleSheet(f"color: {sc.color}; background: transparent;")
        self.title_label.setText(os.path.basename(results["path"]))
        self.status_label.setText(sc.status)
        self.status_label.setStyleSheet(f"color: {sc.color}; background: transparent;")
        meta = results["meta"]
        dims = f"{meta.get('Width')}x{meta.get('Height')}"
        fmt = meta.get("Format", "Unknown")
        size = meta.get("FileSize", len(results["raw_bytes"]))
        md5 = meta.get("MD5", "N/A")
        sha = meta.get("SHA256", "N/A")
        self.hash_label.setText(
            f"{fmt} � {dims} px � {size:,} bytes � MD5 {md5} � SHA-256 {sha[:32]}")
        self.overview_tab.show_results(results)
        self.metadata_tab.show_results(results)
        self.stego_tab.show_results(results)
        self.carver_tab.show_results(results)
        self.tampering_tab.select_map("ela")

    def _on_analysis_failed(self, message: str) -> None:
        QApplication.restoreOverrideCursor()
        self._set_actions_enabled(self.controller.has_image)
        QMessageBox.critical(self, "Could not analyze image", message)

    def _on_map_ready(self, key: str) -> None:
        self.tampering_tab.show_map(key)

    def _on_map_failed(self, key: str, reason: str) -> None:
        QApplication.restoreOverrideCursor()
        from ui.controller import MAP_SHORT_NAMES
        QMessageBox.critical(
            self, "Map rendering failed",
            f"The {MAP_SHORT_NAMES.get(key, key)} map could not be rendered.\n\nReason: {reason}")

    def _on_lab_ready(self, name: str) -> None:
        if name == "lsb_report":
            self.stego_tab.show_lsb_report()
        elif name == "lsb_dump":
            self.stego_tab.show_dump_done()

    def _on_lab_failed(self, name: str, reason: str) -> None:
        QMessageBox.critical(self, f"{name} failed", f"Reason: {reason}")

    # -- commands -------------------------------------------------------------------
    def _open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open image", "", IMAGE_FILTER)
        if path:
            self.controller.load(path)

    def _carve(self) -> None:
        if not self.controller.has_image:
            QMessageBox.information(self, "Carve payloads", "Open an image first.")
            return
        out_dir = QFileDialog.getExistingDirectory(
            self, "Select Folder to Carve Embedded Files Into")
        if not out_dir:
            return
        try:
            carved = self.controller.carve_payloads(out_dir)
        except Exception as exc:
            QMessageBox.critical(self, "Carving failed", f"Reason: {exc}")
            return
        if carved:
            msg = f"Carved {len(carved)} payload(s) to:\n{out_dir}\n\n"
            for c in carved:
                msg += f"• {c.name} ({c.size:,} bytes) -> {c.filename}\n"
            QMessageBox.information(self, "Carving complete", msg)
        else:
            QMessageBox.information(self, "Carve payloads",
                                    "No secondary payloads or trailing overlays were found.")
            self.controller.status.emit("No payloads carved")

    def _sanitize(self) -> None:
        if not self.controller.has_image:
            QMessageBox.information(self, "Sanitize copy", "Open an image first.")
            return
        base = os.path.basename(self.controller.path)
        path, _ = QFileDialog.getSaveFileName(
            self, "Sanitize copy", "sanitized_" + base,
            "Clean image (*.jpg *.png *.webp);;All files (*)")
        if not path:
            return
        try:
            self.controller.sanitize_copy(path)
        except Exception as exc:
            QMessageBox.critical(self, "Sanitize failed",
                                 f"Could not write a metadata-free copy.\n\nReason: {exc}")
            return
        QMessageBox.information(self, "Sanitize complete",
                                f"Metadata-free copy saved to:\n{path}")

    def _export_html(self) -> None:
        if not self.controller.has_image:
            QMessageBox.information(self, "HTML report", "Open an image first.")
            return
        base = os.path.splitext(os.path.basename(self.controller.path))[0]
        path, _ = QFileDialog.getSaveFileName(
            self, "HTML report", f"forensic_report_{base}.html",
            "HTML report (*.html);;All files (*)")
        if not path:
            return
        try:
            self.controller.export_report("html", path)
        except Exception as exc:
            QMessageBox.critical(self, "Report generation failed", f"Reason: {exc}")
            return
        QMessageBox.information(self, "Report generated",
                                f"Standalone HTML report saved to:\n{path}")

    def _export_json(self) -> None:
        if not self.controller.has_image:
            QMessageBox.information(self, "JSON audit", "Open an image first.")
            return
        base = os.path.splitext(os.path.basename(self.controller.path))[0]
        path, _ = QFileDialog.getSaveFileName(
            self, "JSON audit", f"metadata_{base}.json", "JSON (*.json);;All files (*)")
        if not path:
            return
        try:
            self.controller.export_report("json", path)
        except Exception as exc:
            QMessageBox.critical(self, "JSON export failed", f"Reason: {exc}")
            return
        QMessageBox.information(self, "JSON exported",
                                f"Forensic audit JSON saved to:\n{path}")

    def _export_csv(self) -> None:
        if not self.controller.has_image:
            QMessageBox.information(self, "CSV export", "Open an image first.")
            return
        base = os.path.splitext(os.path.basename(self.controller.path))[0]
        path, _ = QFileDialog.getSaveFileName(
            self, "CSV export", f"metadata_{base}.csv", "CSV (*.csv);;All files (*)")
        if not path:
            return
        try:
            self.controller.export_metadata_csv(path)
        except Exception as exc:
            QMessageBox.critical(self, "CSV export failed", f"Reason: {exc}")
            return
        QMessageBox.information(self, "CSV exported", f"Metadata saved to:\n{path}")
