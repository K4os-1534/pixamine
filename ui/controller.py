"""AppController: the central state layer between analysis and UI.

Owns the session state (loaded results, rendered maps) and dispatches all
heavy work to worker threads. Views never call analysis code directly - they
connect to the controller's signals and call its methods.
"""

from __future__ import annotations

import os
import webbrowser
from typing import Any

import numpy as np
from PIL import Image
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QImage, QPixmap

import carver
import metadata_engine
import reporting
import tamper_analysis
from ui.workers import AnalysisWorker, LabWorker, MapWorker


def pil_to_pixmap(img: Image.Image) -> QPixmap:
    """Convert a PIL image to QPixmap (RGB888; NumPy copy keeps alignment)."""
    img = img.convert("RGB")
    arr = np.asarray(img)  # (h, w, 3) uint8
    h, w, _ = arr.shape
    qimg = QImage(arr.data, w, h, 3 * w, QImage.Format_RGB888)
    return QPixmap.fromImage(qimg)


# Analysis map registry: (key, combo label, colormap, quality, blend, compare).
# Capability flags drive the per-map control states exactly as before.
MAP_MODES = [
    ("ela", "Error Level Analysis (ELA)", True, True, True, True),
    ("clone", "Copy-Move (Clone) Detection", False, False, True, True),
    ("lighting", "Luminance Gradient (Lighting Angle)", False, False, True, True),
    ("noise", "Sensor Noise Variance Map", True, False, True, True),
    ("ghost", "JPEG Ghost Map", True, False, True, True),
    ("thumb", "Embedded Thumbnail Diff", False, False, False, False),
]
MAP_LABEL_TO_KEY = {label: key for key, label, *_ in MAP_MODES}

# Per-mode tooltip for the map selector (accurate for the current detectors).
MAP_TOOLTIPS = {
    "ela": "ELA re-saves the image and highlights regions whose compression error "
           "differs from their neighborhood. Edited regions often stand out.",
    "clone": "Detects duplicated regions pasted within the same image. Only "
             "geometrically verified clusters (RANSAC) are outlined.",
    "lighting": "Dominant lighting direction per block; conflicting hues on "
                "adjacent surfaces hint at compositing.",
    "noise": "Shows local noise strength. Composite images often mix regions "
             "with inconsistent sensor noise. Flat areas are dimmed.",
    "ghost": "Farid-style JPEG ghost analysis: regions that fit an earlier "
             "compression level unusually well stand out.",
    "thumb": "Cameras embed a small preview at capture time. Editors that "
             "re-save pixels often leave the original thumbnail behind.",
}

MAP_SHORT_NAMES = {
    "ela": "ELA",
    "clone": "copy-move",
    "lighting": "lighting",
    "noise": "noise",
    "ghost": "JPEG ghost",
    "thumb": "thumbnail diff",
}


class AppController(QObject):
    """Central session state + work dispatch. One instance per app run."""

    analysisStarted = Signal(str)
    progress = Signal(str, float)
    analysisFinished = Signal()
    analysisFailed = Signal(str)
    mapReady = Signal(str)           # map key
    mapFailed = Signal(str, str)
    labReady = Signal(str)           # job name
    labFailed = Signal(str, str)
    status = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.path: str | None = None
        self.results: dict[str, Any] | None = None
        self.maps: dict[str, Any] = {}          # key -> MapResult / CloneResult
        self.active_view: str = "ela"
        self.ela_quality: int = 90
        self.colormap: str = "inferno"
        self.compare: bool = True
        self.blend: float = 100.0
        self._analysis_worker: AnalysisWorker | None = None
        self._map_worker: MapWorker | None = None
        self._lab_workers: list[LabWorker] = []
        self._lab_results: dict[str, Any] = {}

    # -- state helpers -------------------------------------------------------
    @property
    def has_image(self) -> bool:
        return self.results is not None

    @property
    def src_image(self) -> Image.Image | None:
        return self.results["src_image"] if self.results else None

    @property
    def meta(self) -> dict[str, Any]:
        return self.results["meta"] if self.results else {}

    def clear(self) -> None:
        self.path = None
        self.results = None
        self.maps = {}
        self.active_view = "ela"
        self._lab_results = {}

    # -- analysis ------------------------------------------------------------
    def load(self, path: str) -> None:
        if self._analysis_worker is not None and self._analysis_worker.isRunning():
            self.status.emit("Busy — wait for the current analysis to finish")
            return
        if not os.path.isfile(path):
            self.analysisFailed.emit(f"File not found: {path}")
            return
        self.clear()
        self.status.emit(f"Analyzing {os.path.basename(path)} …")
        self.analysisStarted.emit(path)
        self._analysis_worker = AnalysisWorker(path, self)
        self._analysis_worker.progress.connect(self.progress)
        self._analysis_worker.finished_ok.connect(self._on_analysis_done)
        self._analysis_worker.failed.connect(self._on_analysis_failed)
        self._analysis_worker.start()

    def _on_analysis_done(self, results: dict[str, Any]) -> None:
        self.results = results
        self.path = results["path"]
        self.maps = {}
        elapsed = results.get("elapsed_seconds")
        n_sigs = len(results["signatures"])
        n_risks = len(results["scorecard"].risk_factors)
        self.analysisFinished.emit()
        self.status.emit(
            f"Analysis of {os.path.basename(self.path)} complete in {elapsed:.1f}s · "
            f"{n_sigs} binary signature match(es) · {n_risks} risk factor(s)"
        )

    def _on_analysis_failed(self, message: str) -> None:
        self.analysisFailed.emit(message)
        self.status.emit("Ready")

    # -- map rendering -------------------------------------------------------
    def request_map(self, key: str) -> None:
        """Render the requested analysis map (worker thread, cached)."""
        if not self.has_image:
            return
        self.active_view = key
        if key in self.maps:
            self.mapReady.emit(key)
            return
        if self._map_worker is not None and self._map_worker.isRunning():
            self.status.emit("Busy — wait for the current map to finish")
            return

        src = self.src_image
        cmap = self.colormap
        quality = self.ela_quality

        if key == "ela":
            func = lambda: tamper_analysis.enhanced_ela_map(src, quality=quality, colormap=cmap)
        elif key == "clone":
            func = lambda: tamper_analysis.detect_copy_move(src)
        elif key == "lighting":
            func = lambda: tamper_analysis.luminance_gradient_map(src)
        elif key == "noise":
            func = lambda: tamper_analysis.noise_variance_map(src, colormap=cmap)
        elif key == "ghost":
            func = lambda: tamper_analysis.jpeg_ghost_map(src, colormap=cmap)
        elif key == "thumb":
            thumb_bytes = self.meta.get("_thumbnail_bytes")
            func = lambda: tamper_analysis.render_thumbnail_diff(src, thumb_bytes)
        else:
            return

        self.status.emit(f"Rendering {MAP_SHORT_NAMES.get(key, key)} map …")
        self._map_worker = MapWorker(key, func, self)
        self._map_worker.finished_ok.connect(self._on_map_done)
        self._map_worker.failed.connect(self._on_map_failed)
        self._map_worker.start()

    def _on_map_done(self, key: str, result: Any) -> None:
        self.maps[key] = result
        self.mapReady.emit(key)
        self.status.emit("Ready")

    def _on_map_failed(self, key: str, reason: str) -> None:
        self.mapFailed.emit(key, reason)
        self.status.emit("Map rendering failed")

    def invalidate_maps(self, keys: list[str]) -> None:
        """Drop cached maps (colormap/quality changed) and re-render the active one."""
        for k in keys:
            self.maps.pop(k, None)
        self.request_map(self.active_view)

    # -- labs ----------------------------------------------------------------
    def run_lab(self, name: str, func: Any) -> None:
        """Run a small lab job on a worker thread; results via labReady + lab_result."""
        worker = LabWorker(name, func, self)
        worker.finished_ok.connect(self._on_lab_done)
        worker.failed.connect(self._on_lab_failed)
        self._lab_workers.append(worker)
        worker.finished.connect(lambda: self._lab_workers.remove(worker))
        worker.start()

    def _on_lab_done(self, name: str, payload: Any) -> None:
        self._lab_results[name] = payload
        self.labReady.emit(name)
        self.status.emit("Ready")

    def lab_result(self, name: str) -> Any:
        return self._lab_results.get(name)

    def _on_lab_failed(self, name: str, reason: str) -> None:
        self.labFailed.emit(name, reason)
        self.status.emit(f"{name} failed")

    # -- actions -------------------------------------------------------------
    def carve_payloads(self, out_dir: str) -> list:
        carved = carver.carve_files(
            self.results["raw_bytes"], out_dir,
            base_name=os.path.splitext(os.path.basename(self.path))[0])
        self.status.emit(f"Carved {len(carved)} payload(s) to {out_dir}")
        return carved

    def sanitize_copy(self, out_path: str) -> None:
        metadata_engine.strip_all_metadata(self.path, out_path)
        self.status.emit(f"Sanitized copy saved to {os.path.basename(out_path)}")

    def export_report(self, kind: str, out_path: str) -> None:
        results = self.results
        if kind == "html":
            reporting.generate_html_report(
                self.path, results["meta"], results["scorecard"],
                results["signatures"], out_path)
        else:
            reporting.generate_json_report(
                self.path, results["meta"], results["scorecard"],
                results["signatures"], out_path)
        self.status.emit(f"{kind.upper()} report saved to {os.path.basename(out_path)}")

    def export_metadata_csv(self, out_path: str) -> None:
        metadata_engine.export_metadata_csv(self.meta, out_path)
        self.status.emit(f"Metadata CSV saved to {os.path.basename(out_path)}")

    def open_map_link(self) -> None:
        url = self.meta.get("GPS:OpenStreetMap")
        if url:
            webbrowser.open(url)
