"""Orchestration of the forensic analysis pipeline.

The Qt UI calls :func:`analyze_file` from a worker thread; nothing in here
imports any UI toolkit, so algorithms can be run and tested headlessly.
"""

from __future__ import annotations

import time
from typing import Any

from PIL import Image

import carver
import forensics
import metadata_engine
import scoring
import stego
import tamper_analysis


def analyze_file(path: str, progress: Any = None) -> dict[str, Any]:
    """Run the full forensic pipeline on one image and return every result.

    The returned dict carries both the raw artifacts (bytes, PIL image,
    metadata, findings, signatures) and the derived statistics (chi-square,
    SPA, copy-move clusters, scorecard) so callers can build any view or
    report without re-running analysis. ``progress`` is an optional callable
    receiving (stage_name, 0..1) for progress indication.
    """

    def report(stage: str, frac: float) -> None:
        if progress is not None:
            progress(stage, frac)

    started = time.perf_counter()
    report("reading file", 0.05)
    with open(path, "rb") as f:
        raw_bytes = f.read()
    with Image.open(path) as img:
        src_image = img.convert("RGB")

    report("metadata", 0.2)
    meta = metadata_engine.deep_extract_metadata(path)
    report("consistency findings", 0.35)
    findings = forensics.analyze(meta)
    report("binary signatures", 0.45)
    signatures = carver.scan_signatures(raw_bytes)
    _, overlay = carver.detect_overlay(raw_bytes)
    report("steganalysis", 0.6)
    chi_profile, chi2_prob = stego.chi_square_attack(src_image)
    spa_ratio = stego.sample_pair_analysis(src_image)
    report("copy-move detection", 0.8)
    clone = tamper_analysis.detect_copy_move(src_image)
    report("scoring", 0.95)
    scorecard = scoring.evaluate_authenticity(
        meta,
        findings,
        signatures=signatures,
        overlay_size=len(overlay),
        chi2_prob=chi2_prob,
        spa_ratio=spa_ratio,
        clone_clusters=clone.clusters,
    )
    elapsed = time.perf_counter() - started
    report("done", 1.0)
    return {
        "path": path,
        "raw_bytes": raw_bytes,
        "src_image": src_image,
        "meta": meta,
        "findings": findings,
        "signatures": signatures,
        "chi2_prob": chi2_prob,
        "chi_profile": chi_profile,
        "spa_ratio": spa_ratio,
        "clone": clone,
        "elapsed_seconds": elapsed,
        "scorecard": scorecard,
    }
