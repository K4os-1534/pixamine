"""Run every detector over the fixture set and dump one metrics JSON.

Usage:  python tests/run_metrics.py <output.json> [--label before|after]

This is the before/after validation harness for the algorithm overhaul.
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import numpy as np
from PIL import Image

import pipeline
import stego
import tamper_analysis
from tests.fixtures import FIXTURE_TRUTH, generate_all, SECRET_MESSAGE


def clone_metrics(img: Image.Image) -> dict:
    """Run the copy-move detector and record raw match statistics."""
    start = time.perf_counter()
    result = tamper_analysis.detect_copy_move(img)
    elapsed = time.perf_counter() - start
    return {
        "clusters": len(result.clusters),
        "confidence": None if result.confidence is None else round(result.confidence, 2),
        "details": [c.describe() for c in result.clusters],
        "seconds": round(elapsed, 2),
    }


def stego_metrics(img: Image.Image) -> dict:
    _, chi2 = stego.chi_square_attack(img)
    spa = stego.sample_pair_analysis(img)
    raw = stego.extract_lsb_bytes(img, channels="RGB", bits_per_channel=1, max_bytes=65536)
    report = stego.inspect_lsb_payload(raw)
    found = any(SECRET_MESSAGE[:20] in s for s in report["strings"])
    return {
        "chi2_prob": round(chi2, 3),
        "spa_ratio": round(spa, 3),
        "lsb_strings_found": found,
        "lsb_entropy": round(report["entropy"], 2),
    }


def noise_contrast(img: Image.Image) -> dict:
    """Mean noise-residual energy on left vs right half (splice sensitivity)."""
    from scipy import ndimage

    gray = np.asarray(img.convert("L"), dtype=np.float32)
    residual = gray - ndimage.median_filter(gray, size=5)
    energy = np.abs(residual).mean(axis=0)
    mid = energy.shape[0] // 2
    left, right = float(energy[:mid].mean()), float(energy[mid:].mean())
    return {
        "left_mean": round(left, 2),
        "right_mean": round(right, 2),
        "ratio": round(max(left, right) / max(min(left, right), 1e-6), 3),
    }


def ela_mean(img: Image.Image, quality: int = 90) -> float:
    """Mean ELA difference amplitude — high on recompressed images (FP check)."""
    import io

    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = np.asarray(Image.open(buf).convert("RGB"), dtype=np.float32)
    src = np.asarray(img.convert("RGB"), dtype=np.float32)
    return round(float(np.abs(src - resaved).mean()), 2)


def run(out_path: str, label: str) -> dict:
    paths = generate_all()
    results: dict[str, dict] = {}
    for name, path in paths.items():
        started = time.perf_counter()
        res = pipeline.analyze_file(path)
        img = res["src_image"]
        sc = res["scorecard"]
        entry = {
            "expected": FIXTURE_TRUTH.get(name, "?"),
            "overall_score": sc.overall_score,
            "status": sc.status,
            "pillars": {
                "meta": sc.metadata_score,
                "comp": sc.compression_score,
                "cont": sc.container_score,
                "stego": sc.stego_score,
                "tamper": sc.tamper_score,
            },
            "n_risk_factors": len(sc.risk_factors),
            "risk_confidences": [
                rf.get("confidence") for rf in sc.risk_factors
            ],
            "chi2_prob": round(res["chi2_prob"], 3),
            "spa_ratio": round(res["spa_ratio"], 3),
            "clone": clone_metrics(img),
            "stego_strings": stego_metrics(img)["lsb_strings_found"],
            "noise_contrast": noise_contrast(img),
            "ela_mean_q90": ela_mean(img),
            "seconds": round(time.perf_counter() - started, 2),
        }
        results[name] = entry
        print(f"[{label}] {name:18} score={entry['overall_score']:3} "
              f"chi2={entry['chi2_prob']:.2f} spa={entry['spa_ratio']:.2f} "
              f"clusters={entry['clone']['clusters']}(conf={entry['clone']['confidence']}) "
              f"strings={entry['stego_strings']} risks={entry['n_risk_factors']}")

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"wrote {out_path}")
    return results


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/forensics-baseline2/metrics.json"
    label = sys.argv[2] if len(sys.argv) > 2 else "run"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    run(out, label)
