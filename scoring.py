"""Forensic scoring & authenticity assessment engine.

Aggregates independent evidence into a five-pillar scorecard:
1. Metadata & provenance consistency   (timestamp/camera-tag heuristics)
2. Compression consistency             (quantization tables)
3. Container integrity                 (trailing data, embedded payloads)
4. Steganography risk                  (chi-square + sample pair analysis)
5. Visual tampering risk               (copy-move clusters)

Evidence-based deductions are scaled by a per-signal confidence value so a
weak indicator deducts little. Thresholds were calibrated on the fixture set
in tests/fixtures.py (known authentic + known manipulated samples): e.g. clean
images score SPA ≤ 0.08 and χ² ≤ 0.05, scattered 30% LSB payloads score SPA
≈ 0.36, sequential 35% payloads score χ² ≈ 0.35.

Noise-inconsistency auto-flagging is deliberately NOT included: validation
showed adjacent-block noise conflict cannot separate spliced from natural
imagery on compressed content, and the noise map stays a visual tool with
honest limitation notes instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from forensics import Finding


@dataclass
class ForensicScorecard:
    overall_score: int  # 0 to 100
    status: str         # CLEAN, LOW_RISK, SUSPICIOUS, LIKELY_TAMPERED
    color: str          # UI color hex (AA contrast on dark backgrounds)
    metadata_score: int
    compression_score: int
    container_score: int
    stego_score: int
    tamper_score: int
    risk_factors: list[dict[str, Any]] = field(default_factory=list)


def _finding_bucket(title_lower: str) -> str:
    if any(w in title_lower for w in ("editor", "software", "photoshop", "gimp", "mismatch", "modified")):
        return "meta"
    if any(w in title_lower for w in ("quality", "quantization", "ijg", "compression")):
        return "comp"
    if any(w in title_lower for w in ("trailing", "marker", "container", "payload")):
        return "cont"
    return "meta"


def evaluate_authenticity(
    meta: dict[str, Any],
    findings: list[Finding],
    signatures: list[Any] | None = None,
    overlay_size: int = 0,
    chi2_prob: float = 0.0,
    spa_ratio: float = 0.0,
    clone_clusters: list[Any] | None = None,
) -> ForensicScorecard:
    """Calculate the structured forensic authenticity scorecard.

    Every evidence-based deduction is scaled by a confidence value (0-1) that
    reflects how strongly the underlying signal fired relative to its
    calibrated clean-image baseline.
    """
    meta_deductions = 0
    comp_deductions = 0
    cont_deductions = 0
    stego_deductions = 0
    tamper_deductions = 0
    risk_factors: list[dict[str, Any]] = []

    # 1. Metadata findings (severity-based; these are heuristic, no confidence)
    for f in findings:
        sev = f.severity.lower()
        pts = {"alert": 25, "warn": 12}.get(sev, 3)
        bucket = _finding_bucket(f.title.lower())
        if bucket == "meta":
            meta_deductions += pts
        elif bucket == "comp":
            comp_deductions += pts
        elif bucket == "cont":
            cont_deductions += pts
        else:
            meta_deductions += pts
        if sev in ("alert", "warn"):
            risk_factors.append({
                "severity": "CRITICAL" if sev == "alert" else "WARNING",
                "category": f.title,
                "detail": f.detail,
                "confidence": None,
            })

    # 2. Container & embedded payload risks (structural facts: confidence 1.0)
    if overlay_size > 0:
        cont_deductions += 35
        risk_factors.append({
            "severity": "CRITICAL",
            "category": "Trailing Overlay",
            "detail": f"{overlay_size:,} bytes of data detected past the image's "
                      "legitimate end-of-file",
            "confidence": 1.0,
        })

    suspicious_sigs = [
        s for s in (signatures or [])
        if getattr(s, "category", "") in ("Archive", "Executable", "Crypto")
    ]
    if suspicious_sigs:
        cont_deductions += 30
        stego_deductions += 20
        sig_names = ", ".join(s.name for s in suspicious_sigs[:3])
        risk_factors.append({
            "severity": "CRITICAL",
            "category": "Embedded Payload Structure",
            "detail": f"Detected embedded binary structures: {sig_names}",
            "confidence": 1.0,
        })

    # 3. Steganography risk — combine the two independent signals.
    #    chi-square detects sequential embedding (calibrated clean baseline
    #    ≤ 0.05); SPA estimates scattered payload rate (clean baseline ≤ 0.08).
    seq_conf = max(0.0, min(1.0, (chi2_prob - 0.15) / 0.45)) if chi2_prob > 0.15 else 0.0
    scat_conf = max(0.0, min(1.0, (spa_ratio - 0.08) / 0.25)) if spa_ratio > 0.08 else 0.0
    stego_conf = max(seq_conf, scat_conf)
    if stego_conf > 0.0:
        stego_signal = ("sequential LSB embedding (χ²)" if seq_conf >= scat_conf
                        else "scattered LSB payload (sample-pair analysis)")
        stego_deductions += round(65 * stego_conf) if stego_conf >= 0.5 else round(30 * stego_conf)
        if stego_conf >= 0.8:
            stego_deductions += 15
        risk_factors.append({
            "severity": "CRITICAL" if stego_conf >= 0.6 else "WARNING",
            "category": "LSB Steganography Indicators",
            "detail": f"{stego_signal}: χ² probability {chi2_prob:.2f}, "
                      f"estimated scattered payload rate {spa_ratio * 100:.0f}%. "
                      "Statistical indicators — verify with LSB extraction.",
            "confidence": round(stego_conf, 2),
        })

    # 4. Copy-move forgery risk — RANSAC-verified clusters with their own
    #    confidence values from the detector.
    clusters = list(clone_clusters or [])
    if clusters:
        best = max(clusters, key=lambda c: getattr(c, "confidence", 0.0))
        conf = float(getattr(best, "confidence", 0.0))
        if conf > 0.0:
            tamper_deductions += round(45 * conf) if conf >= 0.45 else round(20 * conf)
            risk_factors.append({
                "severity": "CRITICAL" if conf >= 0.45 else "WARNING",
                "category": "Copy-Move (Clone) Detection",
                "detail": best.describe() + ". Geometrically verified duplicated "
                          "region — review the outlined areas in the copy-move view.",
                "confidence": round(conf, 2),
            })
            if len(clusters) > 1:
                risk_factors[-1]["detail"] += (
                    f" ({len(clusters)} distinct clone events detected.)")

    # Pillar scores (clamped 0 to 100)
    score_meta = max(0, 100 - meta_deductions)
    score_comp = max(0, 100 - comp_deductions)
    score_cont = max(0, 100 - cont_deductions)
    score_stego = max(0, 100 - stego_deductions)
    score_tamper = max(0, 100 - tamper_deductions)

    overall = int(
        0.25 * score_meta
        + 0.20 * score_comp
        + 0.25 * score_cont
        + 0.15 * score_stego
        + 0.15 * score_tamper
    )

    # Strong evidence overrides the pillar average: one CRITICAL finding with
    # confidence ≥ 0.5 forces the verdict below CLEAN regardless of how well
    # the other pillars score.
    has_strong_evidence = any(
        rf["severity"] == "CRITICAL"
        and (rf.get("confidence") or 0.0) >= 0.5
        for rf in risk_factors
    )
    if has_strong_evidence:
        overall = min(overall, 69)

    if overall >= 85:
        status = "CLEAN / VERIFIED CONSISTENT"
        color = "#4ade80"  # Green (AA contrast on the dark UI)
    elif overall >= 70:
        status = "LOW RISK / MINOR ANOMALIES"
        color = "#60a5fa"  # Blue
    elif overall >= 45:
        status = "SUSPICIOUS / INCONSISTENCIES FOUND"
        color = "#fbbf24"  # Amber
    else:
        status = "LIKELY TAMPERED / FORGED"
        color = "#f87171"  # Red

    return ForensicScorecard(
        overall_score=overall,
        status=status,
        color=color,
        metadata_score=score_meta,
        compression_score=score_comp,
        container_score=score_cont,
        stego_score=score_stego,
        tamper_score=score_tamper,
        risk_factors=risk_factors,
    )
