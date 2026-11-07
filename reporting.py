"""Forensic report generator (standalone HTML dossier & machine-readable JSON).

Generates self-contained reports with:
- Authenticity scorecard and risk factors
- Embedded visual analyses (ELA, noise, bit-plane 0, entropy plot)
- Chain-of-custody hashes (MD5, SHA-256)
- Full metadata table
- Binary signature analysis
"""

from __future__ import annotations

import base64
import io
import json
import os
from datetime import datetime
from typing import Any

from PIL import Image

from carver import render_entropy_plot
from scoring import ForensicScorecard
from stego import slice_bit_plane
from tamper_analysis import enhanced_ela_map, noise_variance_map


def _image_to_base64_data_uri(img: Image.Image, format: str = "PNG") -> str:
    """Encode a PIL Image into a base64 Data URI.

    Tamper-map detectors return MapResult wrappers; their visualization
    lives in the ``image`` attribute, so accept either form.
    """
    if hasattr(img, "image"):
        img = img.image
    buf = io.BytesIO()
    img.save(buf, format=format)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/{format.lower()};base64,{encoded}"


def generate_json_report(
    path: str,
    meta: dict[str, Any],
    scorecard: ForensicScorecard,
    signatures: list[Any],
    output_path: str,
) -> None:
    """Generate structured JSON forensic audit file."""
    def default_serializer(o: Any) -> Any:
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, bytes):
            return f"<binary: {len(o)} bytes>"
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)

    clean_meta = {k: v for k, v in meta.items() if not k.startswith("_")}
    sig_dicts = [
        {"offset": s.offset, "name": s.name, "category": s.category, "desc": s.description}
        for s in signatures
    ]

    report = {
        "report_generated": datetime.now().isoformat(),
        "target_file": os.path.basename(path),
        "file_path": os.path.abspath(path),
        "hashes": {"md5": meta.get("MD5"), "sha256": meta.get("SHA256")},
        "scorecard": {
            "overall_score": scorecard.overall_score,
            "status": scorecard.status,
            "metadata_score": scorecard.metadata_score,
            "compression_score": scorecard.compression_score,
            "container_score": scorecard.container_score,
            "stego_score": scorecard.stego_score,
            "tamper_score": scorecard.tamper_score,
            "risk_factors": scorecard.risk_factors,
        },
        "embedded_signatures": sig_dicts,
        "metadata": clean_meta,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, default=default_serializer, indent=2)


def generate_html_report(
    path: str,
    meta: dict[str, Any],
    scorecard: ForensicScorecard,
    signatures: list[Any],
    output_path: str,
) -> None:
    """Generate a sleek, standalone dark-themed HTML forensic report."""
    with open(path, "rb") as f:
        raw_bytes = f.read()

    with Image.open(path) as img:
        orig_img = img.convert("RGB")

    # Generate embedded visuals
    thumb_orig = orig_img.copy()
    thumb_orig.thumbnail((480, 320))
    uri_orig = _image_to_base64_data_uri(thumb_orig, "JPEG")

    ela_img = enhanced_ela_map(thumb_orig, quality=90, colormap="inferno")
    uri_ela = _image_to_base64_data_uri(ela_img, "PNG")

    noise_img = noise_variance_map(thumb_orig)
    uri_noise = _image_to_base64_data_uri(noise_img, "PNG")

    bit0_img = slice_bit_plane(thumb_orig, plane=0, channel="RGB")
    uri_bit0 = _image_to_base64_data_uri(bit0_img, "PNG")

    entropy_img = render_entropy_plot(raw_bytes, width=760, height=220)
    uri_entropy = _image_to_base64_data_uri(entropy_img, "PNG")

    # Build Risk Factors HTML (badge colors meet WCAG AA with white text)
    risk_html = ""
    if scorecard.risk_factors:
        for rf in scorecard.risk_factors:
            badge_color = "#b91c1c" if rf["severity"] == "CRITICAL" else "#b45309"
            conf = rf.get("confidence")
            conf_html = (f" <span style='color:#94a3b8; font-size:11px;'>confidence "
                         f"{conf * 100:.0f}%</span>") if conf is not None else ""
            risk_html += f"""
            <div class="risk-card" style="border-left: 4px solid {badge_color};">
                <span class="badge" style="background: {badge_color};">{rf['severity']}</span>
                <strong>{rf['category']}</strong>{conf_html}: {rf['detail']}
            </div>
            """
    else:
        risk_html = "<div class='clean-note'>No metadata or container anomalies detected.</div>"

    # Build Signatures HTML
    sig_rows = ""
    for s in signatures:
        sig_rows += f"""
        <tr>
            <td class="mono">0x{s.offset:06x}</td>
            <td><span class="badge category">{s.category}</span></td>
            <td><strong>{s.name}</strong></td>
            <td>{s.description}</td>
        </tr>
        """
    if not sig_rows:
        sig_rows = "<tr><td colspan='4'>No secondary signatures or trailing payloads detected.</td></tr>"

    # Build Metadata Table
    meta_rows = ""
    clean_meta = {k: v for k, v in meta.items() if not k.startswith("_")}
    for k in sorted(clean_meta.keys()):
        val = str(clean_meta[k])
        # Format links if GPS
        if k in ("GPS:OpenStreetMap", "GPS:GoogleMaps"):
            val = f"<a href='{val}' target='_blank' style='color:#38bdf8;'>Open Map Coordinates &rarr;</a>"
        meta_rows += f"<tr><td class='tag-name'>{k}</td><td class='tag-val mono'>{val}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forensic Report: {os.path.basename(path)}</title>
<style>
:root {{
    --bg: #0f172a;
    --card: #1e293b;
    --card-border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #06b6d4;
}}
body {{
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
}}
.container {{
    max-width: 1200px;
    margin: 0 auto;
}}
.header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--card-border);
    padding-bottom: 16px;
    margin-bottom: 24px;
}}
.header h1 {{
    margin: 0;
    font-size: 24px;
    letter-spacing: -0.5px;
}}
.timestamp {{
    color: var(--text-muted);
    font-size: 13px;
}}
.score-banner {{
    display: flex;
    align-items: center;
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
    gap: 24px;
}}
.score-dial {{
    font-size: 48px;
    font-weight: 800;
    color: {scorecard.color};
    min-width: 120px;
    text-align: center;
}}
.score-info h2 {{
    margin: 0 0 6px 0;
    font-size: 20px;
    color: {scorecard.color};
}}
.score-pillars {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-top: 12px;
}}
.pillar {{
    background: rgba(0,0,0,0.25);
    padding: 8px;
    border-radius: 4px;
    text-align: center;
    font-size: 12px;
}}
.pillar-val {{
    font-weight: bold;
    font-size: 14px;
}}
.section-title {{
    font-size: 18px;
    margin: 28px 0 14px 0;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.grid-2 {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
}}
.grid-4 {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
}}
.card {{
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 16px;
}}
.card h3 {{
    margin: 0 0 12px 0;
    font-size: 14px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.img-panel {{
    text-align: center;
    background: #000;
    border-radius: 4px;
    overflow: hidden;
}}
.img-panel img {{
    max-width: 100%;
    height: auto;
    display: block;
}}
.img-caption {{
    font-size: 11px;
    color: var(--text-muted);
    padding: 6px;
    background: rgba(0,0,0,0.6);
}}
.risk-card {{
    background: rgba(0,0,0,0.3);
    padding: 10px 14px;
    border-radius: 4px;
    margin-bottom: 8px;
    font-size: 13px;
}}
.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    color: #fff;
    margin-right: 6px;
}}
.badge.category {{
    background: #334155;
    color: #38bdf8;
}}
.clean-note {{
    color: #22c55e;
    font-size: 14px;
    padding: 8px 0;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
th, td {{
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--card-border);
}}
th {{
    background: rgba(0,0,0,0.3);
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
}}
.mono {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
}}
.tag-name {{
    color: #38bdf8;
    width: 260px;
}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>Forensic Inspection Report</h1>
            <div class="timestamp">Target: <strong style="color:#fff;">{os.path.basename(path)}</strong> | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
        </div>
        <div class="mono" style="font-size:12px; color:var(--text-muted); text-align:right;">
            <div>MD5: {meta.get('MD5', 'N/A')}</div>
            <div>SHA256: {meta.get('SHA256', 'N/A')[:32]}...</div>
        </div>
    </div>

    <div class="score-banner">
        <div class="score-dial">{scorecard.overall_score}<span style="font-size:20px; color:var(--text-muted);">/100</span></div>
        <div class="score-info" style="flex:1;">
            <h2>{scorecard.status}</h2>
            <div style="font-size:13px; color:var(--text-muted);">Heuristic assessment aggregated over five pillars: metadata consistency, compression tables, container structure, steganography statistics, and pixel tampering. Scores indicate anomalies to review, not proof of authenticity or manipulation.</div>
            <div class="score-pillars">
                <div class="pillar"><div>Metadata</div><div class="pillar-val">{scorecard.metadata_score}%</div></div>
                <div class="pillar"><div>Compression</div><div class="pillar-val">{scorecard.compression_score}%</div></div>
                <div class="pillar"><div>Container</div><div class="pillar-val">{scorecard.container_score}%</div></div>
                <div class="pillar"><div>Stego</div><div class="pillar-val">{scorecard.stego_score}%</div></div>
                <div class="pillar"><div>Tampering</div><div class="pillar-val">{scorecard.tamper_score}%</div></div>
            </div>
        </div>
    </div>

    <div class="card" style="margin-bottom:24px;">
        <h3>Forensic Risk Factors &amp; Inconsistencies</h3>
        {risk_html}
    </div>

    <div class="section-title">Visual Forensics &amp; Tamper Analysis</div>
    <div class="grid-4">
        <div class="img-panel">
            <img src="{uri_orig}" alt="Source Image">
            <div class="img-caption">Source Preview ({meta.get('Width')}x{meta.get('Height')})</div>
        </div>
        <div class="img-panel">
            <img src="{uri_ela}" alt="ELA Heatmap">
            <div class="img-caption">Error Level Analysis (Inferno Heatmap)</div>
        </div>
        <div class="img-panel">
            <img src="{uri_noise}" alt="Noise Variance">
            <div class="img-caption">Sensor Noise Variance Map</div>
        </div>
        <div class="img-panel">
            <img src="{uri_bit0}" alt="Bit-Plane 0">
            <div class="img-caption">Least Significant Bit (Plane 0)</div>
        </div>
    </div>
    <div class="card" style="margin-top:16px; margin-bottom:24px; font-size:12px; color:var(--text-muted);">
        Limitations: these visual analyses are indicators, not proof. Flat regions,
        heavy recompression, repetitive textures, and multiple exports can produce
        false positives on ELA, noise, and ghost maps; LSB plane structure is normal
        for natural images. Interpret findings together, and keep the original file
        (hashes above) for verification.
    </div>

    <div class="section-title">Binary Entropy &amp; Embedded Payloads</div>
    <div class="card" style="margin-bottom:24px;">
        <div class="img-panel" style="margin-bottom:16px;">
            <img src="{uri_entropy}" alt="Shannon Entropy Profile">
        </div>
        <h3>Detected Signatures &amp; Embedded Payloads</h3>
        <table>
            <thead>
                <tr>
                    <th>Offset</th>
                    <th>Category</th>
                    <th>Payload Name</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {sig_rows}
            </tbody>
        </table>
    </div>

    <div class="section-title">Deep Metadata &amp; Device Fingerprints</div>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>Tag</th>
                    <th>Extracted Value</th>
                </tr>
            </thead>
            <tbody>
                {meta_rows}
            </tbody>
        </table>
    </div>
</div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
