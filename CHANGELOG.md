# Changelog

## 1.0.0 — 2026-11-07

First open-source release of Pixamine.

### Analysis

- Deep metadata extraction: EXIF, XMP, IPTC, ICC profiles, MakerNotes
  (Nikon/Canon/Apple), PNG/WebP chunks, GPS with map links.
- Consistency findings: timestamp logic, editor/software tags, dimension and
  thumbnail mismatches, JPEG marker anomalies.
- Visual tamper views: ELA (multi-quality, local-background normalized),
  sensor-noise map (median residual + robust MAD + reliability mask),
  block-wise lighting direction, JPEG ghost with best-fit quality
  distribution, embedded-thumbnail diff with SSIM scoring.
- Copy-move detection: SIFT + Lowe ratio test + RANSAC partial-affine
  consensus, spatial-compactness filtering, inverse-direction merge.
  Validated: zero clusters on clean/repetitive textures; detects verbatim and
  rotated/scaled clones.
- Steganalysis: bit planes 0-7, LSB string/payload extraction, Westfeld
  chi-square attack (exact scipy survival function), Dumitrescu-Wu-Wang
  sample pair analysis (calibrated against known embedding rates).
- Binary forensics: sliding-window entropy profile, 31-signature scanner with
  structural validators, trailing-overlay detection, payload carving, hex
  inspector.
- Five-pillar authenticity scorecard with per-finding confidence values and
  limitation notes.

### Application

- PySide6 workstation: Overview, Metadata, Tampering, Steganography, and
  Structure & Carving tabs; zoom/pan image viewer with nearest-neighbor
  pixel inspection; side-by-side comparison and map blending.
- All analysis runs on worker threads; the UI never blocks.
- WCAG 2.1 AA verified dark theme, keyboard navigation, tooltips explaining
  every technical term, plain-language error dialogs.
- Standalone HTML report and machine-readable JSON audit; metadata CSV
  export; metadata-free sanitized copies.
- Deterministic fixture suite and two test harnesses (detector metrics +
  31-check feature verification).
