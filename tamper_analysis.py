"""Visual tampering & forgery detection engine.

Design principles (applied to every detector):
- Use robust statistics (median residual, percentile normalization, block
  coherence) so natural textures and recompression stop producing false
  positives.
- Return a MapResult carrying the visualization plus an honest confidence
  value and limitation notes, so results are never presented as proof.
- Prefer established building blocks: scipy.ndimage filters for residual and
  block statistics, OpenCV SIFT + RANSAC for copy-move detection.

Detectors:
- ELA: multi-quality median difference with local-background normalization.
- Noise: median-filter residual, robust local noise (MAD), reliability mask.
- Lighting: block-wise dominant gradient angle with coherence gating.
- JPEG ghost: min recompression difference + best-quality distribution.
- Copy-move: SIFT keypoints, Lowe ratio test, translation clustering,
  RANSAC affine verification (robust to rotation/scale of the cloned patch).
- Thumbnail diff: embedded EXIF thumbnail vs resized image + SSIM score.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

import cv2
import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageOps
from scipy import ndimage


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------
@dataclass
class MapResult:
    """Visualization plus honest confidence and limitation notes."""

    image: Image.Image
    confidence: float | None = None   # 0..1, None when not meaningful
    notes: list[str] = field(default_factory=list)
    legend: str = ""

    @property
    def confidence_percent(self) -> str:
        return "--" if self.confidence is None else f"{self.confidence * 100:.0f}%"


def _rgb(image: Image.Image, max_side: int | None = None) -> Image.Image:
    img = image.convert("RGB")
    if max_side and max(img.size) > max_side:
        img = img.copy()
        img.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
    return img


def _luma(img: Image.Image) -> np.ndarray:
    """Perceptual-ish luminance (Rec. 601), float32."""
    arr = np.asarray(img.convert("RGB"), dtype=np.float32)
    return arr[:, :, 0] * 0.299 + arr[:, :, 1] * 0.587 + arr[:, :, 2] * 0.114


def _resave(img: Image.Image, quality: int) -> np.ndarray:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=int(quality))
    buf.seek(0)
    return np.asarray(Image.open(buf).convert("RGB"), dtype=np.float32)


def _percentile_normalize(arr: np.ndarray, low_pct: float = 1.0, high_pct: float = 99.0) -> np.ndarray:
    """Stretch to 0..255 using robust percentiles (immune to outliers)."""
    lo, hi = np.percentile(arr, [low_pct, high_pct])
    if hi - lo < 1e-6:
        return np.zeros_like(arr, dtype=np.uint8)
    return np.clip((arr - lo) / (hi - lo) * 255.0, 0, 255).astype(np.uint8)


def _apply_colormap(gray_arr: np.ndarray, colormap: str = "inferno") -> Image.Image:
    """Map a uint8 grayscale array to a false-color RGB heatmap."""
    normalized = gray_arr.astype(np.float32) / 255.0

    if colormap == "jet":
        r = np.clip(1.5 - np.abs(4.0 * normalized - 3.0), 0.0, 1.0)
        g = np.clip(1.5 - np.abs(4.0 * normalized - 2.0), 0.0, 1.0)
        b = np.clip(1.5 - np.abs(4.0 * normalized - 1.0), 0.0, 1.0)
    elif colormap == "viridis":
        r = np.clip(0.28 + 0.72 * normalized**2, 0.0, 1.0)
        g = np.clip(normalized * 1.1 - 0.1 * normalized**3, 0.0, 1.0)
        b = np.clip(0.53 + 0.47 * (1.0 - normalized) ** 2 - 0.3 * normalized, 0.0, 1.0)
    elif colormap == "hot":
        r = np.clip(3.0 * normalized, 0.0, 1.0)
        g = np.clip(3.0 * normalized - 1.0, 0.0, 1.0)
        b = np.clip(3.0 * normalized - 2.0, 0.0, 1.0)
    else:  # inferno
        r = np.clip(normalized * 1.5 - 0.2 * normalized**4, 0.0, 1.0)
        g = np.clip(normalized**2 * 1.4 - 0.1 * normalized, 0.0, 1.0)
        b = np.clip(0.3 * (1.0 - normalized) + 0.8 * normalized**4, 0.0, 1.0)

    rgb = np.stack([r * 255, g * 255, b * 255], axis=2).astype(np.uint8)
    return Image.fromarray(rgb, mode="RGB")


# ---------------------------------------------------------------------------
# ELA — multi-quality median diff with local-background normalization
# ---------------------------------------------------------------------------
def enhanced_ela_map(
    image: Image.Image,
    quality: int = 90,
    colormap: str = "inferno",
    max_side: int = 1600,
) -> MapResult:
    """Error Level Analysis, hardened against the classic false positives.

    Improvements over naive ELA:
    - Median of three re-save qualities (q-10, q, q+10): a single unlucky
      quality no longer floods the map.
    - Computed on luminance: chroma-subsampling edges stop dominating.
    - Local-background subtraction (31px window): uniformly-compressed areas
      (sky, walls) cancel out; only regions that differ from their own
      neighborhood stand out — the actual splice signal.
    """
    src = _rgb(image, max_side=max_side)
    luma = _luma(src)
    base_q = max(50, min(99, int(quality)))
    qualities = sorted({max(50, base_q - 10), base_q, min(99, base_q + 10)})

    diffs = np.stack([np.abs(luma - _luma(Image.fromarray(_resave(src, q).astype(np.uint8))))
                      for q in qualities])
    diff = np.median(diffs, axis=0)

    background = ndimage.uniform_filter(diff, size=31)
    residual = diff - background  # positive where local error exceeds its surroundings

    cv = float(np.std(diff) / (np.mean(diff) + 1e-6))
    boosted = _percentile_normalize(np.abs(residual), 1.0, 99.5)

    notes = [
        f"Median of re-saves at qualities {', '.join(str(q) for q in qualities)}.",
        "Local-background normalized: flat uniformly-compressed areas (sky, walls) "
        "cancel instead of glowing.",
        "Edges always glow by design — look for contiguous patches that do not "
        "follow object boundaries.",
    ]
    if cv < 0.35:
        notes.append("Very uniform error levels across the image: consistent with a "
                     "single uniform save (or heavy smoothing).")
    return MapResult(
        image=_apply_colormap(boosted, colormap),
        confidence=None,
        notes=notes,
        legend="Brightness = local compression error exceeding its neighborhood.",
    )


def _luma_resaved(img: Image.Image, quality: int) -> np.ndarray:
    return (
        _resave(img, quality)[:, :, 0] * 0.299
        + _resave(img, quality)[:, :, 1] * 0.587
        + _resave(img, quality)[:, :, 2] * 0.114
    )


# ---------------------------------------------------------------------------
# Noise — median residual with robust local MAD and reliability masking
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Noise map — median residual with robust local MAD and reliability masking
# ---------------------------------------------------------------------------
def noise_variance_map(
    image: Image.Image,
    colormap: str = "viridis",
    max_side: int = 1400,
) -> MapResult:
    """Local sensor-noise level map for splice detection.

    Improvements over the Laplacian+boxblur version:
    - Median-filter residual instead of Laplacian: robust to strong edges.
    - Robust local noise via local MAD (median absolute deviation), so a few
      edge pixels inside a block cannot fake high noise.
    - Reliability mask: blocks without enough texture are dimmed instead of
      being reported as "smooth" evidence.
    """
    src = _rgb(image, max_side=max_side)
    gray = _luma(src)
    residual = gray - ndimage.median_filter(gray, size=5)

    # Local texture energy: flat blocks give unreliable noise estimates.
    tex = np.sqrt(
        np.maximum(ndimage.uniform_filter(gray**2, size=17)
                   - ndimage.uniform_filter(gray, size=17) ** 2, 0.0)
    )
    tex_threshold = max(2.0, float(np.percentile(tex, 25)))
    reliable = tex > tex_threshold

    # Robust local noise level: 1.4826 * local median of |residual| (MAD → σ).
    noise_local = 1.4826 * ndimage.median_filter(np.abs(residual), size=11)
    noise_vis = _percentile_normalize(noise_local, 2.0, 98.0).astype(np.float32)
    noise_vis[~reliable] = 64  # dim neutral: "low information", not evidence

    reliable_fraction = float(reliable.mean())
    notes = [
        "Noise level estimated from the median-filter residual (robust to edges), "
        "block-averaged with median absolute deviation.",
        "Dimmed areas lack texture: their noise estimate is unreliable, not 'smooth'.",
        "Limitations: strong JPEG compression homogenizes noise and hides splice "
        "differences; in-camera denoising does the same. Differences across a hard "
        "boundary are evidence; gradual differences usually are not.",
    ]
    if reliable_fraction < 0.25:
        notes.append("Most of this image is flat/low-texture — treat the whole map "
                     "with caution.")
    return MapResult(
        image=_apply_colormap(noise_vis.astype(np.uint8), colormap),
        confidence=reliable_fraction,
        notes=notes,
        legend="Bright = strong local noise; dim = too flat to judge.",
    )


# ---------------------------------------------------------------------------
# Lighting — block-wise dominant gradient angle with coherence gating
# ---------------------------------------------------------------------------
def luminance_gradient_map(
    image: Image.Image,
    block: int = 32,
    max_side: int = 1200,
) -> MapResult:
    """Dominant lighting-direction map.

    Per 32px block the circular-mean gradient angle and its coherence are
    computed (scipy Sobel). Random texture angles average out (low
    coherence), so only blocks with a dominant direction are colored —
    per-pixel hue noise is gone. Conflicting hues between adjacent surfaces
    remain the compositing signal.
    """
    src = _rgb(image, max_side=max_side)
    gray = _luma(src)
    gx = ndimage.sobel(gray, axis=1)
    gy = ndimage.sobel(gray, axis=0)
    mag = np.hypot(gx, gy)
    angle = np.arctan2(gy, gx)

    h, w = mag.shape
    # The block grid must cover the image even when the image is smaller
    # than one block (tiny images): clamp the block to the image, then take
    # the largest whole number of blocks that fits.
    bh = bw = max(1, min(block, h, w))
    gh, gw = max(1, h // bh), max(1, w // bw)

    mag_blocks = mag[: gh * bh, : gw * bw].reshape(gh, bh, gw, bw).mean(axis=(1, 3))
    sx = (np.cos(angle) * mag)[: gh * bh, : gw * bw].reshape(gh, bh, gw, bw).sum(axis=(1, 3))
    sy = (np.sin(angle) * mag)[: gh * bh, : gw * bw].reshape(gh, bh, gw, bw).sum(axis=(1, 3))
    resultant = np.hypot(sx, sy)
    total = mag_blocks * bh * bw
    coherence = np.divide(resultant, np.maximum(total, 1e-6))  # 0..1
    block_angle = np.arctan2(sy, sx)

    mag_threshold = max(3.0, float(np.percentile(mag_blocks, 55)))
    reliable = mag_blocks > mag_threshold

    hue = ((block_angle + np.pi) / (2 * np.pi) * 255).astype(np.uint8)
    sat = (np.clip(coherence, 0, 1) * 255).astype(np.uint8)
    val = _percentile_normalize(mag_blocks, 5, 95)
    sat[~reliable] = 0
    val[~reliable] = 40

    hsv = np.stack([hue, sat, val], axis=2).astype(np.uint8)
    vis = Image.fromarray(hsv, mode="HSV").convert("RGB")
    vis = vis.resize(src.size, Image.Resampling.NEAREST)

    reliable_fraction = float(reliable.mean())
    notes = [
        "Hue encodes each 32px block's dominant gradient direction; brightness "
        "encodes gradient strength; saturation encodes how coherent the "
        "directions inside the block are.",
        "Compare hues of what should be one continuous surface. Random texture "
        "produces low-saturation blocks instead of misleading hues.",
        "Limitations: this is a 2-D gradient statistic, not a 3-D lighting "
        "estimate; flat and blurry regions are dimmed as unreliable.",
    ]
    return MapResult(
        image=vis,
        confidence=reliable_fraction,
        notes=notes,
        legend="Hue wheel = direction; gray blocks = not enough structure.",
    )


# ---------------------------------------------------------------------------
# JPEG ghost — min difference + best-fit quality distribution
# ---------------------------------------------------------------------------
def jpeg_ghost_map(
    image: Image.Image,
    qualities: tuple[int, ...] = tuple(range(50, 100, 5)),
    colormap: str = "inferno",
    max_side: int = 1000,
) -> MapResult:
    """Farid-style JPEG ghost with best-fit quality statistics.

    For every pixel the difference to re-saves at each quality is tracked;
    the minimum difference is visualized and the per-pixel best-fit quality
    is summarized: a single dominant quality means one uniform save; a
    strong secondary quality cluster suggests part of the image was last
    compressed elsewhere.
    """
    src = _rgb(image, max_side=max_side)
    arr = np.asarray(src, dtype=np.int16)
    mins = np.full(arr.shape[:2], 1e9, dtype=np.float32)
    argmin = np.zeros(arr.shape[:2], dtype=np.uint8)
    for idx, quality in enumerate(qualities):
        resaved = _resave(src, quality)
        diff = np.abs(arr - resaved).mean(axis=2)
        closer = diff < mins
        mins[closer] = diff[closer]
        argmin[closer] = idx

    boosted = _percentile_normalize(mins, 1.0, 99.0)
    hist = np.bincount(argmin.ravel(), minlength=len(qualities))
    fractions = hist / hist.sum()
    ordered = sorted(range(len(qualities)), key=lambda i: -fractions[i])
    top = ordered[0]
    notes = [
        f"Re-save sweep over qualities {qualities[0]}-{qualities[-1]}; shown is the "
        "smallest per-pixel difference (robust percentile scaling).",
        f"Dominant best-fit quality: {qualities[top]} "
        f"({fractions[top] * 100:.0f}% of pixels) — likely the original save level.",
    ]
    confidence = None
    secondary = next((i for i in ordered[1:] if fractions[i] >= 0.08 and i != top), None)
    if secondary is not None and fractions[top] < 0.75:
        notes.append(
            f"Secondary best-fit cluster at quality {qualities[secondary]} "
            f"({fractions[secondary] * 100:.0f}% of pixels): those regions were "
            "plausibly last compressed at a different level — review them."
        )
        confidence = min(1.0, fractions[secondary] * 4.0)
    notes.append("Limitations: multiple re-saves or non-JPEG sources blur the signal; "
                 "dark differences alone are not proof of splicing.")
    return MapResult(
        image=_apply_colormap(boosted, colormap),
        confidence=confidence,
        notes=notes,
        legend="Bright = pixel survives some re-save unusually well.",
    )


# ---------------------------------------------------------------------------
# Thumbnail diff with SSIM consistency score
# ---------------------------------------------------------------------------
def render_thumbnail_diff(src_image: Image.Image, thumb_bytes: bytes | None) -> MapResult:
    """Compare the embedded EXIF thumbnail against the full image.

    Returns a three-panel strip (resized main | embedded thumbnail | amplified
    difference) plus an SSIM-based consistency score. A camera-generated
    thumbnail scores near 1.0; a mismatched (stale) thumbnail scores lower.
    """
    from skimage.metrics import structural_similarity

    if thumb_bytes:
        try:
            thumb = Image.open(io.BytesIO(thumb_bytes)).convert("RGB")
            resized = _rgb(src_image).resize(thumb.size, Image.Resampling.BILINEAR)
            diff = ImageEnhance.Brightness(ImageChops.difference(resized, thumb)).enhance(10)
            gap = 6
            strip = Image.new("RGB", (resized.width * 3 + gap * 2, resized.height), (24, 24, 26))
            strip.paste(resized, (0, 0))
            strip.paste(thumb, (resized.width + gap, 0))
            strip.paste(diff, (resized.width * 2 + gap * 2, 0))

            ssim = float(
                structural_similarity(
                    np.asarray(resized), np.asarray(thumb), channel_axis=2,
                    data_range=255.0,
                )
            )
            notes = [
                f"SSIM consistency (resized main vs embedded thumbnail): {ssim:.3f} "
                "(1.0 = identical).",
                "Camera-generated thumbnails score ≳0.9. A low score means the "
                "thumbnail no longer matches the pixels — typical after editing "
                "tools re-save the image without refreshing the preview.",
            ]
            if ssim < 0.85:
                notes.append("Thumbnail mismatch detected — consistent with "
                             "post-capture pixel editing.")
            return MapResult(image=strip, confidence=max(0.0, min(1.0, ssim)),
                             notes=notes, legend="left: resized main · middle: embedded thumbnail · right: amplified difference")
        except Exception:
            pass

    w, h = 640, 240
    card = Image.new("RGB", (w, h), (26, 26, 28))
    draw = ImageDraw.Draw(card)
    draw.rectangle([(16, 16), (w - 16, h - 16)], fill=(20, 20, 22), outline=(70, 70, 74), width=1)
    draw.text((36, 40), "NO EMBEDDED EXIF THUMBNAIL DETECTED", fill=(224, 164, 88))
    draw.text((36, 80), "- This container carries no embedded IFD1 preview stream.", fill=(212, 210, 205))
    draw.text((36, 110), "- Embedded thumbnails come from camera hardware and mobile devices.", fill=(150, 148, 144))
    draw.text((36, 140), "- PNG files, screenshots, and web exports omit thumbnail IFDs.", fill=(150, 148, 144))
    draw.text((36, 180), "To test this view, open an unedited camera JPEG with EXIF.", fill=(95, 179, 196))
    return MapResult(image=card, confidence=None,
                     notes=["No embedded thumbnail: nothing to compare. This is normal "
                            "for PNG, screenshots and web exports."],
                     legend="")


# ---------------------------------------------------------------------------
# Copy-move detection — SIFT + ratio test + translation clustering + RANSAC
# ---------------------------------------------------------------------------
@dataclass
class CloneCluster:
    """One geometrically-verified duplicated region."""

    inliers: int
    inlier_ratio: float
    translation: tuple[float, float]
    rotation_deg: float
    scale: float
    confidence: float
    src_points: np.ndarray      # Nx2 inlier keypoints (source region)
    dst_points: np.ndarray      # Nx2 inlier keypoints (pasted region)

    def describe(self) -> str:
        parts = [f"{self.inliers} verified keypoint matches"]
        if abs(self.rotation_deg) > 0.5 or abs(self.scale - 1.0) > 0.03:
            parts.append(f"shift ({self.translation[0]:+.0f}, {self.translation[1]:+.0f}) px, "
                         f"rotation {self.rotation_deg:+.1f}°, scale ×{self.scale:.2f}")
        else:
            parts.append(f"shift ({self.translation[0]:+.0f}, {self.translation[1]:+.0f}) px")
        return "; ".join(parts)


@dataclass
class CloneResult:
    image: Image.Image
    clusters: list[CloneCluster]
    confidence: float | None
    notes: list[str]
    legend: str = ""


CLUSTER_COLORS = [
    (224, 164, 88),   # amber
    (95, 179, 196),   # teal
    (168, 96, 92),    # brick red
    (150, 170, 110),  # moss
    (190, 140, 190),  # mauve
]


def detect_copy_move(
    image: Image.Image,
    max_side: int = 900,
    ratio_test: float = 0.80,
    min_shift_px: float = 16.0,
    min_inliers: int = 8,
    max_spread_frac: float = 0.30,
) -> CloneResult:
    """Detect duplicated regions via SIFT matching with geometric verification.

    Replaces the previous quadrant-mean block matching, which produced 658
    phantom clusters on a clean periodic texture while missing a verbatim
    clone. This implementation (standard keypoint-based copy-move detection,
    Amerini et al. 2011 style):
    - SIFT keypoints; the two nearest non-self neighbors are ratio-tested
      (Lowe), so ambiguous repetitive matches are rejected.
    - Greedy RANSAC consensus search over all matches: each accepted cluster
      is geometrically verified with a partial-affine model (handles rotation
      and scale) and must be spatially compact — inliers scattered across the
      frame indicate repetition, not a cloned patch. Copy events detected in
      both match directions are merged into one cluster.
    """
    src = _rgb(image, max_side=max_side)
    gray = np.asarray(ImageOps.grayscale(src), dtype=np.uint8)

    notes: list[str] = []
    empty = CloneResult(image=src, clusters=[], confidence=None, notes=notes,
                        legend="Outlines mark geometrically verified duplicated regions.")

    sift = cv2.SIFT_create(nfeatures=6000, contrastThreshold=0.01)
    kps, desc = sift.detectAndCompute(gray, None)
    if desc is None or len(kps) < 16:
        notes.append("Not enough distinctive features for copy-move analysis "
                     "(image too flat or too small).")
        return empty

    pts = np.array([kp.pt for kp in kps], dtype=np.float32)
    bf = cv2.BFMatcher(cv2.NORM_L2)
    knn = bf.knnMatch(desc, desc, k=3)

    good = []
    for pair in knn:
        # In self-matching the first neighbor is the descriptor itself; the
        # two nearest *other* descriptors are the candidate and its rival.
        non_self = [m for m in pair if m.queryIdx != m.trainIdx][:2]
        if len(non_self) != 2:
            continue
        m1, m2 = non_self
        if m1.distance >= ratio_test * m2.distance:
            continue
        p1, p2 = pts[m1.queryIdx], pts[m1.trainIdx]
        if np.hypot(*(p2 - p1)) < min_shift_px:
            continue
        good.append((m1.queryIdx, m1.trainIdx))

    if len(good) < min_inliers:
        notes.append("No distinctive repeated structures with consistent geometry.")
        return empty

    all_src = np.array([pts[qi] for qi, _ in good], dtype=np.float32)
    all_dst = np.array([pts[ti] for _, ti in good], dtype=np.float32)

    # Greedy consensus search: fit a partial-affine model to the whole match
    # set with RANSAC, take its inliers as one cluster, remove them, repeat.
    # Keypoint localization jitter splits true translations across adjacent
    # translation bins, so binning is not used for seeding at all.
    spread_limit = max_spread_frac * max(gray.shape[0], gray.shape[1])
    clusters: list[CloneCluster] = []
    remaining = list(range(len(good)))
    for _ in range(5):
        if len(remaining) < min_inliers:
            break
        r_src = all_src[remaining].reshape(-1, 1, 2)
        r_dst = all_dst[remaining].reshape(-1, 1, 2)
        model, mask = cv2.estimateAffinePartial2D(
            r_src, r_dst, method=cv2.RANSAC,
            ransacReprojThreshold=3.0, maxIters=3000,
        )
        if model is None or mask is None:
            break
        keep = mask.ravel().astype(bool)
        inliers = int(keep.sum())
        if inliers < min_inliers:
            break

        cluster_src = all_src[remaining][keep]
        cluster_dst = all_dst[remaining][keep]

        # Contiguity: a real cloned patch is compact; repetitive textures put
        # consistent-geometry matches all over the frame.
        spread = max(cluster_src.std(axis=0).max(), cluster_dst.std(axis=0).max())
        if spread > spread_limit:
            remaining = [r for r, k in zip(remaining, keep) if not k]
            continue

        scale = float(np.hypot(model[0, 0], model[1, 0]))
        rotation = float(np.degrees(np.arctan2(model[1, 0], model[0, 0])))
        translation = (float(model[0, 2]), float(model[1, 2]))

        # Confidence: inlier count is the primary signal (random matches almost
        # never agree on a 7-dof transform within 3 px), damped for clusters
        # spread wide across the frame.
        base = min(0.95, 0.30 + 0.05 * (inliers - 6))
        compact = 1.0 - 0.3 * min(1.0, spread / spread_limit)
        confidence = float(base * compact)
        clusters.append(
            CloneCluster(
                inliers=inliers,
                inlier_ratio=inliers / len(good),
                translation=translation,
                rotation_deg=rotation,
                scale=scale,
                confidence=confidence,
                src_points=cluster_src,
                dst_points=cluster_dst,
            )
        )
        remaining = [r for r, k in zip(remaining, keep) if not k]
        if len(clusters) >= 5:
            break

    clusters.sort(key=lambda c: -c.inliers)

    # Merge copy events detected in both match directions: the same source and
    # destination regions appear as T (src→dst) and T⁻¹ (dst→src). Two
    # clusters describing the same region pair share (nearly) the same union
    # bounding box.
    def _bbox(cluster: CloneCluster) -> tuple[float, float, float, float]:
        all_pts = np.vstack([cluster.src_points, cluster.dst_points])
        x0, y0 = all_pts.min(axis=0)
        x1, y1 = all_pts.max(axis=0)
        return x0, y0, x1, y1

    def _iou(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> float:
        ix0, iy0 = max(a[0], b[0]), max(a[1], b[1])
        ix1, iy1 = min(a[2], b[2]), min(a[3], b[3])
        inter = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
        if inter <= 0:
            return 0.0
        area_a = (a[2] - a[0]) * (a[3] - a[1])
        area_b = (b[2] - b[0]) * (b[3] - b[1])
        return inter / max(area_a + area_b - inter, 1e-6)

    merged: list[CloneCluster] = []
    for cluster in clusters:
        box = _bbox(cluster)
        target = next((m for m in merged if _iou(_bbox(m), box) > 0.5), None)
        if target is None:
            merged.append(cluster)
        elif cluster.inliers > target.inliers:
            merged.remove(target)
            merged.append(cluster)
    clusters = merged

    # Render overlays: hull around each region + connecting lines.
    vis = src.copy()
    draw = ImageDraw.Draw(vis, "RGBA")
    for idx, cluster in enumerate(clusters):
        color = CLUSTER_COLORS[idx % len(CLUSTER_COLORS)]
        for region_pts in (cluster.src_points, cluster.dst_points):
            if len(region_pts) >= 3:
                hull = cv2.convexHull(region_pts.astype(np.float32)).reshape(-1, 2)
                poly = [tuple(p) for p in hull]
                draw.polygon(poly, outline=color + (255,), fill=color + (42,))
            else:
                for x, y in region_pts:
                    draw.ellipse([x - 5, y - 5, x + 5, y + 5], outline=color + (255,))
        for (x1, y1), (x2, y2) in zip(cluster.src_points[:40], cluster.dst_points[:40]):
            draw.line([(x1, y1), (x2, y2)], fill=color + (110,), width=1)

    overall = max((c.confidence for c in clusters), default=None)
    if clusters:
        notes.append("Regions are accepted only when several distinctive keypoints "
                     "agree on one consistent geometric transform (RANSAC verified).")
        notes.extend(f"Cluster {i + 1}: {c.describe()} (confidence {c.confidence * 100:.0f}%)"
                     for i, c in enumerate(clusters))
        notes.append("Limitations: periodic patterns (bricks, fences, foliage) can "
                     "produce internally consistent translations; verify the outlined "
                     "regions visually before concluding.")
    else:
        notes.append("No geometrically consistent duplicated regions found. "
                     "This does not exclude manual edits that are not copies.")
    return CloneResult(image=vis, clusters=clusters, confidence=overall,
                       notes=notes,
                       legend="Outlines mark geometrically verified duplicated regions; "
                              "lines connect matched keypoints.")
