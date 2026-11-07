"""Generate known-authentic and known-manipulated sample images for validation.

Every fixture is deterministic (seeded) and documented in FIXTURES so the
metrics harness can assert what each detector SHOULD find.

Authentic fixtures:
  authentic_photo.jpg  camera-like JPEG: full EXIF + embedded thumbnail, one save at q85
  screenshot.png       UI-like PNG, no metadata (no-EXIF is normal for PNG)
  periodic_texture.jpg brick-like repetitive pattern (hard case: repetitive textures)
  photo_b.jpg          second camera-like image (source material for the splice)

Manipulated fixtures:
  resaved.jpg          authentic_photo re-saved at q75, no edits (false-positive test)
  cloned_same.jpg      patch copied & pasted verbatim (classic copy-move)
  cloned_rsis.jpg      patch pasted with 15 deg rotation + 1.4x scale (defeats block matching)
  spliced.jpg          region from photo_b composited into authentic_photo (noise inconsistency)
  lsb_stego.png        authentic pixels saved as PNG with an LSB message in the RGB stream
  appended.jpg         authentic_photo with a ZIP archive appended after EOI
"""

from __future__ import annotations

import io
import os
import zipfile
from datetime import datetime

import numpy as np
import piexif
from PIL import Image, ImageDraw, ImageFilter

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

W, H = 640, 480
SECRET_MESSAGE = "FORENSIC-LSB-CANARY-7f3a91d4"


def _lowfreq_field(rng: np.random.Generator, w: int, h: int, grid: int = 7) -> np.ndarray:
    """Smooth random color field (upscaled bicubic) — mimics scene illumination."""
    small = rng.random((grid, grid, 3)).astype(np.float32) * 255
    img = Image.fromarray(small.astype(np.uint8)).resize((w, h), Image.Resampling.BICUBIC)
    return np.asarray(img, dtype=np.float32)


def _texture_field(rng: np.random.Generator, w: int, h: int, sigma: float = 18.0) -> np.ndarray:
    """Mid-frequency speckle mimicking surface texture (blur is mild so real
    local structure survives — SIFT-grade detail like foliage or fabric)."""
    noise = rng.normal(0, sigma, (h, w)).astype(np.float32)
    img = Image.fromarray(np.clip(noise + 128, 0, 255).astype(np.uint8), "L")
    img = img.filter(ImageFilter.GaussianBlur(0.8))
    return np.asarray(img, dtype=np.float32) - 128.0


def _add_structures(img: Image.Image, rng: np.random.Generator, n: int = 26) -> Image.Image:
    """Scatter hard-edged shapes (buildings/objects stand-ins) so the scene
    carries distinctive keypoints the way real photos do."""
    d = ImageDraw.Draw(img)
    w, h = img.size
    for _ in range(n):
        sw, sh = int(rng.integers(24, 90)), int(rng.integers(20, 70))
        x0, y0 = int(rng.integers(0, w - sw)), int(rng.integers(0, h - sh))
        shade = int(rng.integers(40, 220))
        color = (shade, int(shade * rng.uniform(0.7, 1.1)), int(shade * rng.uniform(0.6, 1.0)))
        if rng.random() < 0.5:
            d.rectangle([x0, y0, x0 + sw, y0 + sh], fill=color)
        else:
            d.ellipse([x0, y0, x0 + sw, y0 + sh], fill=color)
    return img


def _object_cluster(img: Image.Image) -> Image.Image:
    """Draw a distinctive object cluster across the clone-source region."""
    d = ImageDraw.Draw(img)
    d.rectangle([70, 70, 150, 150], fill=(198, 62, 52))
    d.ellipse([100, 90, 190, 175], fill=(52, 92, 198))
    d.rectangle([62, 122, 122, 190], fill=(228, 198, 82))
    d.ellipse([130, 60, 210, 120], fill=(90, 160, 90))
    return img


def make_photo(
    w: int, h: int, seed: int, tint: tuple[float, float, float], soft: bool = False
) -> Image.Image:
    """Synthetic photo-like image: illumination field + texture + sensor noise.

    With soft=True the image is smoother (less texture and sensor noise), like
    a phone photo processed with aggressive denoising — the classic splice
    partner whose smooth region stands out in noise-residual analysis.
    """
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w].astype(np.float32)
    gradient = np.stack(
        [x / max(w - 1, 1) * tint[0], y / max(h - 1, 1) * tint[1], (x + y) / max(w + h - 2, 1) * tint[2]],
        axis=2,
    )
    field = _lowfreq_field(rng, w, h) * 0.55
    tex_amp, sensor_sigma = (7.0, 0.6) if soft else (16.0, 2.2)
    tex = np.stack(
        [_texture_field(rng, w, h, tex_amp) for _ in range(3)], axis=2
    )
    sensor = rng.normal(0, sensor_sigma, (h, w, 3)).astype(np.float32)
    arr = np.clip(gradient * 0.55 + field * 0.45 + tex * 0.6 + sensor, 0, 255).astype(np.uint8)
    img = Image.fromarray(arr, "RGB")
    return _add_structures(img, rng)


def _full_exif(width: int, height: int, thumb_jpeg: bytes | None) -> bytes:
    now = datetime(2026, 3, 14, 9, 26, 53)
    dt = now.strftime("%Y:%m:%d %H:%M:%S").encode()
    zeroth = {
        piexif.ImageIFD.Make: b"Canon",
        piexif.ImageIFD.Model: b"Canon EOS R6",
        piexif.ImageIFD.Software: b"Firmware 1.6.0",
        piexif.ImageIFD.DateTime: dt,
        piexif.ImageIFD.Orientation: 1,
        piexif.ImageIFD.XResolution: (72, 1),
        piexif.ImageIFD.YResolution: (72, 1),
        piexif.ImageIFD.ResolutionUnit: 2,
    }
    exif_ifd = {
        piexif.ExifIFD.DateTimeOriginal: dt,
        piexif.ExifIFD.DateTimeDigitized: dt,
        piexif.ExifIFD.ExposureTime: (1, 250),
        piexif.ExifIFD.FNumber: (28, 10),
        piexif.ExifIFD.ISOSpeedRatings: 400,
        piexif.ExifIFD.PixelXDimension: width,
        piexif.ExifIFD.PixelYDimension: height,
        piexif.ExifIFD.LensModel: b"RF24-70mm F2.8 L IS USM",
    }
    gps = {
        piexif.GPSIFD.GPSLatitudeRef: b"N",
        piexif.GPSIFD.GPSLatitude: ((41, 1), (23, 1), (0, 1)),
        piexif.GPSIFD.GPSLongitudeRef: b"E",
        piexif.GPSIFD.GPSLongitude: ((2, 1), (9, 1), (0, 1)),
    }
    first = {}
    if thumb_jpeg is not None:
        first[piexif.ImageIFD.JPEGInterchangeFormat] = 0
        first[piexif.ImageIFD.JPEGInterchangeFormatLength] = len(thumb_jpeg)
    exif = {"0th": zeroth, "Exif": exif_ifd, "GPS": gps, "1st": first, "thumbnail": thumb_jpeg or b""}
    return piexif.dump(exif)


def _thumb_bytes(img: Image.Image, quality: int = 85) -> bytes:
    thumb = img.copy()
    thumb.thumbnail((160, 120), Image.Resampling.BILINEAR)
    buf = io.BytesIO()
    thumb.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def _save_jpeg_with_exif(img: Image.Image, path: str, quality: int) -> None:
    exif = _full_exif(img.width, img.height, _thumb_bytes(img))
    img.save(path, "JPEG", quality=quality, exif=exif)


def _make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hidden_evidence.txt", "Carved-canary payload for container tests.")
    return buf.getvalue()


def _embed_lsb_payload(
    img: Image.Image,
    message: str,
    scatter_rate: float = 0.0,
    sequential_fill: float = 0.0,
    seed: int = 5,
) -> Image.Image:
    """Embed an LSB payload modeling real stego tools.

    - `message`: written sequentially (set-embedding) at the start of the RGB
      stream so string extraction finds it.
    - `scatter_rate`: fraction of remaining samples carrying uniform random
      bits at scattered positions (flip-embedding) — models an encrypted
      payload, which is what real tools embed.
    - `sequential_fill`: alternative mode — uniform bits written sequentially
      over that fraction of the stream (models naive sequential embedding).
    """
    arr = np.asarray(img, dtype=np.uint8).copy()
    flat = arr.reshape(-1)
    rng = np.random.default_rng(seed)

    bits = []
    for byte in message.encode("utf-8"):
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    bits.append(0)  # NUL terminator
    if len(bits) > len(flat):
        raise ValueError("message too long for image")
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | bit

    rest = len(flat) - len(bits)
    if sequential_fill > 0:
        n = int(len(flat) * sequential_fill)
        rb = rng.integers(0, 2, n)
        seg = flat[len(bits):len(bits) + n]
        mod = rb == 1
        seg[mod] ^= 1
        flat[len(bits):len(bits) + n] = seg
    elif scatter_rate > 0:
        n = int(rest * scatter_rate)
        pos = rng.choice(rest, size=n, replace=False) + len(bits)
        rb = rng.integers(0, 2, n)
        mod = rb == 1
        flat[pos[mod]] ^= 1
    return Image.fromarray(arr.reshape(arr.shape), "RGB")


def generate_all(out_dir: str = FIXTURE_DIR) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths: dict[str, str] = {}

    photo_a = make_photo(W, H, seed=11, tint=(150, 120, 60))
    photo_b = make_photo(W, H, seed=42, tint=(40, 140, 170), soft=True)

    # --- authentic ---
    p = os.path.join(out_dir, "authentic_photo.jpg")
    _save_jpeg_with_exif(photo_a, p, quality=85)
    paths["authentic_photo"] = p

    p = os.path.join(out_dir, "photo_b.jpg")
    _save_jpeg_with_exif(photo_b, p, quality=85)
    paths["photo_b"] = p

    screenshot = Image.new("RGB", (W, H), (245, 245, 247))
    d = ImageDraw.Draw(screenshot)
    d.rectangle([40, 40, 300, 120], fill=(30, 90, 170))
    d.rectangle([40, 140, 600, 170], fill=(210, 210, 214))
    d.rectangle([40, 190, 520, 220], fill=(210, 210, 214))
    d.rectangle([40, 250, 580, 400], fill=(255, 255, 255), outline=(180, 180, 186))
    p = os.path.join(out_dir, "screenshot.png")
    screenshot.save(p, "PNG")
    paths["screenshot"] = p

    # periodic brick pattern — repetitive-texture false-positive stress test
    rng = np.random.default_rng(7)
    brick_w, brick_h, mortar = 64, 32, 3
    canvas = np.zeros((H, W, 3), dtype=np.uint8)
    for row in range(H // (brick_h + mortar) + 1):
        offset = (brick_w // 2) if row % 2 else 0
        for col in range(-1, W // brick_w + 2):
            x0 = col * (brick_w + mortar) + offset
            y0 = row * (brick_h + mortar)
            shade = rng.integers(120, 160)
            canvas[
                y0 : min(y0 + brick_h, H), max(x0, 0) : min(x0 + brick_w, W)
            ] = (shade, int(shade * 0.45), int(shade * 0.32))
    grain = rng.normal(0, 3, (H, W, 3)).astype(np.float32)
    p = os.path.join(out_dir, "periodic_texture.jpg")
    Image.fromarray(np.clip(canvas.astype(np.float32) + grain, 0, 255).astype(np.uint8)).save(
        p, "JPEG", quality=88
    )
    paths["periodic_texture"] = p

    # --- manipulated ---
    resaved_img = Image.open(paths["authentic_photo"]).convert("RGB")
    p = os.path.join(out_dir, "resaved.jpg")
    resaved_img.save(p, "JPEG", quality=75)
    paths["resaved"] = p

    # copy-move: verbatim patch (content-rich region, like real forgeries)
    img = _object_cluster(photo_a.copy())
    patch = img.crop((60, 60, 240, 200))
    img.paste(patch, (330, 210))
    p = os.path.join(out_dir, "cloned_same.jpg")
    img.save(p, "JPEG", quality=85)
    paths["cloned_same"] = p

    # copy-move with rotation + scale (defeats naive block matching)
    img = _object_cluster(photo_a.copy())
    patch = img.crop((60, 60, 240, 200)).rotate(15, expand=True)
    patch = patch.resize((int(patch.width * 1.5), int(patch.height * 1.5)),
                         Image.Resampling.BICUBIC)
    img.paste(patch, (320, 200))
    p = os.path.join(out_dir, "cloned_rsis.jpg")
    img.save(p, "JPEG", quality=85)
    paths["cloned_rsis"] = p

    # splice: right half from photo_b
    img = photo_a.copy()
    region = photo_b.crop((W // 2, 0, W, H))
    img.paste(region, (W // 2, 0))
    p = os.path.join(out_dir, "spliced.jpg")
    img.save(p, "JPEG", quality=85)
    paths["spliced"] = p

    # LSB stego (PNG survives LSB embedding): canary string + scattered
    # uniform payload at 30% of remaining capacity (encrypted-payload model).
    img = _embed_lsb_payload(photo_a, SECRET_MESSAGE, scatter_rate=0.30)
    p = os.path.join(out_dir, "lsb_stego.png")
    img.save(p, "PNG")
    paths["lsb_stego"] = p

    # sequential LSB stego: uniform bits written over the first 50% of the
    # stream — the chi-square attack's target scenario.
    img = _embed_lsb_payload(photo_a, SECRET_MESSAGE, sequential_fill=0.50)
    p = os.path.join(out_dir, "lsb_sequential.png")
    img.save(p, "PNG")
    paths["lsb_sequential"] = p

    # appended ZIP after EOI
    tmp = os.path.join(out_dir, "_tmp_auth.jpg")
    _save_jpeg_with_exif(photo_a, tmp, quality=85)
    with open(tmp, "rb") as f:
        jpeg_bytes = f.read()
    os.remove(tmp)
    p = os.path.join(out_dir, "appended.jpg")
    with open(p, "wb") as f:
        f.write(jpeg_bytes + _make_zip())
    paths["appended"] = p

    return paths


FIXTURE_TRUTH = {
    # fixture -> what a trustworthy tool should conclude
    "authentic_photo": "clean",
    "photo_b": "clean",
    "screenshot": "clean (no-EXIF is normal for PNG)",
    "periodic_texture": "clean (repetitive texture; detector must not cry clone)",
    "resaved": "minor anomaly at most (recompression is not tampering)",
    "cloned_same": "copy-move detected (translation)",
    "cloned_rsis": "copy-move detected (rotation+scale)",
    "spliced": "noise/compression inconsistency detected",
    "lsb_stego": "LSB steganography detected (scattered — SPA)",
    "lsb_sequential": "LSB steganography detected (sequential — chi-square)",
    "appended": "trailing payload detected",
}


if __name__ == "__main__":
    import json
    paths = generate_all()
    print(json.dumps(paths, indent=2))
