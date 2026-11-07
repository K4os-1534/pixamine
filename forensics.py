"""Heuristic checks for common image metadata forgery."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from exif_utils import parse_datetime_fields

EDITOR_MARKERS = (
    "photoshop",
    "gimp",
    "paint.net",
    "snapseed",
    "lightroom",
    "affinity",
    "pixelmator",
    "canva",
    "picsart",
    "instagram",
    "facetune",
)

CAMERA_MAKES = (
    "canon",
    "nikon",
    "sony",
    "fujifilm",
    "fuji",
    "olympus",
    "panasonic",
    "leica",
    "pentax",
    "hasselblad",
    "kodak",
    "samsung",
    "apple",
    "google",
    "huawei",
    "xiaomi",
    "oneplus",
    "motorola",
    "dji",
    "gopro",
)


class Finding:
    def __init__(self, severity: str, title: str, detail: str) -> None:
        self.severity = severity  # info | warn | alert
        self.title = title
        self.detail = detail

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.title}: {self.detail}"


def analyze(meta: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    fmt = str(meta.get("Format") or "").upper()
    has_exif = bool(meta.get("_has_exif"))
    dates = parse_datetime_fields(meta)
    software = str(meta.get("Software") or "").strip()
    make = str(meta.get("Make") or "").strip()
    model = str(meta.get("Model") or "").strip()

    if fmt in ("JPEG", "JPG", "TIFF") and not has_exif:
        findings.append(
            Finding(
                "warn",
                "No EXIF data",
                "This format normally carries camera metadata. Missing EXIF can mean the file was exported, stripped, or rebuilt.",
            )
        )
    elif not has_exif:
        findings.append(
            Finding(
                "info",
                "No EXIF data",
                "PNG/WebP and some exports often have little or no EXIF. That alone is not proof of forgery.",
            )
        )

    if software:
        lower = software.lower()
        if any(marker in lower for marker in EDITOR_MARKERS):
            findings.append(
                Finding(
                    "warn",
                    "Editor software tag",
                    f"Software field is '{software}'. Editors rewrite or inject metadata when saving.",
                )
            )
        else:
            findings.append(
                Finding(
                    "info",
                    "Software tag",
                    f"Software field is '{software}'.",
                )
            )

    if make and any(c in make.lower() for c in CAMERA_MAKES) and software:
        if any(marker in software.lower() for marker in EDITOR_MARKERS):
            findings.append(
                Finding(
                    "warn",
                    "Camera + editor mix",
                    f"Make is '{make}' but Software is '{software}'. The file was likely saved after capture.",
                )
            )

    if make and not model:
        findings.append(
            Finding(
                "warn",
                "Incomplete camera tags",
                f"Make is present ('{make}') but Model is missing. Partial EXIF is sometimes left after manual edits.",
            )
        )

    original = dates.get("DateTimeOriginal")
    digitized = dates.get("DateTimeDigitized")
    modified_tag = dates.get("DateTime")
    file_mtime = dates.get("FileModified")
    now = datetime.now()

    if original and digitized:
        delta = abs(original - digitized)
        if delta > timedelta(minutes=5):
            findings.append(
                Finding(
                    "alert",
                    "Capture vs digitize mismatch",
                    f"DateTimeOriginal={original} and DateTimeDigitized={digitized} differ by {delta}.",
                )
            )

    if original and modified_tag:
        if modified_tag < original - timedelta(seconds=2):
            findings.append(
                Finding(
                    "alert",
                    "Modify date before capture",
                    f"DateTime ({modified_tag}) is earlier than DateTimeOriginal ({original}). Timestamps may have been edited.",
                )
            )
        elif modified_tag - original > timedelta(days=1):
            findings.append(
                Finding(
                    "info",
                    "File saved after capture",
                    f"DateTime ({modified_tag}) is later than DateTimeOriginal ({original}). Common after export; not proof of forgery.",
                )
            )

    for name, value in dates.items():
        if name.startswith("DateTime") and value > now + timedelta(minutes=5):
            findings.append(
                Finding(
                    "alert",
                    "Future timestamp",
                    f"{name} is {value}, which is after the current clock. Likely manipulated or a wrong camera clock.",
                )
            )
        if value.year < 1990:
            findings.append(
                Finding(
                    "alert",
                    "Implausible timestamp",
                    f"{name} is {value}. Consumer digital cameras were not in use that early.",
                )
            )

    if original and file_mtime and file_mtime + timedelta(seconds=5) < original:
        findings.append(
            Finding(
                "alert",
                "Filesystem time before capture",
                f"File modified time ({file_mtime}) is earlier than DateTimeOriginal ({original}). EXIF dates may have been rewritten.",
            )
        )

    gps = meta.get("GPSCoordinates")
    if gps and not original:
        findings.append(
            Finding(
                "warn",
                "GPS without capture time",
                "Coordinates are present but DateTimeOriginal is missing. Tags may have been copied from another file.",
            )
        )

    findings.extend(_container_findings(meta, make, software))

    if not findings:
        findings.append(
            Finding(
                "info",
                "No metadata red flags",
                "No timestamp or software inconsistencies were found. This does not prove the pixels are authentic.",
            )
        )

    return findings


def _container_findings(meta: dict[str, Any], make: str, software: str) -> list[Finding]:
    findings: list[Finding] = []
    jpeg = meta.get("_jpeg") or {}
    tool = str(meta.get("XMPCreatorTool") or "").strip()
    history = str(meta.get("XMPHistory") or "")

    if meta.get("DimensionMismatchX") or meta.get("DimensionMismatchY"):
        findings.append(
            Finding(
                "alert",
                "EXIF vs pixel size mismatch",
                " ".join(
                    p
                    for p in (meta.get("DimensionMismatchX"), meta.get("DimensionMismatchY"))
                    if p
                )
                + ". Tags may belong to a different image or a crop.",
            )
        )

    aspect_delta = meta.get("ThumbnailAspectDelta")
    if isinstance(aspect_delta, float) and aspect_delta > 0.05:
        findings.append(
            Finding(
                "alert",
                "Thumbnail aspect mismatch",
                f"Embedded thumbnail is {meta.get('ThumbnailWidth')}x{meta.get('ThumbnailHeight')} "
                f"but the image is {meta.get('Width')}x{meta.get('Height')}. "
                "Editors often update pixels and leave the original thumbnail.",
            )
        )
    elif meta.get("_thumbnail_bytes"):
        findings.append(
            Finding(
                "info",
                "Embedded thumbnail",
                f"{meta.get('ThumbnailWidth')}x{meta.get('ThumbnailHeight')} "
                f"({meta.get('ThumbnailBytes')} bytes). Compare it with the main image.",
            )
        )

    if jpeg:
        tables = jpeg.get("quant_tables") or []
        nonstd = [t for t in tables if not t.get("standard")]
        std = [t for t in tables if t.get("standard")]
        if std and jpeg.get("quality_estimate") is not None:
            findings.append(
                Finding(
                    "info",
                    "IJG quantization tables",
                    f"Luma table matches Independent JPEG Group quality "
                    f"{jpeg['quality_estimate']}. Common after libjpeg/editor export.",
                )
            )
        if nonstd:
            detail = "; ".join(t["match"] for t in nonstd)
            findings.append(
                Finding(
                    "info",
                    "Custom quantization tables",
                    detail
                    + ". Cameras often use custom tables; editors may too. Not proof of forgery.",
                )
            )
        if jpeg.get("has_photoshop"):
            findings.append(
                Finding(
                    "warn",
                    "Photoshop IRB segment",
                    "APP13 Photoshop resources are present. The file was saved by Photoshop or a tool that copies IRB.",
                )
            )
        if jpeg.get("trailing_bytes"):
            findings.append(
                Finding(
                    "warn",
                    "Data after EOI",
                    f"{jpeg['trailing_bytes']} byte(s) follow the JPEG end marker. "
                    "Can be appended metadata, an extra image, or incomplete truncation.",
                )
            )
        if jpeg.get("exif_after_sos"):
            findings.append(
                Finding(
                    "alert",
                    "EXIF after image data",
                    "The EXIF APP1 segment appears after SOS. Typical cameras write EXIF first.",
                )
            )
        sos = int(jpeg.get("sos_count") or 0)
        progressive = bool((jpeg.get("sof") or {}).get("progressive"))
        if sos > 1 and not progressive:
            findings.append(
                Finding(
                    "warn",
                    "Multiple SOS scans",
                    f"{sos} scan segments in a non-progressive JPEG. Unusual for a camera original.",
                )
            )
        if jpeg.get("has_adobe") and make and any(c in make.lower() for c in CAMERA_MAKES):
            findings.append(
                Finding(
                    "warn",
                    "Adobe APP14 + camera EXIF",
                    "Adobe color-transform segment plus camera Make/Model often means the pixels were resaved.",
                )
            )
        if jpeg.get("has_xmp") and not jpeg.get("has_exif"):
            findings.append(
                Finding(
                    "warn",
                    "XMP without EXIF",
                    "XMP is present but no EXIF APP1. Common for exports and some editors.",
                )
            )

    if tool:
        lower = tool.lower()
        if any(marker in lower for marker in EDITOR_MARKERS):
            findings.append(
                Finding(
                    "warn",
                    "XMP creator tool",
                    f"XMP CreatorTool is '{tool}'.",
                )
            )
        else:
            findings.append(
                Finding(
                    "info",
                    "XMP creator tool",
                    f"XMP CreatorTool is '{tool}'.",
                )
            )
    if history:
        findings.append(
            Finding(
                "warn",
                "XMP edit history",
                history[:500],
            )
        )
    if software and tool and software.lower() not in tool.lower() and tool.lower() not in software.lower():
        findings.append(
            Finding(
                "info",
                "Software vs XMP tool",
                f"EXIF Software is '{software}' but XMP CreatorTool is '{tool}'.",
            )
        )

    return findings
