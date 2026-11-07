"""EXIF extraction and metadata helpers."""

from __future__ import annotations

import hashlib
import io
import os
import re
from datetime import datetime
from typing import Any
from xml.etree import ElementTree as ET

from PIL import Image, ExifTags
from PIL.ExifTags import GPSTAGS, IFD

from jpeg_structure import parse_iptc_iim, parse_jpeg

EXIF_DATETIME_FORMATS = (
    "%Y:%m:%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y:%m:%d %H:%M:%S.%f",
)

XMP_NS = {
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "photoshop": "http://ns.adobe.com/photoshop/1.0/",
    "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "crs": "http://ns.adobe.com/camera-raw-settings/1.0/",
}


def _decode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return repr(value)
    if isinstance(value, tuple) and len(value) == 1:
        return _decode_value(value[0])
    return value


def _parse_exif_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(_decode_value(value)).strip()
    if not text or text.startswith("0000"):
        return None
    for fmt in EXIF_DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _rational_to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            if value.denominator == 0:
                return None
            return float(value.numerator) / float(value.denominator)
        if isinstance(value, tuple) and len(value) == 2:
            num, den = value
            if den == 0:
                return None
            return float(num) / float(den)
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _gps_to_degrees(values: Any, ref: str | None) -> float | None:
    if not values or len(values) < 3:
        return None
    deg = _rational_to_float(values[0])
    minutes = _rational_to_float(values[1])
    seconds = _rational_to_float(values[2])
    if deg is None or minutes is None or seconds is None:
        return None
    decimal = deg + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ("S", "W"):
        decimal = -decimal
    return decimal


def _file_hashes(path: str) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def _u16(data: bytes, offset: int, endian: str) -> int:
    return int.from_bytes(data[offset : offset + 2], endian)


def _u32(data: bytes, offset: int, endian: str) -> int:
    return int.from_bytes(data[offset : offset + 4], endian)


def extract_exif_thumbnail(app1_payload: bytes) -> bytes | None:
    """Return embedded JPEG thumbnail from an APP1 Exif payload, if present."""
    if app1_payload.startswith(b"Exif\x00\x00"):
        tiff = app1_payload[6:]
    elif app1_payload.startswith(b"MM") or app1_payload.startswith(b"II"):
        tiff = app1_payload
    else:
        return None
    if len(tiff) < 8:
        return None
    endian = "little" if tiff[:2] == b"II" else "big"
    if (endian == "little" and tiff[2:4] != b"\x2a\x00") or (
        endian == "big" and tiff[2:4] != b"\x00\x2a"
    ):
        return None
    ifd0 = _u32(tiff, 4, endian)
    thumb = _ifd_thumbnail(tiff, ifd0, endian)
    if thumb:
        return thumb
    next_ifd = _next_ifd(tiff, ifd0, endian)
    if next_ifd:
        return _ifd_thumbnail(tiff, next_ifd, endian)
    return None


def _next_ifd(tiff: bytes, ifd: int, endian: str) -> int:
    if ifd + 2 > len(tiff):
        return 0
    count = _u16(tiff, ifd, endian)
    ptr = ifd + 2 + count * 12
    if ptr + 4 > len(tiff):
        return 0
    return _u32(tiff, ptr, endian)


def _ifd_thumbnail(tiff: bytes, ifd: int, endian: str) -> bytes | None:
    tags = _read_ifd_tags(tiff, ifd, endian)
    offset = tags.get(0x0201)
    length = tags.get(0x0202)
    if offset and length and offset + length <= len(tiff):
        blob = tiff[offset : offset + length]
        if blob[:2] == b"\xff\xd8":
            return blob
    return None


def _read_ifd_tags(tiff: bytes, ifd: int, endian: str) -> dict[int, int]:
    tags: dict[int, int] = {}
    if ifd + 2 > len(tiff):
        return tags
    count = _u16(tiff, ifd, endian)
    type_size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}
    for n in range(count):
        entry = ifd + 2 + n * 12
        if entry + 12 > len(tiff):
            break
        tag = _u16(tiff, entry, endian)
        typ = _u16(tiff, entry + 2, endian)
        num = _u32(tiff, entry + 4, endian)
        valoff = entry + 8
        size = type_size.get(typ, 1) * num
        if size <= 4:
            if typ == 3 and num == 1:
                value = _u16(tiff, valoff, endian)
            else:
                value = _u32(tiff, valoff, endian)
        else:
            value = _u32(tiff, valoff, endian)
        tags[tag] = value
    return tags


def extract_jpeg_thumbnail_from_file(data: bytes) -> bytes | None:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(data)
    while i + 4 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        code = data[i + 1]
        if code in (0xD8, 0xD9) or 0xD0 <= code <= 0xD7:
            i += 2
            continue
        if code == 0xDA:
            break
        length = int.from_bytes(data[i + 2 : i + 4], "big")
        payload = data[i + 4 : i + 2 + length]
        if code == 0xE1 and payload.startswith(b"Exif\x00\x00"):
            thumb = extract_exif_thumbnail(payload)
            if thumb:
                return thumb
        i = i + 2 + length
    return None


def _png_chunks(data: bytes) -> dict[str, Any]:
    result: dict[str, str] = {}
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return result
    i = 8
    while i + 12 <= len(data):
        length = int.from_bytes(data[i : i + 4], "big")
        name = data[i + 4 : i + 8].decode("latin-1", errors="replace")
        payload = data[i + 8 : i + 8 + length]
        i = i + 12 + length
        if name == "IEND":
            break
        if name == "tEXt":
            key, _, value = payload.partition(b"\x00")
            k = key.decode("latin-1", errors="replace")
            v = value.decode("latin-1", errors="replace")
            result[f"PNG:{k}"] = v
        elif name == "iTXt":
            key, sep, rest = payload.partition(b"\x00")
            if sep and len(rest) >= 2:
                rest = rest[2:]  # skip compression flag/method
                _, _, rest = rest.partition(b"\x00")  # language
                _, _, text_b = rest.partition(b"\x00")  # translated key
                k = key.decode("latin-1", errors="replace")
                text = text_b.decode("utf-8", errors="replace")
                result[f"PNG:{k}"] = text
        elif name == "tIME" and len(payload) == 7:
            year = int.from_bytes(payload[0:2], "big")
            result["PNG:tIME"] = (
                f"{year:04d}-{payload[2]:02d}-{payload[3]:02d} "
                f"{payload[4]:02d}:{payload[5]:02d}:{payload[6]:02d}"
            )
        elif name == "pHYs" and len(payload) >= 9:
            x = int.from_bytes(payload[0:4], "big")
            y = int.from_bytes(payload[4:8], "big")
            unit = payload[8]
            result["PNG:pHYs"] = f"{x}x{y} " + ("meters" if unit == 1 else "unspecified")
    return result


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def parse_xmp_summary(xml: str) -> dict[str, str]:
    summary: dict[str, str] = {}
    if not xml.strip():
        return summary
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        tool = re.search(r"CreatorTool>([^<]+)", xml)
        if tool:
            summary["XMPCreatorTool"] = tool.group(1).strip()
        if re.search(r"stEvt:action=", xml) or "xmpMM:History" in xml:
            summary["XMPHasHistory"] = "yes"
        return summary

    tools: list[str] = []
    history: list[str] = []
    for elem in root.iter():
        name = _local_name(elem.tag)
        text = (elem.text or "").strip()
        if name in ("CreatorTool", "creatorTool") and text:
            tools.append(text)
        if name in ("derivedFrom", "DerivedFrom") and text:
            summary["XMPDerivedFrom"] = text
        software = elem.attrib.get(f"{{{XMP_NS['stEvt']}}}softwareAgent") or elem.attrib.get(
            "softwareAgent"
        )
        action = elem.attrib.get(f"{{{XMP_NS['stEvt']}}}action") or elem.attrib.get("action")
        when = elem.attrib.get(f"{{{XMP_NS['stEvt']}}}when") or elem.attrib.get("when")
        if software or action:
            history.append(" ".join(p for p in (action, software, when) if p))
        if name in ("creator",) and text:
            summary["XMPCreator"] = text

    if tools:
        summary["XMPCreatorTool"] = tools[0]
    if history:
        summary["XMPHasHistory"] = "yes"
        summary["XMPHistory"] = " | ".join(history[:12])
    return summary


def _thumbnail_stats(thumb_bytes: bytes | None, width: int, height: int) -> dict[str, Any]:
    info: dict[str, Any] = {}
    if not thumb_bytes:
        return info
    info["ThumbnailBytes"] = len(thumb_bytes)
    try:
        with Image.open(io.BytesIO(thumb_bytes)) as thumb:
            tw, th = thumb.size
            info["ThumbnailWidth"] = tw
            info["ThumbnailHeight"] = th
            info["ThumbnailFormat"] = thumb.format
            if width and height and tw and th:
                main_aspect = width / height
                thumb_aspect = tw / th
                info["ThumbnailAspectDelta"] = abs(main_aspect - thumb_aspect)
    except Exception as exc:
        info["ThumbnailError"] = str(exc)
    return info


def extract_exif(path: str) -> dict[str, Any]:
    """Return a flat dict of readable EXIF tags plus file stats."""
    md5, sha256 = _file_hashes(path)
    result: dict[str, Any] = {
        "FileName": os.path.basename(path),
        "FilePath": os.path.abspath(path),
        "FileSize": os.path.getsize(path),
        "FileModified": datetime.fromtimestamp(os.path.getmtime(path)),
        "FileCreated": datetime.fromtimestamp(os.path.getctime(path)),
        "MD5": md5,
        "SHA256": sha256,
        "_has_exif": False,
    }

    with open(path, "rb") as handle:
        raw = handle.read()

    jpeg = parse_jpeg(raw)
    if jpeg:
        result["_jpeg"] = jpeg
        if jpeg.get("quality_estimate") is not None:
            result["JPEGQualityEstimate"] = jpeg["quality_estimate"]
        thumb = extract_jpeg_thumbnail_from_file(raw)
        if thumb:
            result["_thumbnail_bytes"] = thumb
        if jpeg.get("xmp"):
            result["_xmp"] = jpeg["xmp"]
            result.update(parse_xmp_summary(jpeg["xmp"]))
        for key, value in (jpeg.get("iptc") or {}).items():
            result[f"IPTC:{key}"] = value

    png_info = _png_chunks(raw)
    result.update(png_info)

    with Image.open(path) as img:
        result["Format"] = img.format
        result["Mode"] = img.mode
        result["Width"] = img.width
        result["Height"] = img.height

        if not jpeg:
            xmp = img.info.get("xmp") or img.info.get("XML:com.adobe.xmp")
            if isinstance(xmp, bytes):
                xmp = xmp.decode("utf-8", errors="replace")
            if xmp:
                result["_xmp"] = str(xmp)
                result.update(parse_xmp_summary(str(xmp)))
            iptc_raw = img.info.get("photoshop") or img.info.get("iptc")
            if isinstance(iptc_raw, bytes):
                for key, value in parse_iptc_iim(iptc_raw).items():
                    result.setdefault(f"IPTC:{key}", value)

        if "_thumbnail_bytes" not in result:
            try:
                exif_obj = img.getexif()
                thumb_ifd = exif_obj.get_ifd(IFD.IFD1) if exif_obj else {}
                offset = thumb_ifd.get(0x0201) if thumb_ifd else None
                length = thumb_ifd.get(0x0202) if thumb_ifd else None
                raw_exif = img.info.get("exif")
                if isinstance(raw_exif, bytes) and offset and length:
                    # Pillow stores TIFF offsets relative to TIFF header inside APP1.
                    tiff_start = 6 if raw_exif.startswith(b"Exif\x00\x00") else 0
                    blob = raw_exif[tiff_start + int(offset) : tiff_start + int(offset) + int(length)]
                    if blob[:2] == b"\xff\xd8":
                        result["_thumbnail_bytes"] = blob
            except Exception:
                pass

        result.update(
            _thumbnail_stats(
                result.get("_thumbnail_bytes"),
                img.width,
                img.height,
            )
        )

        exif = img.getexif()
        if not exif:
            return result

        result["_has_exif"] = True

        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if name in ("GPSInfo", "ExifOffset", "MakerNote"):
                continue
            result[name] = _decode_value(value)

        try:
            gps_ifd = exif.get_ifd(IFD.GPSInfo)
        except Exception:
            gps_ifd = {}

        gps_named: dict[str, Any] = {}
        for tag_id, value in gps_ifd.items():
            name = GPSTAGS.get(tag_id, str(tag_id))
            gps_named[name] = _decode_value(value)

        if gps_named:
            lat = _gps_to_degrees(
                gps_named.get("GPSLatitude"),
                str(gps_named.get("GPSLatitudeRef") or ""),
            )
            lon = _gps_to_degrees(
                gps_named.get("GPSLongitude"),
                str(gps_named.get("GPSLongitudeRef") or ""),
            )
            if lat is not None and lon is not None:
                result["GPSLatitude"] = lat
                result["GPSLongitude"] = lon
                result["GPSCoordinates"] = f"{lat:.6f}, {lon:.6f}"
            alt = _rational_to_float(gps_named.get("GPSAltitude"))
            if alt is not None:
                result["GPSAltitude"] = alt

        try:
            exif_ifd = exif.get_ifd(IFD.Exif)
        except Exception:
            exif_ifd = {}

        for tag_id, value in exif_ifd.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if name == "MakerNote":
                continue
            result[name] = _decode_value(value)

    px = result.get("ExifImageWidth") or result.get("PixelXDimension")
    py = result.get("ExifImageHeight") or result.get("PixelYDimension")
    try:
        if px and int(px) != int(result["Width"]):
            result["DimensionMismatchX"] = f"EXIF {px} vs pixel {result['Width']}"
        if py and int(py) != int(result["Height"]):
            result["DimensionMismatchY"] = f"EXIF {py} vs pixel {result['Height']}"
    except (TypeError, ValueError):
        pass

    return result


def parse_datetime_fields(meta: dict[str, Any]) -> dict[str, datetime]:
    fields = {}
    for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
        parsed = _parse_exif_datetime(meta.get(key))
        if parsed:
            fields[key] = parsed
    for key in ("FileModified", "FileCreated"):
        value = meta.get(key)
        if isinstance(value, datetime):
            fields[key] = value
    return fields
