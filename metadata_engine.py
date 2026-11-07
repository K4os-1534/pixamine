"""Deep multi-format metadata extraction & integrity engine.

Provides:
- MakerNotes decoder (Canon, Nikon, Apple: shutter counts, serial numbers)
- ICC Profile inspector (color space, device class, rendering intent, creator)
- PNG & WebP container chunk parsing (tIME, pHYs, VP8X, etc.)
- GPS helpers (decimal coordinates, OpenStreetMap/Google Maps links, GeoJSON)
- Metadata sanitizer (strips EXIF/XMP/IPTC/ICC for clean copies)
- CSV metadata export
"""

from __future__ import annotations

import csv
import os
import struct
from typing import Any

from PIL import Image

import exif_utils


def parse_icc_profile(icc_bytes: bytes | None) -> dict[str, Any]:
    """Parse ICC Color Profile header and primary tags."""
    if not icc_bytes or len(icc_bytes) < 128:
        return {}

    try:
        size = struct.unpack(">I", icc_bytes[0:4])[0]
        cmm_type = icc_bytes[4:8].decode("latin-1", errors="replace").strip()
        version_major = icc_bytes[8]
        version_minor = (icc_bytes[9] >> 4) & 0x0F
        device_class = icc_bytes[12:16].decode("latin-1", errors="replace").strip()
        color_space = icc_bytes[16:20].decode("latin-1", errors="replace").strip()
        conn_space = icc_bytes[20:24].decode("latin-1", errors="replace").strip()

        # Date/time
        y, m, d, h, mn, s = struct.unpack(">6H", icc_bytes[24:36])
        dt_str = f"{y:04d}-{m:02d}-{d:02d} {h:02d}:{mn:02d}:{s:02d}"

        platform = icc_bytes[40:44].decode("latin-1", errors="replace").strip()
        rendering_intent_code = struct.unpack(">I", icc_bytes[64:68])[0]
        intents = {
            0: "Perceptual",
            1: "Media-Relative Colorimetric",
            2: "Saturation",
            3: "ICC-Absolute Colorimetric",
        }
        rendering_intent = intents.get(rendering_intent_code, f"Unknown ({rendering_intent_code})")
        creator = icc_bytes[80:84].decode("latin-1", errors="replace").strip()

        device_class_names = {
            "scnr": "Input Device / Scanner",
            "mntr": "Display Device / Monitor",
            "prtr": "Output Device / Printer",
            "link": "DeviceLink Profile",
            "spac": "ColorSpace Conversion Profile",
            "abst": "Abstract Profile",
            "nmcl": "Named Color Profile",
        }

        # Look for 'desc' tag in tag table
        tag_count = struct.unpack(">I", icc_bytes[128:132])[0] if len(icc_bytes) >= 132 else 0
        description = ""
        offset = 132
        for _ in range(min(tag_count, 64)):
            if offset + 12 > len(icc_bytes):
                break
            tag_sig = icc_bytes[offset : offset + 4]
            tag_off = struct.unpack(">I", icc_bytes[offset + 4 : offset + 8])[0]
            tag_len = struct.unpack(">I", icc_bytes[offset + 8 : offset + 12])[0]
            if tag_sig == b"desc" and tag_off + tag_len <= len(icc_bytes):
                tag_data = icc_bytes[tag_off : tag_off + tag_len]
                if len(tag_data) >= 12 and tag_data[:4] == b"desc":
                    ascii_len = struct.unpack(">I", tag_data[8:12])[0]
                    description = tag_data[12 : 12 + ascii_len].decode("latin-1", errors="replace").strip("\x00")
                elif len(tag_data) >= 16 and tag_data[:4] == b"mluc":
                    # Multi-localized Unicode
                    record_count = struct.unpack(">I", tag_data[8:12])[0]
                    if record_count > 0:
                        rec_len = struct.unpack(">I", tag_data[20:24])[0]
                        rec_off = struct.unpack(">I", tag_data[24:28])[0]
                        description = tag_data[rec_off : rec_off + rec_len].decode("utf-16-be", errors="replace").strip("\x00")
                break
            offset += 12

        return {
            "ProfileSize": size,
            "CMMType": cmm_type or "Generic",
            "ProfileVersion": f"{version_major}.{version_minor}",
            "DeviceClass": device_class_names.get(device_class, device_class),
            "ColorSpace": color_space,
            "ConnectionSpace": conn_space,
            "Created": dt_str,
            "Platform": platform or "Independent",
            "RenderingIntent": rendering_intent,
            "Creator": creator,
            "Description": description or "Embedded ICC Profile",
        }
    except Exception:
        return {"RawICCProfile": f"{len(icc_bytes)} bytes"}


def parse_makernotes(raw_bytes: bytes, make: str = "") -> dict[str, Any]:
    """Parse manufacturer-specific MakerNote tags (Nikon, Canon, Sony, Apple)."""
    if not raw_bytes or len(raw_bytes) < 16:
        return {}

    notes: dict[str, Any] = {}
    make_lower = make.lower()

    try:
        # Nikon MakerNotes
        if "nikon" in make_lower or raw_bytes.startswith(b"Nikon"):
            # Nikon version 3 starts with 'Nikon\x00\x02\x00...'
            tiff_offset = 0
            if raw_bytes.startswith(b"Nikon\x00\x02"):
                tiff_offset = 10
            elif raw_bytes.startswith(b"Nikon"):
                tiff_offset = 8

            data = raw_bytes[tiff_offset:]
            if len(data) >= 8:
                endian = "<" if data[:2] == b"II" else ">"
                ifd_off = struct.unpack(f"{endian}I", data[4:8])[0]
                if ifd_off + 2 <= len(data):
                    num_tags = struct.unpack(f"{endian}H", data[ifd_off : ifd_off + 2])[0]
                    pos = ifd_off + 2
                    for _ in range(min(num_tags, 120)):
                        if pos + 12 > len(data):
                            break
                        tag_id, tag_type, count = struct.unpack(f"{endian}HHI", data[pos : pos + 8])
                        val_bytes = data[pos + 8 : pos + 12]
                        # Shutter count tag in Nikon is 0x00A7
                        if tag_id == 0x00A7:
                            notes["ShutterCount"] = struct.unpack(f"{endian}I", val_bytes)[0]
                        elif tag_id == 0x001D:  # Serial number
                            notes["SerialNumber"] = val_bytes.decode("latin-1", errors="replace").strip("\x00")
                        pos += 12

        # Canon MakerNotes
        elif "canon" in make_lower:
            data = raw_bytes
            endian = "<" if data[:2] == b"II" else ">"
            if len(data) >= 4:
                num_tags = struct.unpack(f"{endian}H", data[:2])[0]
                pos = 2
                for _ in range(min(num_tags, 100)):
                    if pos + 12 > len(data):
                        break
                    tag_id = struct.unpack(f"{endian}H", data[pos : pos + 2])[0]
                    val_bytes = data[pos + 8 : pos + 12]
                    if tag_id == 0x000C:  # Camera serial number
                        notes["CameraSerialNumber"] = struct.unpack(f"{endian}I", val_bytes)[0]
                    elif tag_id == 0x0095:  # Lens model
                        notes["LensModelID"] = struct.unpack(f"{endian}I", val_bytes)[0]
                    pos += 12

        # Apple Computational MakerNote
        elif "apple" in make_lower or b"Apple iOS" in raw_bytes[:64]:
            notes["AppleComputationalPhoto"] = True
            # Search for RunTime plist or RunTime epochs
            if b"bplist00" in raw_bytes:
                notes["AppleBinaryPropertyList"] = "Contains iOS Camera/Depth metadata"
    except Exception:
        pass

    return notes


def parse_webp_chunks(raw: bytes) -> dict[str, Any]:
    """Parse deep WebP container chunks."""
    if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WEBP":
        return {}

    chunks: dict[str, Any] = {"WebPFormat": "Extended WebP" if raw[12:16] == b"VP8X" else "Standard WebP"}
    pos = 12
    length = len(raw)

    while pos + 8 <= length:
        fourcc = raw[pos : pos + 4].decode("latin-1", errors="replace")
        chunk_len = struct.unpack("<I", raw[pos + 4 : pos + 8])[0]
        payload = raw[pos + 8 : pos + 8 + chunk_len]

        if fourcc == "VP8X" and len(payload) >= 10:
            flags = payload[0]
            chunks["HasICC"] = bool(flags & 0x20)
            chunks["HasAlpha"] = bool(flags & 0x10)
            chunks["HasEXIF"] = bool(flags & 0x08)
            chunks["HasXMP"] = bool(flags & 0x04)
            chunks["HasAnimation"] = bool(flags & 0x02)
            c_w = 1 + struct.unpack("<I", payload[4:7] + b"\x00")[0]
            c_h = 1 + struct.unpack("<I", payload[7:10] + b"\x00")[0]
            chunks["CanvasWidth"] = c_w
            chunks["CanvasHeight"] = c_h
        elif fourcc == "EXIF":
            chunks["WebP_EXIF_Bytes"] = chunk_len
        elif fourcc == "XMP ":
            chunks["WebP_XMP_Bytes"] = chunk_len
        elif fourcc == "ICCP":
            chunks["WebP_ICC_Profile"] = parse_icc_profile(payload)
        elif fourcc == "ANIM":
            chunks["IsAnimatedWebP"] = True

        # Chunks are padded to even byte length
        pos += 8 + chunk_len + (chunk_len % 2)

    return chunks


def parse_png_deep(raw: bytes) -> dict[str, Any]:
    """Parse PNG ancillary chunks (tIME, pHYs, gAMA, sRGB, etc.)."""
    if len(raw) < 8 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        return {}

    info: dict[str, Any] = {}
    pos = 8
    length = len(raw)

    while pos + 8 <= length:
        chunk_len = struct.unpack(">I", raw[pos : pos + 4])[0]
        chunk_type = raw[pos + 4 : pos + 8].decode("latin-1", errors="replace")
        payload = raw[pos + 8 : pos + 8 + chunk_len]

        if chunk_type == "tIME" and len(payload) >= 7:
            y, m, d, h, mn, s = struct.unpack(">H5B", payload[:7])
            info["PNG:EmbeddedModifiedTime"] = f"{y:04d}:{m:02d}:{d:02d} {h:02d}:{mn:02d}:{s:02d}"
        elif chunk_type == "pHYs" and len(payload) >= 9:
            ppu_x, ppu_y, unit = struct.unpack(">IIB", payload[:9])
            if unit == 1:  # meter
                dpi_x = int(round(ppu_x * 0.0254))
                dpi_y = int(round(ppu_y * 0.0254))
                info["PNG:DPI"] = f"{dpi_x}x{dpi_y} DPI"
            else:
                info["PNG:PixelDensity"] = f"{ppu_x}x{ppu_y} (relative)"
        elif chunk_type == "gAMA" and len(payload) >= 4:
            gamma = struct.unpack(">I", payload[:4])[0] / 100000.0
            info["PNG:Gamma"] = f"{gamma:.4f}"
        elif chunk_type == "sRGB" and len(payload) >= 1:
            intents = {0: "Perceptual", 1: "Relative colorimetric", 2: "Saturation", 3: "Absolute colorimetric"}
            info["PNG:sRGBIntent"] = intents.get(payload[0], f"Unknown ({payload[0]})")
        elif chunk_type == "iCCP":
            sep = payload.find(b"\x00")
            if sep != -1:
                pname = payload[:sep].decode("latin-1", errors="replace")
                info["PNG:ICCProfileName"] = pname

        pos += 12 + chunk_len  # 4 len + 4 type + data + 4 crc

    return info


def deep_extract_metadata(path: str) -> dict[str, Any]:
    """ExifTool-grade deep metadata extraction across all containers."""
    # 1. Base EXIF & hashes
    meta = exif_utils.extract_exif(path)

    with open(path, "rb") as f:
        raw = f.read()

    # 2. ICC Profile
    icc_data = None
    try:
        with Image.open(path) as img:
            icc_data = img.info.get("icc_profile")
    except Exception:
        pass
    if icc_data:
        meta["_icc_profile"] = parse_icc_profile(icc_data)

    # 3. MakerNotes
    try:
        with Image.open(path) as img:
            exif = img.getexif()
            if exif:
                mn_bytes = exif.get(0x927C)  # MakerNote tag ID
                if isinstance(mn_bytes, bytes):
                    notes = parse_makernotes(mn_bytes, make=str(meta.get("Make", "")))
                    for k, v in notes.items():
                        meta[f"MakerNote:{k}"] = v
    except Exception:
        pass

    # 4. Container-specific deep parser
    if meta.get("Format") == "PNG" or raw[:8] == b"\x89PNG\r\n\x1a\n":
        meta.update(parse_png_deep(raw))
    elif meta.get("Format") == "WEBP" or (len(raw) >= 12 and raw[8:12] == b"WEBP"):
        meta.update(parse_webp_chunks(raw))

    # 5. GPS Intelligence
    if "GPSLatitude" in meta and "GPSLongitude" in meta:
        lat = meta["GPSLatitude"]
        lon = meta["GPSLongitude"]
        meta["GPS:OpenStreetMap"] = f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"
        meta["GPS:GoogleMaps"] = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
        meta["GPS:GeoJSON"] = {
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {"file": os.path.basename(path), "altitude": meta.get("GPSAltitude")},
        }

    return meta


def strip_all_metadata(input_path: str, output_path: str) -> bool:
    """Write a metadata-free copy with identical pixel data.

    Rebuilds the image in a fresh container (rather than re-saving the original)
    so no EXIF/XMP/IPTC/ICC data or text chunks carry over. Raises OSError or
    PIL errors with the real reason on failure.
    """
    with Image.open(input_path) as img:
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(list(img.getdata()))
        clean_img.save(output_path)
    return True


def export_metadata_csv(meta: dict[str, Any], output_path: str) -> None:
    """Export metadata dictionary to a key-value CSV file."""
    clean_dict = {k: v for k, v in meta.items() if not k.startswith("_")}
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Tag", "Value"])
        for k, v in sorted(clean_dict.items()):
            writer.writerow([k, str(v)])
