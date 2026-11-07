"""JPEG container forensics: markers, quantization tables, quality estimate."""

from __future__ import annotations

from typing import Any

MARKER_NAMES = {
    0xC0: "SOF0 (baseline)",
    0xC1: "SOF1 (extended)",
    0xC2: "SOF2 (progressive)",
    0xC3: "SOF3 (lossless)",
    0xC4: "DHT",
    0xC5: "SOF5",
    0xC6: "SOF6",
    0xC7: "SOF7",
    0xC8: "JPG",
    0xC9: "SOF9",
    0xCA: "SOF10",
    0xCB: "SOF11",
    0xCC: "DAC",
    0xCD: "SOF13",
    0xCE: "SOF14",
    0xCF: "SOF15",
    0xD0: "RST0",
    0xD1: "RST1",
    0xD2: "RST2",
    0xD3: "RST3",
    0xD4: "RST4",
    0xD5: "RST5",
    0xD6: "RST6",
    0xD7: "RST7",
    0xD8: "SOI",
    0xD9: "EOI",
    0xDA: "SOS",
    0xDB: "DQT",
    0xDC: "DNL",
    0xDD: "DRI",
    0xDE: "DHP",
    0xDF: "EXP",
    0xFE: "COM",
}

STANDALONE = {0x01, 0xD8, 0xD9} | set(range(0xD0, 0xD8))

# Zigzag index -> natural 8x8 offset (JPEG spec).
ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10,
    17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
]

# JPEG Annex K sample tables, natural (row-major) order.
STD_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]
STD_CHROMA = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
]


def _marker_name(code: int) -> str:
    if 0xE0 <= code <= 0xEF:
        return f"APP{code - 0xE0}"
    return MARKER_NAMES.get(code, f"0x{code:02X}")


def _ijg_scale(std: list[int], quality: int) -> list[int]:
    q = max(1, min(100, quality))
    scale = 5000 // q if q < 50 else 200 - q * 2
    out = []
    for value in std:
        temp = (value * scale + 50) // 100
        out.append(min(255, max(1, temp)))
    return out


def _natural_to_zigzag(natural: list[int]) -> list[int]:
    return [natural[ZIGZAG[i]] for i in range(64)]


def _zigzag_to_natural(zigzag: list[int]) -> list[int]:
    natural = [0] * 64
    for i, value in enumerate(zigzag):
        natural[ZIGZAG[i]] = value
    return natural


def _mean_abs_diff(a: list[int], b: list[int]) -> float:
    return sum(abs(x - y) for x, y in zip(a, b)) / float(len(a))


def _match_ijg(values: list[int]) -> dict[str, Any]:
    best_q = 1
    best_mad = 1e9
    best_kind = "luma"
    for quality in range(1, 101):
        luma = _natural_to_zigzag(_ijg_scale(STD_LUMA, quality))
        chroma = _natural_to_zigzag(_ijg_scale(STD_CHROMA, quality))
        mad_l = _mean_abs_diff(values, luma)
        mad_c = _mean_abs_diff(values, chroma)
        if mad_l < best_mad:
            best_mad, best_q, best_kind = mad_l, quality, "luma"
        if mad_c < best_mad:
            best_mad, best_q, best_kind = mad_c, quality, "chroma"
    if best_mad == 0:
        match = f"exact IJG {best_kind} quality {best_q}"
    elif best_mad <= 1.0:
        match = f"near IJG {best_kind} quality {best_q} (MAD {best_mad:.2f})"
    else:
        match = f"non-standard vs IJG (closest {best_kind} Q{best_q}, MAD {best_mad:.2f})"
    return {
        "quality_estimate": best_q,
        "mad": round(best_mad, 3),
        "match": match,
        "standard": best_mad <= 1.0,
    }


def _app_detail(code: int, payload: bytes) -> str:
    if code == 0xE0:
        if payload.startswith(b"JFIF\x00"):
            return "JFIF"
        if payload.startswith(b"JFXX\x00"):
            return "JFXX"
    if code == 0xE1:
        if payload.startswith(b"Exif\x00\x00") or payload.startswith(b"Exif\x00\xff"):
            return "EXIF"
        if payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            return "XMP"
    if code == 0xE2 and payload.startswith(b"ICC_PROFILE\x00"):
        return "ICC"
    if code == 0xED and payload.startswith(b"Photoshop 3.0\x00"):
        return "Photoshop IRB"
    if code == 0xEE and payload.startswith(b"Adobe"):
        return "Adobe APP14"
    head = payload[:24].decode("latin-1", errors="replace").replace("\x00", " ")
    return head.strip() or f"{len(payload)} bytes"


def _parse_dqt(payload: bytes) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    i = 0
    while i + 1 <= len(payload):
        prec_id = payload[i]
        i += 1
        precision = prec_id >> 4
        table_id = prec_id & 0x0F
        size = 64 * (2 if precision else 1)
        if i + size > len(payload):
            break
        chunk = payload[i : i + size]
        i += size
        if precision:
            values = [int.from_bytes(chunk[j : j + 2], "big") for j in range(0, size, 2)]
        else:
            values = list(chunk)
        info = _match_ijg(values)
        tables.append(
            {
                "table_id": table_id,
                "precision_bits": 16 if precision else 8,
                "values": values,
                "natural": _zigzag_to_natural(values),
                **info,
            }
        )
    return tables


def _skip_scan(data: bytes, i: int) -> int:
    n = len(data)
    while i < n:
        if data[i] != 0xFF:
            i += 1
            continue
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            return n
        code = data[i]
        if code == 0x00 or 0xD0 <= code <= 0xD7:
            i += 1
            continue
        return i - 1
    return n


def parse_jpeg(data: bytes) -> dict[str, Any] | None:
    """Walk JPEG markers. Returns None if the file is not JPEG."""
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        return None

    markers: list[dict[str, Any]] = []
    tables: list[dict[str, Any]] = []
    comments: list[str] = []
    xmp_parts: list[str] = []
    iptc: dict[str, str] = {}
    i = 0
    n = len(data)
    sos_count = 0
    eoi_offset: int | None = None
    sof: dict[str, Any] | None = None

    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        while i + 1 < n and data[i] == 0xFF and data[i + 1] == 0xFF:
            i += 1
        if i + 1 >= n:
            break
        if data[i] != 0xFF:
            continue
        code = data[i + 1]
        offset = i
        i += 2
        name = _marker_name(code)
        entry: dict[str, Any] = {"name": name, "code": code, "offset": offset, "detail": ""}

        if code in STANDALONE:
            if code == 0xD9:
                eoi_offset = offset
                markers.append(entry)
                break
            markers.append(entry)
            continue

        if i + 2 > n:
            entry["detail"] = "truncated length"
            markers.append(entry)
            break
        length = int.from_bytes(data[i : i + 2], "big")
        payload_start = i + 2
        payload_end = i + length
        if length < 2 or payload_end > n:
            entry["detail"] = f"bad length {length}"
            markers.append(entry)
            break
        payload = data[payload_start:payload_end]
        entry["length"] = length
        i = payload_end

        if code == 0xDB:
            parsed = _parse_dqt(payload)
            tables.extend(parsed)
            entry["detail"] = ", ".join(
                f"id {t['table_id']}: {t['match']}" for t in parsed
            ) or "DQT"
        elif 0xC0 <= code <= 0xCF and code not in (0xC4, 0xC8, 0xCC):
            if len(payload) >= 6:
                sof = {
                    "precision": payload[0],
                    "height": int.from_bytes(payload[1:3], "big"),
                    "width": int.from_bytes(payload[3:5], "big"),
                    "components": payload[5],
                    "progressive": code == 0xC2,
                    "marker": name,
                }
                entry["detail"] = (
                    f"{sof['width']}x{sof['height']} "
                    f"{sof['components']} components, {sof['precision']}-bit"
                )
        elif code == 0xDA:
            sos_count += 1
            entry["detail"] = f"scan {sos_count}"
            markers.append(entry)
            i = _skip_scan(data, i)
            continue
        elif code == 0xFE:
            text = payload.decode("utf-8", errors="replace").rstrip("\x00")
            comments.append(text)
            entry["detail"] = text[:80]
        elif 0xE0 <= code <= 0xEF:
            detail = _app_detail(code, payload)
            entry["detail"] = detail
            if detail == "XMP":
                xml = payload.split(b"\x00", 1)[-1].decode("utf-8", errors="replace")
                xmp_parts.append(xml)
            elif detail == "Photoshop IRB":
                iptc.update(_parse_iptc_from_irb(payload))
        markers.append(entry)

    luma_q = next((t["quality_estimate"] for t in tables if t["table_id"] == 0), None)
    if luma_q is None and tables:
        luma_q = tables[0]["quality_estimate"]

    names = [m["name"] for m in markers]
    app_details = [m.get("detail") or "" for m in markers if m["name"].startswith("APP")]
    soi = next((m["offset"] for m in markers if m["code"] == 0xD8), None)
    first_exif = next(
        (m["offset"] for m in markers if m.get("detail") == "EXIF"), None
    )
    first_sos = next((m["offset"] for m in markers if m["code"] == 0xDA), None)

    return {
        "markers": markers,
        "marker_names": names,
        "quant_tables": tables,
        "quality_estimate": luma_q,
        "comments": comments,
        "sof": sof,
        "sos_count": sos_count,
        "has_jfif": any(d == "JFIF" for d in app_details),
        "has_exif": any(d == "EXIF" for d in app_details),
        "has_xmp": any(d == "XMP" for d in app_details),
        "has_icc": any(d == "ICC" for d in app_details),
        "has_photoshop": any(d == "Photoshop IRB" for d in app_details),
        "has_adobe": any(d == "Adobe APP14" for d in app_details),
        "xmp": "\n".join(xmp_parts),
        "iptc": iptc,
        "eoi_offset": eoi_offset,
        "trailing_bytes": (n - (eoi_offset + 2)) if eoi_offset is not None else 0,
        "exif_after_sos": bool(
            first_exif is not None and first_sos is not None and first_exif > first_sos
        ),
        "soi_offset": soi,
    }


def _parse_iptc_from_irb(payload: bytes) -> dict[str, str]:
    if not payload.startswith(b"Photoshop 3.0\x00"):
        return {}
    data = payload[len(b"Photoshop 3.0\x00") :]
    iptc_payload = b""
    i = 0
    while i + 12 <= len(data):
        if data[i : i + 4] != b"8BIM":
            i += 1
            continue
        i += 4
        if i + 2 > len(data):
            break
        res_id = int.from_bytes(data[i : i + 2], "big")
        i += 2
        if i >= len(data):
            break
        name_len = data[i]
        i += 1
        i += name_len
        if (name_len + 1) % 2 == 1:
            i += 1
        if i + 4 > len(data):
            break
        size = int.from_bytes(data[i : i + 4], "big")
        i += 4
        block = data[i : i + size]
        i += size
        if size % 2 == 1:
            i += 1
        if res_id == 0x0404:
            iptc_payload = block
    return parse_iptc_iim(iptc_payload) if iptc_payload else {}


IPTC_DATASETS = {
    (2, 5): "ObjectName",
    (2, 15): "Category",
    (2, 20): "SupplementalCategory",
    (2, 25): "Keywords",
    (2, 40): "SpecialInstructions",
    (2, 55): "DateCreated",
    (2, 60): "TimeCreated",
    (2, 80): "Byline",
    (2, 85): "BylineTitle",
    (2, 90): "City",
    (2, 95): "ProvinceState",
    (2, 101): "Country",
    (2, 105): "Headline",
    (2, 110): "Credit",
    (2, 115): "Source",
    (2, 116): "CopyrightNotice",
    (2, 120): "Caption",
    (2, 122): "CaptionWriter",
}


def parse_iptc_iim(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    i = 0
    while i + 5 <= len(data):
        if data[i] != 0x1C:
            i += 1
            continue
        record = data[i + 1]
        dataset = data[i + 2]
        length = int.from_bytes(data[i + 3 : i + 5], "big")
        i += 5
        if length & 0x8000:
            nlen = length & 0x7FFF
            if i + nlen > len(data):
                break
            length = int.from_bytes(data[i : i + nlen], "big")
            i += nlen
        value = data[i : i + length]
        i += length
        key = IPTC_DATASETS.get((record, dataset))
        if not key:
            continue
        text = value.decode("utf-8", errors="replace").strip()
        if not text:
            continue
        if key in result:
            result[key] = result[key] + "; " + text
        else:
            result[key] = text
    return result
