"""Binary forensics & file carving engine (Binwalk-level capabilities).

Provides:
- Shannon entropy calculation & visual plotting
- Magic byte signature scanning across 31 file formats
- Trailing overlay (hidden payload past EOF) detection
- Automated file carving
- Interactive hex dump viewer
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import numpy as np
from PIL import Image, ImageDraw


@dataclass
class SignatureMatch:
    offset: int
    name: str
    category: str
    description: str
    size: int | None = None
    confidence: str = "High"


@dataclass
class CarvedItem:
    offset: int
    name: str
    filename: str
    size: int
    category: str


def _validate_pe(data: bytes, offset: int) -> bool:
    if offset + 0x40 > len(data):
        return False
    pe_off = int.from_bytes(data[offset + 0x3C : offset + 0x40], "little")
    if pe_off > 4096 or offset + pe_off + 4 > len(data):
        return False
    return data[offset + pe_off : offset + pe_off + 4] == b"PE\x00\x00"


def _validate_bmp(data: bytes, offset: int) -> bool:
    if offset + 14 > len(data):
        return False
    if data[offset + 6 : offset + 10] != b"\x00\x00\x00\x00":
        return False
    pix_off = int.from_bytes(data[offset + 10 : offset + 14], "little")
    return 14 <= pix_off <= 4096


def _validate_zip(data: bytes, offset: int) -> bool:
    if offset + 30 > len(data):
        return False
    version = int.from_bytes(data[offset + 4 : offset + 6], "little")
    method = int.from_bytes(data[offset + 8 : offset + 10], "little")
    return version <= 63 and method in (0, 8, 9, 12, 14, 93)


def _validate_gzip(data: bytes, offset: int) -> bool:
    if offset + 10 > len(data):
        return False
    method = data[offset + 2]
    flags = data[offset + 3]
    return method == 8 and (flags & 0xE0) == 0


def _validate_elf(data: bytes, offset: int) -> bool:
    if offset + 16 > len(data):
        return False
    cls = data[offset + 4]
    endian = data[offset + 5]
    version = data[offset + 6]
    return cls in (1, 2) and endian in (1, 2) and version == 1


# Common signatures for image-stego / polyglot / embedded-file detection
SIGNATURES: list[dict[str, Any]] = [
    # Archives & Compressed
    {"name": "ZIP Archive", "category": "Archive", "magic": b"PK\x03\x04", "desc": "Standard ZIP / JAR / Office XML container", "ext": "zip", "validator": _validate_zip},
    {"name": "ZIP Spanned/Empty", "category": "Archive", "magic": b"PK\x05\x06", "desc": "End of Central Directory record", "ext": "zip"},
    {"name": "7-Zip Archive", "category": "Archive", "magic": b"7z\xbc\xaf\x27\x1c", "desc": "7-Zip compressed archive", "ext": "7z"},
    {"name": "RAR Archive", "category": "Archive", "magic": b"Rar!\x1a\x07\x00", "desc": "RAR archive v4.x", "ext": "rar"},
    {"name": "RAR5 Archive", "category": "Archive", "magic": b"Rar!\x1a\x07\x01\x00", "desc": "RAR archive v5.x", "ext": "rar"},
    {"name": "GZIP Archive", "category": "Archive", "magic": b"\x1f\x8b\x08", "desc": "GZIP compressed file", "ext": "gz", "validator": _validate_gzip},
    {"name": "BZIP2 Archive", "category": "Archive", "magic": b"BZh", "desc": "BZIP2 compressed archive", "ext": "bz2"},
    {"name": "XZ Archive", "category": "Archive", "magic": b"\xfd7zXZ\x00", "desc": "XZ / LZMA2 compressed container", "ext": "xz"},
    {"name": "Zstandard Archive", "category": "Archive", "magic": b"\x28\xb5\x2f\xfd", "desc": "Zstandard compressed file", "ext": "zst"},
    {"name": "TAR Archive", "category": "Archive", "magic": b"ustar\x0000", "offset_relative": 257, "desc": "POSIX TAR archive", "ext": "tar"},

    # Executables & Binaries
    {"name": "ELF Executable", "category": "Executable", "magic": b"\x7fELF", "desc": "Linux/Unix ELF executable or library", "ext": "elf", "validator": _validate_elf},
    {"name": "PE Executable", "category": "Executable", "magic": b"MZ", "desc": "DOS / Windows PE executable (EXE/DLL)", "ext": "exe", "validator": _validate_pe},
    {"name": "Mach-O 32-bit (LE)", "category": "Executable", "magic": b"\xce\xfa\xed\xfe", "desc": "macOS Mach-O 32-bit executable", "ext": "macho"},
    {"name": "Mach-O 64-bit (LE)", "category": "Executable", "magic": b"\xcf\xfa\xed\xfe", "desc": "macOS Mach-O 64-bit executable", "ext": "macho"},
    {"name": "WebAssembly", "category": "Executable", "magic": b"\x00asm", "desc": "Compiled WebAssembly binary", "ext": "wasm"},
    {"name": "Java Class", "category": "Executable", "magic": b"\xca\xfe\xba\xbe", "desc": "Compiled Java bytecode class", "ext": "class"},

    # Documents & Databases
    {"name": "PDF Document", "category": "Document", "magic": b"%PDF-", "desc": "Adobe Portable Document Format", "ext": "pdf"},
    {"name": "SQLite Database", "category": "Database", "magic": b"SQLite format 3\x00", "desc": "SQLite 3 database file", "ext": "sqlite"},
    {"name": "Rich Text Format", "category": "Document", "magic": b"{\\rtf", "desc": "RTF formatted text document", "ext": "rtf"},

    # Images (Secondary / Embedded)
    {"name": "JPEG Image", "category": "Image", "magic": b"\xff\xd8\xff", "desc": "JPEG / JFIF image stream", "ext": "jpg"},
    {"name": "PNG Image", "category": "Image", "magic": b"\x89PNG\r\n\x1a\n", "desc": "Portable Network Graphics stream", "ext": "png"},
    {"name": "GIF87a Image", "category": "Image", "magic": b"GIF87a", "desc": "GIF 87a graphic", "ext": "gif"},
    {"name": "GIF89a Image", "category": "Image", "magic": b"GIF89a", "desc": "GIF 89a animation/graphic", "ext": "gif"},
    {"name": "BMP Image", "category": "Image", "magic": b"BM", "desc": "Windows Bitmap image", "ext": "bmp", "validator": _validate_bmp},
    {"name": "TIFF (Little Endian)", "category": "Image", "magic": b"II*\x00", "desc": "Tagged Image File Format (LE)", "ext": "tiff"},
    {"name": "TIFF (Big Endian)", "category": "Image", "magic": b"MM\x00*", "desc": "Tagged Image File Format (BE)", "ext": "tiff"},

    # Audio & Video
    {"name": "MP3 Audio (ID3)", "category": "Media", "magic": b"ID3", "desc": "MPEG Audio with ID3v2 container", "ext": "mp3"},
    {"name": "Ogg Container", "category": "Media", "magic": b"OggS", "desc": "Ogg multimedia bitstream", "ext": "ogg"},
    {"name": "FLAC Audio", "category": "Media", "magic": b"fLaC", "desc": "Free Lossless Audio Codec", "ext": "flac"},
    {"name": "RIFF Audio/Video", "category": "Media", "magic": b"RIFF", "desc": "Resource Interchange File Format (WAV/AVI/WEBP)", "ext": "riff"},

    # Cryptography & Certificates
    {"name": "PEM Certificate/Key", "category": "Crypto", "magic": b"-----BEGIN ", "desc": "PEM encoded certificate or private key", "ext": "pem"},
]


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits per byte, 0.0 to 8.0) of a byte slice."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def compute_entropy_profile(
    data: bytes, block_size: int = 1024, step: int = 512
) -> list[tuple[int, float]]:
    """Compute sliding-window Shannon entropy across file offsets."""
    if not data:
        return []
    total = len(data)
    if total <= block_size:
        return [(0, shannon_entropy(data))]

    results = []
    for offset in range(0, total, step):
        chunk = data[offset : min(offset + block_size, total)]
        if len(chunk) < 64:
            break
        results.append((offset, shannon_entropy(chunk)))
    return results


def render_entropy_plot(
    data: bytes,
    width: int = 760,
    height: int = 240,
    block_size: int = 1024,
    step: int = 512,
) -> Image.Image:
    """Generate a sleek, dark-themed Shannon entropy graph image."""
    profile = compute_entropy_profile(data, block_size, step)
    img = Image.new("RGB", (width, height), color=(26, 27, 38))
    draw = ImageDraw.Draw(img)

    margin_left = 50
    margin_right = 20
    margin_top = 30
    margin_bottom = 35

    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom

    # Background grid
    draw.rectangle(
        [(margin_left, margin_top), (margin_left + plot_w, margin_top + plot_h)],
        fill=(18, 19, 27),
        outline=(50, 54, 76),
    )

    # Horizontal grid lines (0, 2, 4, 6, 7.2, 8 bits)
    grid_levels = [(2.0, "2.0"), (4.0, "4.0"), (6.0, "6.0"), (7.2, "7.2 (Enc/Comp)"), (8.0, "8.0")]
    for level, label in grid_levels:
        y = margin_top + int(plot_h * (1.0 - level / 8.0))
        color = (70, 75, 105) if level != 7.2 else (180, 80, 50)
        draw.line([(margin_left, y), (margin_left + plot_w, y)], fill=color, width=1)
        draw.text((8, y - 6), label[:4], fill=(150, 155, 180))

    # Title & Legend
    overall = shannon_entropy(data)
    title = f"Entropy Profile: Total {len(data):,} bytes | Overall H = {overall:.3f} bits/byte"
    draw.text((margin_left, 10), title, fill=(230, 235, 245))

    if not profile:
        return img

    max_offset = max(p[0] for p in profile) or 1
    points = []
    for offset, ent in profile:
        x = margin_left + int(plot_w * (offset / max_offset))
        y = margin_top + int(plot_h * (1.0 - min(8.0, ent) / 8.0))
        points.append((x, y))

    # Fill polygon under curve
    if len(points) >= 2:
        fill_poly = [(margin_left, margin_top + plot_h)] + points + [(points[-1][0], margin_top + plot_h)]
        overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        draw_ov = ImageDraw.Draw(overlay)
        draw_ov.polygon(fill_poly, fill=(6, 182, 212, 60))
        img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
        draw = ImageDraw.Draw(img)

        # Draw main curve
        for i in range(len(points) - 1):
            draw.line([points[i], points[i + 1]], fill=(6, 182, 212), width=2)

    # X-axis ticks (Offset markers)
    tick_count = 5
    for i in range(tick_count + 1):
        frac = i / tick_count
        off = int(max_offset * frac)
        x = margin_left + int(plot_w * frac)
        draw.line([(x, margin_top + plot_h), (x, margin_top + plot_h + 4)], fill=(120, 125, 150))
        if off >= 1024 * 1024:
            txt = f"{off / (1024*1024):.1f}MB"
        elif off >= 1024:
            txt = f"{off / 1024:.0f}KB"
        else:
            txt = f"{off}B"
        draw.text((x - 12, margin_top + plot_h + 6), txt, fill=(140, 145, 170))

    return img


def detect_file_bounds(data: bytes) -> tuple[int, str]:
    """Find the legitimate end of standard image containers."""
    if len(data) < 16:
        return len(data), "Unknown"

    # JPEG: Find last EOI marker \xff\xd9
    if data[:2] == b"\xff\xd8":
        eoi = data.rfind(b"\xff\xd9")
        if eoi != -1:
            return eoi + 2, "JPEG"

    # PNG: Look for IEND chunk: length (00 00 00 00) + 'IEND' + 4-byte CRC
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        iend = data.find(b"IEND")
        if iend != -1 and iend + 8 <= len(data):
            return iend + 8, "PNG"

    # GIF: Trailer byte 0x3B
    if data[:6] in (b"GIF87a", b"GIF89a"):
        trailer = data.rfind(b"\x3b")
        if trailer != -1:
            return trailer + 1, "GIF"

    # WebP: RIFF length
    if data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
        payload_len = int.from_bytes(data[4:8], "little")
        total_len = payload_len + 8
        if total_len <= len(data):
            return total_len, "WebP"

    # BMP: Size in header at offset 2..6
    if data[:2] == b"BM" and len(data) >= 14:
        bmp_size = int.from_bytes(data[2:6], "little")
        if 14 <= bmp_size <= len(data):
            return bmp_size, "BMP"

    return len(data), "Image"


def detect_overlay(data: bytes) -> tuple[int, bytes]:
    """Detect trailing bytes past the legitimate image container."""
    expected_end, _fmt = detect_file_bounds(data)
    if expected_end < len(data):
        return expected_end, data[expected_end:]
    return len(data), b""


def scan_signatures(data: bytes, min_offset: int = 1) -> list[SignatureMatch]:
    """Scan raw bytes for embedded file headers (Binwalk-style)."""
    matches: list[SignatureMatch] = []
    data_len = len(data)

    # Check for trailing overlay
    overlay_offset, overlay_data = detect_overlay(data)
    if overlay_data:
        matches.append(
            SignatureMatch(
                offset=overlay_offset,
                name="Appended Overlay / Trailing Data",
                category="Payload",
                description=f"{len(overlay_data):,} bytes appended past legitimate end-of-file",
                size=len(overlay_data),
                confidence="High",
            )
        )

    # Search signatures
    for sig in SIGNATURES:
        magic: bytes = sig["magic"]
        magic_len = len(magic)
        rel_offset: int = sig.get("offset_relative", 0)
        validator = sig.get("validator")

        # Search throughout file
        pos = min_offset
        while pos < data_len:
            idx = data.find(magic, pos)
            if idx == -1:
                break

            actual_start = idx - rel_offset
            pos = idx + magic_len

            if actual_start < min_offset:
                continue

            # Run secondary structural validator if defined
            if validator and not validator(data, actual_start):
                continue

            # Reject short (<= 3 bytes) unvalidated matches inside compressed stream before overlay
            if len(magic) <= 3 and actual_start < overlay_offset and not validator:
                continue

            matches.append(
                SignatureMatch(
                    offset=actual_start,
                    name=sig["name"],
                    category=sig["category"],
                    description=sig["desc"],
                    confidence="High" if actual_start >= overlay_offset else "Medium",
                )
            )

    # Sort matches by byte offset
    matches.sort(key=lambda m: m.offset)
    return matches


def carve_files(data: bytes, output_dir: str, base_name: str = "carved") -> list[CarvedItem]:
    """Carve identified embedded payloads and overlay data to disk."""
    os.makedirs(output_dir, exist_ok=True)
    carved: list[CarvedItem] = []

    # 1. Carve overlay if present
    expected_end, overlay = detect_overlay(data)
    if overlay:
        overlay_name = f"{base_name}_offset_0x{expected_end:06x}_overlay.bin"
        target_path = os.path.join(output_dir, overlay_name)
        with open(target_path, "wb") as f:
            f.write(overlay)
        carved.append(
            CarvedItem(
                offset=expected_end,
                name="Trailing Overlay",
                filename=overlay_name,
                size=len(overlay),
                category="Payload",
            )
        )

    # 2. Carve discovered embedded files
    sigs = scan_signatures(data, min_offset=4)
    for i, match in enumerate(sigs):
        if match.name == "Appended Overlay / Trailing Data":
            continue
        start = match.offset
        # Estimate size up to next match or end of file
        end = len(data)
        for next_match in sigs[i + 1 :]:
            if next_match.offset > start:
                end = next_match.offset
                break

        slice_data = data[start:end]
        ext = "bin"
        for s in SIGNATURES:
            if s["name"] == match.name:
                ext = s.get("ext", "bin")
                break

        fname = f"{base_name}_offset_0x{start:06x}_{match.category.lower()}.{ext}"
        target_path = os.path.join(output_dir, fname)
        with open(target_path, "wb") as f:
            f.write(slice_data)

        carved.append(
            CarvedItem(
                offset=start,
                name=match.name,
                filename=fname,
                size=len(slice_data),
                category=match.category,
            )
        )

    return carved


def format_hex_dump(
    data: bytes, offset: int = 0, length: int = 256, bytes_per_line: int = 16
) -> str:
    """Format bytes as a classic hex + ASCII dump."""
    if offset < 0:
        offset = 0
    end = min(offset + length, len(data))
    chunk = data[offset:end]

    lines = []
    for line_offset in range(0, len(chunk), bytes_per_line):
        row = chunk[line_offset : line_offset + bytes_per_line]
        current_addr = offset + line_offset

        # Hex representation
        hex_parts = [f"{b:02x}" for b in row]
        if bytes_per_line == 16 and len(hex_parts) > 8:
            hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
        else:
            hex_str = " ".join(hex_parts)

        pad = " " * (bytes_per_line * 3 + (2 if bytes_per_line == 16 else 0) - len(hex_str))

        # ASCII representation
        ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in row]
        ascii_str = "".join(ascii_chars)

        lines.append(f"{current_addr:08x}  {hex_str}{pad} |{ascii_str}|")

    return "\n".join(lines)
