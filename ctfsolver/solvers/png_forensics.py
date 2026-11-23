"""PNG forensics solver: chunk parsing, CRC validation, IHDR dimension repair, text chunk extraction, trailing data carving, palette stego, and LSB analysis."""
from __future__ import annotations

import math
import os
import re
import struct
import zlib
from typing import Any

from ..flags import scan_bytes, scan_encoded, scan_text
from ..runner import have, run

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
STANDARD_CHUNKS = {
    "IHDR", "PLTE", "IDAT", "IEND",
    "cHRM", "gAMA", "iCCP", "sBIT", "sRGB",
    "bKGD", "hIST", "tRNS", "pHYs", "sPLT",
    "tIME", "iTXt", "tEXt", "zTXt", "eXIf",
    "acTL", "fcTL", "fdAT",
}


def parse_chunks(data: bytes) -> list[dict[str, Any]]:
    """Parse all PNG chunks (type, length, data, CRC). Validate CRCs and flag mismatches."""
    chunks: list[dict[str, Any]] = []
    if not data:
        return chunks

    sig_idx = data.find(PNG_SIGNATURE)
    if sig_idx != -1:
        pos = sig_idx + len(PNG_SIGNATURE)
    else:
        ihdr_idx = data.find(b"IHDR")
        if ihdr_idx >= 4:
            pos = ihdr_idx - 4
        else:
            pos = 0

    total_len = len(data)
    while pos + 8 <= total_len:
        chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype_bytes = data[pos + 4 : pos + 8]
        ctype = ctype_bytes.decode("latin-1", "replace")

        data_start = pos + 8
        data_end = data_start + chunk_len
        crc_end = data_end + 4

        if crc_end > total_len:
            # Chunk is truncated
            cdata = data[data_start:total_len]
            chunks.append({
                "type": ctype,
                "length": chunk_len,
                "data": cdata,
                "crc": None,
                "expected_crc": None,
                "crc_valid": False,
                "offset": pos,
                "data_offset": data_start,
                "truncated": True,
            })
            break

        cdata = data[data_start:data_end]
        stored_crc = struct.unpack(">I", data[data_end:crc_end])[0]
        expected_crc = zlib.crc32(ctype_bytes + cdata) & 0xFFFFFFFF
        crc_valid = (stored_crc == expected_crc)

        chunks.append({
            "type": ctype,
            "length": chunk_len,
            "data": cdata,
            "crc": stored_crc,
            "expected_crc": expected_crc,
            "crc_valid": crc_valid,
            "offset": pos,
            "data_offset": data_start,
            "truncated": False,
        })

        pos = crc_end
        if ctype == "IEND":
            break

    return chunks


def extract_text_chunks(data: bytes) -> list[dict[str, Any]]:
    """Extract tEXt, zTXt (zlib-compressed text), iTXt (international text) chunks.

    These often contain hidden flags or hints in CTF challenges.
    """
    text_entries: list[dict[str, Any]] = []
    chunks = parse_chunks(data)

    for c in chunks:
        ctype = c["type"]
        raw = c["data"]
        flags: list[dict[str, Any]] = []

        if ctype == "tEXt":
            parts = raw.split(b"\x00", 1)
            keyword = parts[0].decode("latin-1", "replace")
            text = parts[1].decode("latin-1", "replace") if len(parts) > 1 else ""
            flags = scan_text(text) + scan_bytes(raw)
            text_entries.append({
                "type": ctype,
                "keyword": keyword,
                "text": text,
                "compressed": False,
                "flags": _dedup_flags(flags),
            })

        elif ctype == "zTXt":
            parts = raw.split(b"\x00", 1)
            keyword = parts[0].decode("latin-1", "replace")
            text = ""
            decomp = b""
            if len(parts) > 1 and len(parts[1]) > 1:
                # byte 0 of parts[1] is compression method (must be 0)
                comp_bytes = parts[1][1:]
                try:
                    decomp = zlib.decompress(comp_bytes)
                    text = decomp.decode("latin-1", "replace")
                except Exception:
                    text = comp_bytes.decode("latin-1", "replace")
            flags = scan_text(text) + (scan_bytes(decomp) if decomp else []) + scan_bytes(raw)
            text_entries.append({
                "type": ctype,
                "keyword": keyword,
                "text": text,
                "compressed": True,
                "flags": _dedup_flags(flags),
            })

        elif ctype == "iTXt":
            idx0 = raw.find(b"\x00")
            keyword, text = "", ""
            lang_tag, trans_keyword = "", ""
            comp_flag = 0
            if idx0 != -1:
                keyword = raw[:idx0].decode("utf-8", "replace")
                rem = raw[idx0 + 1 :]
                if len(rem) >= 2:
                    comp_flag = rem[0]
                    # rem[1] is compression method (0)
                    rem2 = rem[2:]
                    idx1 = rem2.find(b"\x00")
                    if idx1 != -1:
                        lang_tag = rem2[:idx1].decode("latin-1", "replace")
                        rem3 = rem2[idx1 + 1 :]
                        idx2 = rem3.find(b"\x00")
                        if idx2 != -1:
                            trans_keyword = rem3[:idx2].decode("utf-8", "replace")
                            text_bytes = rem3[idx2 + 1 :]
                        else:
                            text_bytes = rem3
                    else:
                        text_bytes = rem2

                    if comp_flag == 1:
                        try:
                            decomp = zlib.decompress(text_bytes)
                            text = decomp.decode("utf-8", "replace")
                        except Exception:
                            text = text_bytes.decode("utf-8", "replace")
                    else:
                        text = text_bytes.decode("utf-8", "replace")
            flags = scan_text(text) + scan_bytes(raw)
            text_entries.append({
                "type": ctype,
                "keyword": keyword,
                "text": text,
                "language": lang_tag,
                "translated_keyword": trans_keyword,
                "compressed": bool(comp_flag),
                "flags": _dedup_flags(flags),
            })

        elif ctype not in STANDARD_CHUNKS:
            # Custom / non-standard chunk that may contain text or flags
            found = scan_bytes(raw) + scan_encoded(raw)
            if found or any(32 <= b <= 126 for b in raw):
                clean_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:200])
                text_entries.append({
                    "type": ctype,
                    "keyword": "custom_chunk",
                    "text": clean_text,
                    "compressed": False,
                    "flags": _dedup_flags(found),
                })

    return text_entries


def check_ihdr(data: bytes) -> dict[str, Any]:
    """Validate IHDR dimensions.

    Detect CTF tricks:
    1. Height or width tampered without recalculating IHDR CRC.
    2. Height tampered with valid CRC, leaving trailing unrendered IDAT rows.
    Returns suggested true dimensions.
    """
    chunks = parse_chunks(data)
    ihdr_chunk = next((c for c in chunks if c["type"] == "IHDR"), None)

    if not ihdr_chunk or len(ihdr_chunk["data"]) < 13:
        return {
            "is_valid": False,
            "width": 0,
            "height": 0,
            "suggested_width": 0,
            "suggested_height": 0,
            "crc_valid": False,
            "issues": ["IHDR chunk missing or corrupted"],
        }

    raw = ihdr_chunk["data"]
    width, height, bit_depth, color_type, comp_method, filter_method, interlace_method = struct.unpack(
        ">IIBBBBB", raw[:13]
    )

    channel_map = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
    channels = channel_map.get(color_type, 1)
    bpp = channels * bit_depth if color_type != 3 else bit_depth
    line_bytes = (width * bpp + 7) // 8
    stride = 1 + line_bytes
    expected_decomp_len = height * stride if interlace_method == 0 else 0

    stored_crc = ihdr_chunk["crc"]
    expected_crc = ihdr_chunk["expected_crc"]
    crc_valid = ihdr_chunk["crc_valid"]

    recovered_height: int | None = None
    recovered_width: int | None = None
    issues: list[str] = []

    # 1. CRC mismatch detection & recovery
    if not crc_valid and stored_crc is not None:
        issues.append(f"IHDR CRC mismatch: stored 0x{stored_crc:08X} != calculated 0x{expected_crc:08X}")
        # Brute force height (most common: image cropped to hide flag)
        for test_h in range(1, 15001):
            test_ihdr = struct.pack(
                ">IIBBBBB", width, test_h, bit_depth, color_type, comp_method, filter_method, interlace_method
            )
            if (zlib.crc32(b"IHDR" + test_ihdr) & 0xFFFFFFFF) == stored_crc:
                recovered_height = test_h
                issues.append(f"CRC recovered original height: {test_h} (stated: {height})")
                break

        # Brute force width (if height wasn't the modified field)
        if recovered_height is None:
            for test_w in range(1, 15001):
                test_ihdr = struct.pack(
                    ">IIBBBBB", test_w, height, bit_depth, color_type, comp_method, filter_method, interlace_method
                )
                if (zlib.crc32(b"IHDR" + test_ihdr) & 0xFFFFFFFF) == stored_crc:
                    recovered_width = test_w
                    issues.append(f"CRC recovered original width: {test_w} (stated: {width})")
                    break

    # 2. Check decompressed IDAT length against stated dimensions
    idat_bytes = b"".join(c["data"] for c in chunks if c["type"] == "IDAT")
    decomp_bytes = b""
    if idat_bytes:
        try:
            decomp_bytes = zlib.decompress(idat_bytes)
        except Exception:
            try:
                decomp_bytes = zlib.decompressobj().decompress(idat_bytes)
            except Exception:
                decomp_bytes = b""

    actual_decomp_len = len(decomp_bytes)
    calculated_height: int | None = None
    has_trailing_idat = False

    if actual_decomp_len > 0 and stride > 0 and interlace_method == 0:
        calculated_height = actual_decomp_len // stride
        if actual_decomp_len > expected_decomp_len:
            has_trailing_idat = True
            issues.append(
                f"Trailing IDAT data: decompressed {actual_decomp_len} bytes > expected {expected_decomp_len} bytes"
            )
            if calculated_height > height:
                issues.append(
                    f"Calculated true height from IDAT data: {calculated_height} rows (stated: {height})"
                )

    # Determine suggested dimensions
    suggested_height = height
    if recovered_height is not None:
        suggested_height = recovered_height
    elif calculated_height is not None and calculated_height > height:
        suggested_height = calculated_height

    suggested_width = width
    if recovered_width is not None:
        suggested_width = recovered_width

    is_valid = bool(crc_valid and not has_trailing_idat and (recovered_height is None) and (recovered_width is None))

    return {
        "width": width,
        "height": height,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "compression": comp_method,
        "filter": filter_method,
        "interlace": interlace_method,
        "channels": channels,
        "bpp": bpp,
        "stride": stride,
        "crc_valid": crc_valid,
        "stored_crc": stored_crc,
        "expected_crc": expected_crc,
        "crc_recovered_height": recovered_height,
        "crc_recovered_width": recovered_width,
        "decompressed_bytes": actual_decomp_len,
        "expected_decompressed_bytes": expected_decomp_len,
        "calculated_height": calculated_height,
        "has_trailing_idat": has_trailing_idat,
        "suggested_width": suggested_width,
        "suggested_height": suggested_height,
        "is_valid": is_valid,
        "issues": issues,
    }


def fix_ihdr_dimensions(data: bytes, new_width: int | None = None, new_height: int | None = None) -> bytes:
    """Rewrite IHDR with corrected width and/or height and recomputed valid CRC."""
    ihdr_idx = data.find(b"IHDR")
    if ihdr_idx < 4 or ihdr_idx + 17 > len(data):
        return data

    ba = bytearray(data)
    if new_width is not None:
        struct.pack_into(">I", ba, ihdr_idx + 4, new_width)
    if new_height is not None:
        struct.pack_into(">I", ba, ihdr_idx + 8, new_height)

    # Recompute CRC over 'IHDR' (4 bytes) + chunk data (13 bytes) = 17 bytes
    new_crc = zlib.crc32(ba[ihdr_idx : ihdr_idx + 17]) & 0xFFFFFFFF
    struct.pack_into(">I", ba, ihdr_idx + 17, new_crc)
    return bytes(ba)


def fix_ihdr_height(data: bytes, new_height: int) -> bytes:
    """Rewrite IHDR with corrected height and valid CRC. This reveals hidden rows."""
    return fix_ihdr_dimensions(data, new_width=None, new_height=new_height)


def brute_ihdr_dimensions(data: bytes, workdir: str) -> list[dict[str, Any]]:
    """Try heights from current to current*3 and widths around current.

    Decompresses IDAT to find which dimensions produce valid decompressed data length.
    Saves corrected PNGs to workdir.
    """
    ihdr_info = check_ihdr(data)
    current_w = ihdr_info.get("width", 0)
    current_h = ihdr_info.get("height", 0)
    bpp = ihdr_info.get("bpp", 24)

    chunks = parse_chunks(data)
    idat_bytes = b"".join(c["data"] for c in chunks if c["type"] == "IDAT")
    decomp = b""
    if idat_bytes:
        try:
            decomp = zlib.decompress(idat_bytes)
        except Exception:
            try:
                decomp = zlib.decompressobj().decompress(idat_bytes)
            except Exception:
                decomp = b""

    total_len = len(decomp)
    candidates: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int]] = set()

    # 1. CRC recovered dimensions
    if ihdr_info.get("crc_recovered_height"):
        rec_h = ihdr_info["crc_recovered_height"]
        if (current_w, rec_h) not in seen:
            seen.add((current_w, rec_h))
            candidates.append((current_w, rec_h, "CRC recovered height"))

    if ihdr_info.get("crc_recovered_width"):
        rec_w = ihdr_info["crc_recovered_width"]
        if (rec_w, current_h) not in seen:
            seen.add((rec_w, current_h))
            candidates.append((rec_w, current_h, "CRC recovered width"))

    # 2. Exact length match from IDAT decompression
    if total_len > 0 and current_w > 0:
        stride0 = 1 + ((current_w * bpp + 7) // 8)
        if stride0 > 0:
            calc_h = total_len // stride0
            if calc_h != current_h and (current_w, calc_h) not in seen:
                seen.add((current_w, calc_h))
                candidates.append((current_w, calc_h, "IDAT decompressed exact height"))

            # Heights from current_h to current_h * 3
            max_h = max(current_h * 3, current_h + 100)
            for h in range(max(1, current_h), max_h + 1):
                if h * stride0 == total_len and (current_w, h) not in seen:
                    seen.add((current_w, h))
                    candidates.append((current_w, h, "IDAT length match"))

        # Widths around current_w (+- 50)
        for dw in range(-50, 51):
            if dw == 0:
                continue
            w = current_w + dw
            if w <= 0:
                continue
            s = 1 + ((w * bpp + 7) // 8)
            if s > 0 and total_len % s == 0:
                h = total_len // s
                if 1 <= h <= max(current_h * 3, 2000) and (w, h) not in seen:
                    seen.add((w, h))
                    candidates.append((w, h, f"IDAT length match with adjusted width ({w}x{h})"))

    results: list[dict[str, Any]] = []
    for w, h, reason in candidates:
        fixed_png = fix_ihdr_dimensions(data, new_width=w, new_height=h)
        out_path = ""
        if workdir:
            try:
                os.makedirs(workdir, exist_ok=True)
                out_path = os.path.join(workdir, f"fixed_{w}x{h}.png")
                with open(out_path, "wb") as f:
                    f.write(fixed_png)
            except OSError:
                out_path = ""

        flags = scan_bytes(fixed_png) + scan_encoded(fixed_png)
        if decomp:
            flags += scan_bytes(decomp) + scan_encoded(decomp)

        results.append({
            "width": w,
            "height": h,
            "reason": reason,
            "path": out_path,
            "flags": _dedup_flags(flags),
            "data_len": len(fixed_png),
        })

    return results


def extract_trailing_data(data: bytes) -> bytes:
    """Extract any data appended after the IEND chunk (appended files/flags)."""
    if not data:
        return b""
    chunks = parse_chunks(data)
    for c in chunks:
        if c["type"] == "IEND":
            iend_end = c["offset"] + 12
            if iend_end < len(data):
                return data[iend_end:]
            return b""

    # Fallback if parse_chunks stopped or missed IEND
    idx = data.rfind(b"IEND")
    if idx != -1:
        iend_end = idx + 8
        if iend_end < len(data):
            return data[iend_end:]
    return b""


def check_palette_stego(data: bytes) -> list[str]:
    """For palette-based (type 3) PNGs, check PLTE chunk for hidden messages in color values."""
    chunks = parse_chunks(data)
    plte_chunk = next((c for c in chunks if c["type"] == "PLTE"), None)
    if not plte_chunk or not plte_chunk["data"]:
        return []

    plte = plte_chunk["data"]
    num_colors = len(plte) // 3
    findings: list[str] = []

    # 1. Plaintext strings and flags directly in PLTE
    for f in scan_bytes(plte):
        findings.append(f["flag"])
    for m in re.findall(rb"[\x20-\x7e]{4,}", plte):
        findings.append(m.decode("latin-1"))

    # 2. Channel-separated bytes (R, G, B channels individually)
    r_bytes = bytes(plte[i] for i in range(0, len(plte), 3))
    g_bytes = bytes(plte[i] for i in range(1, len(plte), 3))
    b_bytes = bytes(plte[i] for i in range(2, len(plte), 3))

    for ch_name, ch_bytes in (("R", r_bytes), ("G", g_bytes), ("B", b_bytes)):
        for f in scan_bytes(ch_bytes):
            findings.append(f["flag"])
        for m in re.findall(rb"[\x20-\x7e]{4,}", ch_bytes):
            findings.append(m.decode("latin-1"))

    # 3. LSBs of palette bytes
    bits = [b & 1 for b in plte]
    lsb_bytes = _bits_to_bytes_msb(bits)
    for f in scan_bytes(lsb_bytes):
        findings.append(f["flag"])
    for m in re.findall(rb"[\x20-\x7e]{4,}", lsb_bytes):
        findings.append(m.decode("latin-1"))

    # 4. Unused palette entries
    idat_bytes = b"".join(c["data"] for c in chunks if c["type"] == "IDAT")
    if idat_bytes:
        try:
            decomp = zlib.decompress(idat_bytes)
            ihdr = check_ihdr(data)
            w = ihdr.get("width", 0)
            h = ihdr.get("height", 0)
            bpp = ihdr.get("bpp", 8)
            stride = 1 + ((w * bpp + 7) // 8)
            used: set[int] = set()
            for r in range(h):
                row_start = r * stride + 1
                row_end = (r + 1) * stride
                if row_end <= len(decomp):
                    used.update(decomp[row_start:row_end])
            unused = [i for i in range(num_colors) if i not in used]
            if unused:
                unused_bytes = bytearray()
                for u in unused:
                    unused_bytes.extend(plte[u * 3 : (u + 1) * 3])
                for f in scan_bytes(bytes(unused_bytes)):
                    findings.append(f["flag"])
                for m in re.findall(rb"[\x20-\x7e]{4,}", bytes(unused_bytes)):
                    findings.append(m.decode("latin-1"))
        except Exception:
            pass

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in findings:
        clean = item.strip()
        if clean and clean not in seen:
            seen.add(clean)
            unique.append(clean)
    return unique


def unfilter_scanlines(decomp_data: bytes, width: int, height: int, bpp: int) -> bytes:
    """Reconstruct unfiltered pixel bytes from decompressed scanline data."""
    bpp_bytes = max(1, (bpp + 7) // 8)
    line_bytes = (width * bpp + 7) // 8
    stride = 1 + line_bytes
    if stride <= 1 or len(decomp_data) < stride:
        return decomp_data

    # Limit to first 1000 rows for high performance
    actual_rows = min(height, len(decomp_data) // stride, 1000)
    out = bytearray(actual_rows * line_bytes)
    prior = bytearray(line_bytes)

    for r in range(actual_rows):
        row_offset = r * stride
        filter_type = decomp_data[row_offset]
        scanline = decomp_data[row_offset + 1 : row_offset + stride]
        current = bytearray(line_bytes)
        slen = len(scanline)

        if filter_type == 0:  # None
            current[:slen] = scanline
        elif filter_type == 1:  # Sub
            for i in range(slen):
                left = current[i - bpp_bytes] if i >= bpp_bytes else 0
                current[i] = (scanline[i] + left) & 0xFF
        elif filter_type == 2:  # Up
            for i in range(slen):
                up = prior[i]
                current[i] = (scanline[i] + up) & 0xFF
        elif filter_type == 3:  # Average
            for i in range(slen):
                left = current[i - bpp_bytes] if i >= bpp_bytes else 0
                up = prior[i]
                current[i] = (scanline[i] + ((left + up) // 2)) & 0xFF
        elif filter_type == 4:  # Paeth
            for i in range(slen):
                left = current[i - bpp_bytes] if i >= bpp_bytes else 0
                up = prior[i]
                up_left = prior[i - bpp_bytes] if i >= bpp_bytes else 0
                p = left + up - up_left
                pa = abs(p - left)
                pb = abs(p - up)
                pc = abs(p - up_left)
                pred = left if (pa <= pb and pa <= pc) else (up if pb <= pc else up_left)
                current[i] = (scanline[i] + pred) & 0xFF
        else:
            current[:slen] = scanline

        out[r * line_bytes : (r + 1) * line_bytes] = current
        prior = current

    return bytes(out)


def _bits_to_bytes_msb(bits: list[int] | bytes) -> bytes:
    out = bytearray()
    n = len(bits) - (len(bits) % 8)
    for i in range(0, n, 8):
        b = (
            (bits[i] << 7)
            | (bits[i + 1] << 6)
            | (bits[i + 2] << 5)
            | (bits[i + 3] << 4)
            | (bits[i + 4] << 3)
            | (bits[i + 5] << 2)
            | (bits[i + 6] << 1)
            | bits[i + 7]
        )
        out.append(b)
    return bytes(out)


def _bits_to_bytes_lsb(bits: list[int] | bytes) -> bytes:
    out = bytearray()
    n = len(bits) - (len(bits) % 8)
    for i in range(0, n, 8):
        b = (
            bits[i]
            | (bits[i + 1] << 1)
            | (bits[i + 2] << 2)
            | (bits[i + 3] << 3)
            | (bits[i + 4] << 4)
            | (bits[i + 5] << 5)
            | (bits[i + 6] << 6)
            | (bits[i + 7] << 7)
        )
        out.append(b)
    return bytes(out)


def _chi_square_pov(samples: bytes) -> tuple[float, float]:
    """Perform Pairs of Values (PoV) chi-square test for LSB replacement steganography."""
    if not samples:
        return 0.0, 1.0
    counts = [0] * 256
    for b in samples:
        counts[b] += 1
    chi2 = 0.0
    df = 0
    for k in range(128):
        c0 = counts[2 * k]
        c1 = counts[2 * k + 1]
        tot = c0 + c1
        if tot > 0:
            df += 1
            chi2 += ((c0 - c1) ** 2) / tot
    norm_chi2 = (chi2 / df) if df > 0 else 0.0
    return chi2, norm_chi2


def detect_lsb_indicator(data: bytes) -> dict[str, Any]:
    """Check if pixel LSBs look non-random (statistical tests and sequential scan on pixel data)."""
    chunks = parse_chunks(data)
    idat_bytes = b"".join(c["data"] for c in chunks if c["type"] == "IDAT")
    if not idat_bytes:
        return {
            "detected": False,
            "confidence": "none",
            "channels": {},
            "flags": [],
            "suspicious_patterns": [],
            "summary": "No IDAT chunk available for LSB analysis",
        }

    decomp = b""
    try:
        decomp = zlib.decompress(idat_bytes)
    except Exception:
        try:
            decomp = zlib.decompressobj().decompress(idat_bytes)
        except Exception:
            decomp = b""

    if not decomp:
        return {
            "detected": False,
            "confidence": "none",
            "channels": {},
            "flags": [],
            "suspicious_patterns": [],
            "summary": "IDAT decompression failed",
        }

    ihdr_info = check_ihdr(data)
    width = ihdr_info.get("width", 0)
    height = ihdr_info.get("height", 0)
    color_type = ihdr_info.get("color_type", 2)
    bpp = ihdr_info.get("bpp", 24)

    # Reconstruct unfiltered pixels
    pixels = unfilter_scanlines(decomp, width, height, bpp)
    if not pixels:
        pixels = decomp

    # Prepare channel streams
    channel_samples: dict[str, bytes] = {}
    if color_type == 2:  # RGB
        channel_samples["R"] = pixels[0::3]
        channel_samples["G"] = pixels[1::3]
        channel_samples["B"] = pixels[2::3]
        channel_samples["RGB"] = pixels
    elif color_type == 6:  # RGBA
        channel_samples["R"] = pixels[0::4]
        channel_samples["G"] = pixels[1::4]
        channel_samples["B"] = pixels[2::4]
        channel_samples["A"] = pixels[3::4]
        # RGB only (skip alpha)
        rgb_bytes = bytearray()
        for i in range(0, len(pixels) - 3, 4):
            rgb_bytes.extend(pixels[i : i + 3])
        channel_samples["RGB"] = bytes(rgb_bytes)
        channel_samples["RGBA"] = pixels
    else:
        channel_samples["gray"] = pixels

    flags: list[dict[str, Any]] = []
    suspicious_patterns: list[str] = []
    channel_stats: dict[str, Any] = {}
    detected = False
    confidence = "none"

    known_headers = [
        (b"PK\x03\x04", "ZIP archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"\x1f\x8b", "GZIP archive"),
        (b"BZh", "Bzip2 archive"),
        (b"\x89PNG", "PNG image"),
        (b"GIF89a", "GIF image"),
        (b"flag{", "Flag text"),
        (b"FLAG{", "Flag text"),
        (b"CTF{", "Flag text"),
    ]

    for name, sample in channel_samples.items():
        if len(sample) < 32:
            continue

        # Limit analysis to first 200,000 bytes for speed
        cur_sample = sample[:200000]
        sample_len = len(cur_sample)

        # 1. Ones ratio in LSB
        ones_count = sum(b & 1 for b in cur_sample)
        ones_ratio = ones_count / sample_len

        # 2. Chi-square PoV
        _, norm_chi2 = _chi_square_pov(cur_sample)

        # 3. Extract sequential LSB bytes (MSB-first and LSB-first)
        bits = [b & 1 for b in cur_sample]
        stream_msb = _bits_to_bytes_msb(bits)
        stream_lsb = _bits_to_bytes_lsb(bits)

        # Check for flags in LSB streams
        f_msb = scan_bytes(stream_msb) + scan_encoded(stream_msb)
        f_lsb = scan_bytes(stream_lsb) + scan_encoded(stream_lsb)
        if f_msb:
            for f in f_msb:
                f["method"] = f"lsb-{name}-msb"
            flags.extend(f_msb)
        if f_lsb:
            for f in f_lsb:
                f["method"] = f"lsb-{name}-lsb"
            flags.extend(f_lsb)

        # Check for known file headers or high printable ASCII ratio
        ascii_ratio = 0.0
        header_found = ""
        for stream, order in ((stream_msb, "MSB"), (stream_lsb, "LSB")):
            for magic, desc in known_headers:
                if stream.startswith(magic):
                    header_found = f"{desc} in {name} ({order})"
                    suspicious_patterns.append(f"Magic header {header_found}")
                    detected = True
                    confidence = "high"

            test_chunk = stream[:256]
            if len(test_chunk) >= 32:
                asc = sum(32 <= c <= 126 or c in (10, 13, 9) for c in test_chunk)
                ar = asc / len(test_chunk)
                if ar > ascii_ratio:
                    ascii_ratio = ar
                if ar > 0.70:
                    sample_txt = test_chunk[:40].decode("latin-1", "replace")
                    suspicious_patterns.append(f"High ASCII ratio ({ar:.1%}) in {name} ({order}): '{sample_txt}'")
                    detected = True
                    confidence = "high"

        # Statistical check: LSB replacement typically flattens PoV (norm_chi2 < 0.5)
        # or ASCII LSB text produces ones_ratio around 0.40 - 0.46
        if norm_chi2 < 0.3 and sample_len > 1000:
            suspicious_patterns.append(f"PoV chi-square anomaly in {name}: norm_chi2={norm_chi2:.3f}")
            detected = True
            if confidence == "none":
                confidence = "medium"

        if 0.38 <= ones_ratio <= 0.46 and sample_len > 1000:
            suspicious_patterns.append(f"ASCII-like LSB bit bias in {name}: ones_ratio={ones_ratio:.3f}")
            detected = True
            if confidence == "none":
                confidence = "medium"

        channel_stats[name] = {
            "ones_ratio": round(ones_ratio, 4),
            "norm_chi2": round(norm_chi2, 4),
            "ascii_ratio": round(ascii_ratio, 4),
            "sample_len": sample_len,
        }

    if flags:
        detected = True
        confidence = "high"

    summary_text = (
        f"LSB stego indicators: {confidence.upper()} confidence ({len(flags)} flag(s), "
        f"{len(suspicious_patterns)} anomaly pattern(s))"
    )

    return {
        "detected": detected,
        "confidence": confidence,
        "channels": channel_stats,
        "flags": _dedup_flags(flags),
        "suspicious_patterns": suspicious_patterns,
        "summary": summary_text,
    }


def _dedup_flags(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in flags:
        val = f.get("flag", "")
        if val and val not in seen:
            seen.add(val)
            unique.append(f)
    return unique


def solve(target: str, workdir: str = "") -> dict[str, Any]:
    """Execute comprehensive PNG forensics and stego analysis.

    Runs chunk validation, IHDR dimension repair, text chunk extraction,
    trailing data carving, palette stego detection, and LSB analysis.
    """
    if not os.path.isfile(target):
        return {
            "step": "png-forensics",
            "flags": [],
            "output": f"Target file not found: {target}",
            "artifacts": [],
        }

    try:
        with open(target, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return {
            "step": "png-forensics",
            "flags": [],
            "output": f"Error reading target file: {e}",
            "artifacts": [],
        }

    # Verify PNG signature or content
    if PNG_SIGNATURE not in data and b"IHDR" not in data:
        return {
            "step": "png-forensics",
            "flags": [],
            "output": "Target is not a valid PNG file (PNG signature not found).",
            "artifacts": [],
        }

    all_flags: list[dict[str, Any]] = []
    artifacts: list[str] = []
    output_lines: list[str] = []

    if workdir:
        os.makedirs(workdir, exist_ok=True)

    # 1. Plain byte sweep on the raw file
    raw_flags = scan_bytes(data) + scan_encoded(data)
    for f in raw_flags:
        f["method"] = "png-raw-bytes"
    all_flags.extend(raw_flags)

    # 2. Parse chunks & validate CRCs
    chunks = parse_chunks(data)
    chunk_types = [c["type"] for c in chunks]
    crc_mismatches = [c for c in chunks if not c["crc_valid"] and not c.get("truncated")]
    output_lines.append(f"[*] Parsed {len(chunks)} PNG chunk(s): {', '.join(chunk_types)}")

    if crc_mismatches:
        for c in crc_mismatches:
            output_lines.append(
                f"[!] CRC mismatch in {c['type']} chunk: stored=0x{c['crc']:08X}, expected=0x{c['expected_crc']:08X}"
            )

    # 3. Text chunk extraction (tEXt, zTXt, iTXt, custom)
    text_chunks = extract_text_chunks(data)
    if text_chunks:
        output_lines.append(f"[*] Found {len(text_chunks)} text/metadata chunk(s):")
        for tc in text_chunks:
            kw = tc.get("keyword", "")
            txt = tc.get("text", "")
            preview = (txt[:100] + "...") if len(txt) > 100 else txt
            output_lines.append(f"    - [{tc['type']}] {kw}: {preview}")
            for f in tc.get("flags", []):
                f["method"] = f"png-text-{tc['type'].lower()}"
                all_flags.append(f)

    # 4. Trailing data after IEND
    trailing = extract_trailing_data(data)
    if trailing:
        output_lines.append(f"[!] Extracted {len(trailing)} byte(s) of trailing data after IEND chunk!")
        t_flags = scan_bytes(trailing) + scan_encoded(trailing)
        for f in t_flags:
            f["method"] = "png-trailing-data"
            all_flags.append(f)

        if workdir:
            ext = ".bin"
            if trailing.startswith(b"PK\x03\x04"):
                ext = ".zip"
            elif trailing.startswith(b"\x89PNG"):
                ext = ".png"
            elif trailing.startswith(b"\x1f\x8b"):
                ext = ".tar.gz"
            elif trailing.startswith(b"\x7fELF"):
                ext = ".elf"
            trailing_path = os.path.join(workdir, f"trailing_data{ext}")
            try:
                with open(trailing_path, "wb") as tfh:
                    tfh.write(trailing)
                artifacts.append(trailing_path)
                output_lines.append(f"    -> Saved trailing data to {trailing_path}")
            except OSError:
                pass

    # 5. IHDR Dimension analysis and repair
    ihdr_res = check_ihdr(data)
    w0 = ihdr_res.get("width", 0)
    h0 = ihdr_res.get("height", 0)
    s_w = ihdr_res.get("suggested_width", w0)
    s_h = ihdr_res.get("suggested_height", h0)
    output_lines.append(f"[*] IHDR stated dimensions: {w0}x{h0} (bit_depth={ihdr_res.get('bit_depth')}, color_type={ihdr_res.get('color_type')})")

    if ihdr_res.get("issues"):
        for issue in ihdr_res["issues"]:
            output_lines.append(f"    [!] {issue}")

    if s_w != w0 or s_h != h0:
        output_lines.append(f"[!] Corrected dimensions suggested: {s_w}x{s_h}")
        fixed_png = fix_ihdr_dimensions(data, new_width=s_w, new_height=s_h)
        if workdir:
            fixed_path = os.path.join(workdir, f"fixed_{s_w}x{s_h}.png")
            try:
                with open(fixed_path, "wb") as f_out:
                    f_out.write(fixed_png)
                artifacts.append(fixed_path)
                output_lines.append(f"    -> Saved corrected PNG to {fixed_path}")
            except OSError:
                pass
        f_flags = scan_bytes(fixed_png) + scan_encoded(fixed_png)
        for f in f_flags:
            f["method"] = "png-fixed-ihdr"
            all_flags.append(f)

    # Brute-force dimensions if trailing IDAT detected or dimensions suspect
    if ihdr_res.get("has_trailing_idat") or not ihdr_res.get("is_valid"):
        brute_results = brute_ihdr_dimensions(data, workdir)
        for br in brute_results:
            if br.get("path") and br["path"] not in artifacts:
                artifacts.append(br["path"])
            for f in br.get("flags", []):
                f["method"] = "png-brute-ihdr"
                all_flags.append(f)

    # 6. Palette steganography (if color_type 3 or PLTE present)
    if ihdr_res.get("color_type") == 3 or any(c["type"] == "PLTE" for c in chunks):
        palette_msgs = check_palette_stego(data)
        if palette_msgs:
            output_lines.append(f"[*] Palette stego sweep found {len(palette_msgs)} string(s)/pattern(s):")
            for msg in palette_msgs[:10]:
                output_lines.append(f"    - {msg}")
                p_flags = scan_text(msg)
                for f in p_flags:
                    f["method"] = "png-palette"
                    all_flags.append(f)

    # 7. LSB Steganography analysis
    lsb_res = detect_lsb_indicator(data)
    if lsb_res.get("detected"):
        output_lines.append(f"[!] {lsb_res.get('summary', 'LSB indicator detected')}")
        for pat in lsb_res.get("suspicious_patterns", []):
            output_lines.append(f"    - {pat}")
        for f in lsb_res.get("flags", []):
            all_flags.append(f)

    # 8. Decompressed IDAT plain byte sweep
    idat_bytes = b"".join(c["data"] for c in chunks if c["type"] == "IDAT")
    if idat_bytes:
        try:
            decomp = zlib.decompress(idat_bytes)
            decomp_flags = scan_bytes(decomp) + scan_encoded(decomp)
            for f in decomp_flags:
                f["method"] = "png-decompressed-idat"
                all_flags.append(f)
        except Exception:
            pass

    # 9. Graceful external tool fallback if available (pngcheck, zsteg)
    if have("pngcheck"):
        r_pc = run(["pngcheck", "-vpt7", target], timeout=15)
        if r_pc.ok() and r_pc.stdout:
            for f in scan_text(r_pc.stdout):
                f["method"] = "pngcheck"
                all_flags.append(f)

    if have("zsteg"):
        r_zs = run(["zsteg", "-a", target], timeout=30)
        if r_zs.ok() and r_zs.stdout:
            output_lines.append("[*] Ran zsteg analysis on target")
            for f in scan_text(r_zs.stdout):
                f["method"] = "zsteg"
                all_flags.append(f)

    deduped = _dedup_flags(all_flags)
    output_lines.append(f"[*] Completed PNG forensics analysis. Total flag(s) found: {len(deduped)}")

    return {
        "step": "png-forensics",
        "summary": f"PNG forensics analysis ({len(deduped)} flag(s) found)",
        "output": "\n".join(output_lines),
        "flags": deduped,
        "artifacts": artifacts,
    }
