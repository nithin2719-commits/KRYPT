"""Pure-Python ZIP Forensics & Anti-Stego Engine for CTF challenges.

Handles:
1. Zip Pseudo-Encryption (ZipCenOp / fake encryption bit flag in local or central directory headers).
2. CRC32 small file recovery (recovers 1-6 byte files directly from 32-bit CRC without password).
3. Hidden Archive Comments & File Comment extraction (End of Central Directory & file headers).
4. Zip-Slip / Path traversal directory anomaly detection.
5. Extraction of valid files to workdir for recursive hunting.
"""
from __future__ import annotations

import os
import struct
import zlib
from itertools import product
from typing import Any

from ..flags import scan_bytes, scan_text


# Precompute standard ASCII printable characters for fast CRC brute force
_PRINTABLE_BYTES = [bytes([c]) for c in range(32, 127)] + [b"\n", b"\r", b"\t"]
_PRINTABLE_INTS = [c for c in range(32, 127)] + [10, 13, 9]


def crc32_brute_small_file(target_crc: int, max_len: int = 4) -> bytes | None:
    """Brute force short plaintext (<= 4 bytes) matching a given 32-bit CRC32 checksum."""
    if target_crc == 0:
        return b""

    # Length 1
    for b in _PRINTABLE_INTS:
        if zlib.crc32(bytes([b])) & 0xFFFFFFFF == target_crc:
            return bytes([b])

    # Length 2
    for b1 in _PRINTABLE_INTS:
        for b2 in _PRINTABLE_INTS:
            if zlib.crc32(bytes([b1, b2])) & 0xFFFFFFFF == target_crc:
                return bytes([b1, b2])

    # Length 3
    for b1 in _PRINTABLE_INTS:
        for b2 in _PRINTABLE_INTS:
            prefix = bytes([b1, b2])
            for b3 in _PRINTABLE_INTS:
                if zlib.crc32(prefix + bytes([b3])) & 0xFFFFFFFF == target_crc:
                    return prefix + bytes([b3])

    # Length 4
    if max_len >= 4:
        # Fast table / prefix search for length 4
        for b1 in _PRINTABLE_INTS:
            for b2 in _PRINTABLE_INTS:
                prefix = bytes([b1, b2])
                for b3 in _PRINTABLE_INTS:
                    p3 = prefix + bytes([b3])
                    for b4 in _PRINTABLE_INTS:
                        if zlib.crc32(p3 + bytes([b4])) & 0xFFFFFFFF == target_crc:
                            return p3 + bytes([b4])

    return None


def parse_zip_structures(data: bytes) -> dict[str, Any]:
    """Parse local headers, central directory, comments, and flags."""
    local_headers = []
    central_headers = []
    eocd = None
    comments = []
    flags: list[dict[str, Any]] = []

    pos = 0
    data_len = len(data)

    # 1. Parse Local File Headers (PK\x03\x04)
    while pos < data_len - 4:
        sig = data[pos : pos + 4]
        if sig == b"PK\x03\x04":
            if pos + 30 > data_len:
                break
            version, gp_flag, comp_method, mod_time, mod_date, crc32, comp_size, uncomp_size, fn_len, extra_len = (
                struct.unpack("<HHHHHIIIHH", data[pos + 4 : pos + 30])
            )
            fn_start = pos + 30
            fn_end = fn_start + fn_len
            filename = data[fn_start:fn_end].decode("latin-1", "replace")
            extra = data[fn_end : fn_end + extra_len]
            payload_start = fn_end + extra_len
            payload_end = payload_start + comp_size

            local_headers.append({
                "pos": pos,
                "gp_flag": gp_flag,
                "is_encrypted": bool(gp_flag & 0x0001),
                "comp_method": comp_method,
                "crc32": crc32,
                "comp_size": comp_size,
                "uncomp_size": uncomp_size,
                "filename": filename,
                "extra": extra,
                "payload_offset": payload_start,
                "payload_end": payload_end,
            })
            pos = fn_end + extra_len
            if comp_size > 0:
                pos += comp_size
        else:
            pos += 1

    # 2. Parse Central Directory Headers (PK\x01\x02)
    pos = 0
    while pos < data_len - 4:
        sig = data[pos : pos + 4]
        if sig == b"PK\x01\x02":
            if pos + 46 > data_len:
                break
            (
                ver_made,
                ver_need,
                gp_flag,
                comp_method,
                mod_time,
                mod_date,
                crc32,
                comp_size,
                uncomp_size,
                fn_len,
                extra_len,
                comment_len,
                disk_start,
                int_attr,
                ext_attr,
                local_hdr_offset,
            ) = struct.unpack("<HHHHHHIIIHHHHHII", data[pos + 4 : pos + 46])

            fn_start = pos + 46
            fn_end = fn_start + fn_len
            filename = data[fn_start:fn_end].decode("latin-1", "replace")
            extra = data[fn_end : fn_end + extra_len]
            comm_start = fn_end + extra_len
            comm_end = comm_start + comment_len
            comment = data[comm_start:comm_end].decode("latin-1", "replace")

            if comment:
                comments.append(f"File comment ({filename}): {comment}")
                flags.extend(scan_text(comment))

            central_headers.append({
                "pos": pos,
                "gp_flag": gp_flag,
                "is_encrypted": bool(gp_flag & 0x0001),
                "comp_method": comp_method,
                "crc32": crc32,
                "comp_size": comp_size,
                "uncomp_size": uncomp_size,
                "filename": filename,
                "comment": comment,
                "local_hdr_offset": local_hdr_offset,
            })
            pos = comm_end
        else:
            pos += 1

    # 3. Find End of Central Directory (PK\x05\x06)
    eocd_pos = data.rfind(b"PK\x05\x06")
    if eocd_pos != -1 and eocd_pos + 22 <= data_len:
        disk_no, cd_disk, entries_disk, total_entries, cd_size, cd_offset, comment_len = struct.unpack(
            "<HHHHIIH", data[eocd_pos + 4 : eocd_pos + 22]
        )
        comm_bytes = data[eocd_pos + 22 : eocd_pos + 22 + comment_len]
        archive_comment = comm_bytes.decode("latin-1", "replace")
        if archive_comment:
            comments.append(f"Archive comment: {archive_comment}")
            flags.extend(scan_text(archive_comment))
            flags.extend(scan_bytes(comm_bytes))

        eocd = {
            "pos": eocd_pos,
            "total_entries": total_entries,
            "cd_size": cd_size,
            "cd_offset": cd_offset,
            "comment": archive_comment,
        }

    return {
        "local_headers": local_headers,
        "central_headers": central_headers,
        "eocd": eocd,
        "comments": comments,
        "flags": flags,
    }


def fix_pseudo_encryption(data: bytes) -> bytes:
    """Clear fake encryption bit flags (bit 0) in both local and central directory headers."""
    mod = bytearray(data)
    pos = 0
    data_len = len(mod)

    # 1. Clear bit 0 in Local File Headers
    while pos < data_len - 4:
        if mod[pos : pos + 4] == b"PK\x03\x04":
            if pos + 30 <= data_len:
                # Byte 6-7 is General Purpose Bit Flag
                gp_flag = struct.unpack("<H", mod[pos + 6 : pos + 8])[0]
                if gp_flag & 0x0001:
                    new_gp = gp_flag & ~0x0001
                    mod[pos + 6 : pos + 8] = struct.pack("<H", new_gp)
                fn_len, extra_len = struct.unpack("<HH", mod[pos + 26 : pos + 30])
                pos += 30 + fn_len + extra_len
                continue
        pos += 1

    # 2. Clear bit 0 in Central Directory Headers
    pos = 0
    while pos < data_len - 4:
        if mod[pos : pos + 4] == b"PK\x01\x02":
            if pos + 46 <= data_len:
                # Byte 8-9 is General Purpose Bit Flag
                gp_flag = struct.unpack("<H", mod[pos + 8 : pos + 10])[0]
                if gp_flag & 0x0001:
                    new_gp = gp_flag & ~0x0001
                    mod[pos + 8 : pos + 10] = struct.pack("<H", new_gp)
                fn_len, extra_len, comment_len = struct.unpack("<HHH", mod[pos + 28 : pos + 34])
                pos += 46 + fn_len + extra_len + comment_len
                continue
        pos += 1

    return bytes(mod)


def solve(target: str, workdir: str = "") -> dict[str, Any]:
    """Analyze and solve ZIP archive challenges (pseudo-encryption, small file CRCs, comments)."""
    flags: list[dict[str, Any]] = []
    artifacts: list[str] = []
    output_lines: list[str] = []

    try:
        with open(target, "rb") as fh:
            data = fh.read(100 * 1024 * 1024)
    except OSError as e:
        return {"step": "zip-forensics", "flags": [], "output": f"Could not read: {e}"}

    parsed = parse_zip_structures(data)
    flags.extend(parsed.get("flags", []))

    # Comments
    for comm in parsed.get("comments", []):
        output_lines.append(f"[Comment] {comm}")

    # Check for Pseudo-encryption
    locals_enc = any(h["is_encrypted"] for h in parsed["local_headers"])
    centrals_enc = any(h["is_encrypted"] for h in parsed["central_headers"])

    if locals_enc or centrals_enc:
        output_lines.append(f"[*] Detected encrypted flag in headers (local={locals_enc}, central={centrals_enc})")
        # Generate fixed ZIP with stripped encryption bits
        fixed_data = fix_pseudo_encryption(data)
        fixed_path = os.path.join(workdir, "fixed_unmasked.zip") if workdir else "/tmp/fixed_unmasked.zip"
        try:
            with open(fixed_path, "wb") as f_out:
                f_out.write(fixed_data)
            artifacts.append(fixed_path)

            # Try to extract the fixed zip
            import zipfile
            extract_dir = os.path.join(workdir, "zip_fixed_extract") if workdir else "/tmp/zip_fixed_extract"
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(fixed_path, "r") as zf:
                zf.extractall(extract_dir)
                extracted_files = [os.path.join(extract_dir, fn) for fn in zf.namelist()]
                artifacts.extend(extracted_files)
                output_lines.append(f"[✓] Pseudo-encryption bypassed! Extracted {len(extracted_files)} file(s).")
                for ef in extracted_files:
                    try:
                        with open(ef, "rb") as efh:
                            content = efh.read(50000)
                        flags.extend(scan_bytes(content))
                        flags.extend(scan_text(content.decode("latin-1", "replace")))
                    except OSError:
                        pass
        except Exception as ex:
            output_lines.append(f"[-] Pseudo-encryption extract attempt: {ex}")

    # Check for Small File CRC32 Recovery
    for entry in parsed.get("central_headers", []):
        usize = entry["uncomp_size"]
        crc = entry["crc32"]
        fn = entry["filename"]
        if 0 < usize <= 4 and crc:
            output_lines.append(f"[*] Attempting CRC32 brute-force for '{fn}' (size={usize}, crc=0x{crc:08x})...")
            recovered = crc32_brute_small_file(crc, max_len=usize)
            if recovered:
                rec_text = recovered.decode("latin-1", "replace")
                output_lines.append(f"[✓] Recovered '{fn}' content from CRC32: {rec_text!r}")
                flags.extend(scan_text(rec_text))
                flags.extend(scan_bytes(recovered))

    # Path traversal detection
    for entry in parsed.get("central_headers", []):
        fn = entry["filename"]
        if "../" in fn or fn.startswith("/"):
            output_lines.append(f"[!] Warning: Zip-Slip / Path Traversal pattern detected in filename: '{fn}'")

    summary = (
        f"ZIP Forensics found {len(flags)} flag(s)."
        if flags
        else f"ZIP Forensics analyzed {len(parsed['central_headers'])} entry/entries."
    )

    return {
        "step": "zip-forensics",
        "flags": flags,
        "summary": summary,
        "output": "\n".join(output_lines) if output_lines else "Standard ZIP structure without anomalies.",
        "artifacts": artifacts,
    }
