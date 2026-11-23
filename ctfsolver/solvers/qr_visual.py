"""Visual steganography, QR code, Barcode, and Bit-Plane analysis solver."""
from __future__ import annotations

import io
import os
from typing import Any

from ..flags import scan_bytes, scan_text, scan_encoded


def decode_qr_barcode(image_path: str, workdir: str = "") -> list[dict[str, Any]]:
    """Scan an image for QR codes, DataMatrix, and barcodes with visual pre-processing."""
    results: list[dict[str, Any]] = []
    found_texts: set[str] = set()

    try:
        from PIL import Image, ImageOps, ImageEnhance
    except ImportError:
        return results

    try:
        base_img = Image.open(image_path)
    except Exception:
        return results

    # Generate image variations: original, grayscale, inverted, high contrast, binary threshold
    variations: list[tuple[str, Image.Image]] = []
    variations.append(("original", base_img))

    gray = ImageOps.grayscale(base_img)
    variations.append(("grayscale", gray))

    try:
        inverted = ImageOps.invert(gray)
        variations.append(("inverted", inverted))
    except Exception:
        pass

    try:
        enhancer = ImageEnhance.Contrast(gray)
        variations.append(("high_contrast", enhancer.enhance(3.0)))
    except Exception:
        pass

    try:
        # Simple binarization threshold
        thresh = gray.point(lambda p: 255 if p > 128 else 0)
        variations.append(("binary_threshold", thresh))
    except Exception:
        pass

    # Method 1: pyzbar
    try:
        import pyzbar.pyzbar as pyzbar
        for label, img in variations:
            try:
                decoded = pyzbar.decode(img)
                for item in decoded:
                    txt = item.data.decode("utf-8", "replace").strip()
                    if txt and txt not in found_texts:
                        found_texts.add(txt)
                        flags = scan_text(txt)
                        results.append({
                            "type": item.type,
                            "variant": label,
                            "text": txt,
                            "flags": flags,
                        })
            except Exception:
                continue
    except ImportError:
        pass

    # Method 2: zxingcpp (fast and detects inverted / distorted codes)
    try:
        import zxingcpp
        for label, img in variations:
            try:
                barcodes = zxingcpp.read_barcodes(img)
                for b in barcodes:
                    txt = b.text.strip()
                    if txt and txt not in found_texts:
                        found_texts.add(txt)
                        flags = scan_text(txt)
                        results.append({
                            "type": str(b.format),
                            "variant": f"zxing-{label}",
                            "text": txt,
                            "flags": flags,
                        })
            except Exception:
                continue
    except ImportError:
        pass

    return results


def extract_bitplanes(image_path: str, workdir: str = "") -> dict[str, Any]:
    """Extract LSB and individual bitplanes from color channels (R, G, B, A)."""
    flags: list[dict[str, Any]] = []
    carved_files: list[str] = []

    try:
        from PIL import Image
        img = Image.open(image_path)
    except Exception:
        return {"flags": [], "artifacts": []}

    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.mode else "RGB")

    pixels = img.load()
    w, h = img.size
    total_px = w * h

    # Only analyze if reasonably sized to keep execution fast (<10M pixels)
    if total_px > 4000000:
        return {"flags": [], "artifacts": []}

    channels = list(img.split())
    chan_names = ["R", "G", "B"] if len(channels) == 3 else ["R", "G", "B", "A"]

    # 1. Test combined LSB (bit 0 of R, G, B sequentially)
    lsb_bits: list[int] = []
    for y in range(min(h, 500)):
        for x in range(min(w, 500)):
            px = pixels[x, y]
            for c in range(min(len(px), 3)):
                lsb_bits.append(px[c] & 1)

    # Convert bit stream to bytes
    byte_vals = bytearray()
    for i in range(0, len(lsb_bits) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | lsb_bits[i + b]
        byte_vals.append(byte)

    found = scan_bytes(bytes(byte_vals)) + scan_encoded(bytes(byte_vals))
    if found:
        for f in found:
            f["method"] = "lsb-rgb"
        flags.extend(found)

    # 2. Test individual channel bit 0
    for idx, name in enumerate(chan_names[:3]):
        chan_bits: list[int] = []
        for y in range(min(h, 600)):
            for x in range(min(w, 600)):
                px = pixels[x, y]
                chan_bits.append(px[idx] & 1)

        c_bytes = bytearray()
        for i in range(0, len(chan_bits) - 7, 8):
            byte = 0
            for b in range(8):
                byte = (byte << 1) | chan_bits[i + b]
            c_bytes.append(byte)

        c_found = scan_bytes(bytes(c_bytes)) + scan_encoded(bytes(c_bytes))
        if c_found:
            for f in c_found:
                f["method"] = f"lsb-{name}"
            flags.extend(c_found)

    return {"flags": flags, "artifacts": carved_files}


def solve(image_path: str, workdir: str = "") -> dict[str, Any]:
    """Run comprehensive visual / QR / bitplane stego analysis."""
    qr_res = decode_qr_barcode(image_path, workdir)
    bitplane_res = extract_bitplanes(image_path, workdir)

    all_flags: list[dict[str, Any]] = []
    output_lines: list[str] = []

    for r in qr_res:
        output_lines.append(f"[{r.get('type')}] ({r.get('variant')}): {r.get('text')}")
        all_flags.extend(r.get("flags", []))

    all_flags.extend(bitplane_res.get("flags", []))

    return {
        "step": "visual-stego-qr",
        "summary": f"QR/Barcode and bit-plane analysis ({len(qr_res)} barcode(s) found)",
        "output": "\n".join(output_lines) if output_lines else "No visual barcode or direct LSB flag detected.",
        "flags": all_flags,
        "artifacts": bitplane_res.get("artifacts", []),
    }
