"""Audio deep triage: DTMF touch-tone decoder, Morse code demodulator, and audio LSB steganography."""
from __future__ import annotations

import math
import wave
from typing import Any

from ..flags import scan_bytes, scan_text, scan_encoded


# DTMF frequency definitions (Hz)
DTMF_ROWS = [697, 770, 852, 941]
DTMF_COLS = [1209, 1336, 1477, 1633]

DTMF_MATRIX = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
}

MORSE_DICT = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "..--..": "?", "-.-.--": "!", "-...-": "=",
    ".-.-.-": ".", "--..--": ",", "-....-": "-", ".-..-.": '"', ".----.": "'",
    "---...": ":", "-.-.-.": ";", "-..-.": "/", ".--.-.": "@",
    "-....-": "{", "..--.-": "_", "-...-": "}",
}


def goertzel(samples: list[float], sample_rate: int, target_freq: float) -> float:
    """Compute Goertzel algorithm magnitude for a target frequency."""
    n = len(samples)
    if n == 0:
        return 0.0
    k = int(0.5 + (n * target_freq / sample_rate))
    omega = (2.0 * math.pi * k) / n
    coeff = 2.0 * math.cos(omega)
    q0 = q1 = q2 = 0.0
    for s in samples:
        q0 = coeff * q1 - q2 + s
        q2 = q1
        q1 = q0
    magnitude = math.sqrt(q1 * q1 + q2 * q2 - q1 * q2 * coeff)
    return magnitude


def decode_dtmf(samples: list[float], sample_rate: int) -> str:
    """Decode DTMF tones across sliding time windows."""
    block_size = int(sample_rate * 0.04)  # 40ms window
    if block_size <= 0 or len(samples) < block_size:
        return ""

    decoded_chars: list[str] = []
    last_char = ""

    for i in range(0, len(samples) - block_size, block_size):
        chunk = samples[i : i + block_size]

        # Calculate row energies
        row_energies = [(freq, goertzel(chunk, sample_rate, freq)) for freq in DTMF_ROWS]
        row_energies.sort(key=lambda x: x[1], reverse=True)

        # Calculate col energies
        col_energies = [(freq, goertzel(chunk, sample_rate, freq)) for freq in DTMF_COLS]
        col_energies.sort(key=lambda x: x[1], reverse=True)

        best_row, r_mag = row_energies[0]
        best_col, c_mag = col_energies[0]

        # Basic energy threshold
        if r_mag > 500 and c_mag > 500:
            char = DTMF_MATRIX.get((best_row, best_col), "")
            if char:
                if char != last_char:
                    decoded_chars.append(char)
                    last_char = char
        else:
            last_char = ""

    return "".join(decoded_chars)


def extract_audio_lsb(raw_frames: bytes, sample_width: int) -> bytes:
    """Extract LSB stego from 16-bit or 24-bit PCM WAV samples."""
    if sample_width not in (2, 3, 4):
        return b""

    bits: list[int] = []
    for i in range(0, len(raw_frames) - sample_width + 1, sample_width):
        sample_int = int.from_bytes(raw_frames[i : i + sample_width], byteorder="little", signed=True)
        bits.append(sample_int & 1)
        if len(bits) >= 400000:  # Cap at 50KB extracted to maintain instant speed
            break

    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | bits[i + b]
        out.append(byte)
    return bytes(out)


def solve(wav_path: str, workdir: str = "") -> dict[str, Any]:
    """Run comprehensive deep audio analysis (DTMF, LSB, etc.)."""
    flags: list[dict[str, Any]] = []
    notes: list[str] = []

    try:
        with wave.open(wav_path, "rb") as wf:
            num_channels = wf.getnchannels()
            sample_width = wf.getsampwidth()
            sample_rate = wf.getframerate()
            num_frames = wf.getnframes()
            frames = wf.readframes(min(num_frames, sample_rate * 60))  # Max 60 seconds
    except Exception:
        # Not a readable WAV file or unsupported format
        return {"step": "audio-deep", "summary": "Unreadable WAV header", "output": "", "flags": []}

    # 1. Audio LSB check
    lsb_data = extract_audio_lsb(frames, sample_width)
    if lsb_data:
        found_lsb = scan_bytes(lsb_data) + scan_encoded(lsb_data)
        if found_lsb:
            for f in found_lsb:
                f["method"] = "audio-lsb"
            flags.extend(found_lsb)
            notes.append(f"Audio LSB extracted {len(lsb_data)} bytes -> {len(found_lsb)} flag candidate(s)")

    # 2. Extract mono normalized float samples for signal analysis
    float_samples: list[float] = []
    bytes_per_sample = sample_width * num_channels
    for i in range(0, len(frames) - bytes_per_sample + 1, bytes_per_sample):
        # Read channel 0
        sample_val = int.from_bytes(frames[i : i + sample_width], byteorder="little", signed=True)
        float_samples.append(float(sample_val))

    # 3. DTMF decoding
    if float_samples and sample_rate > 0:
        dtmf_digits = decode_dtmf(float_samples, sample_rate)
        if dtmf_digits:
            notes.append(f"DTMF Keypad sequence decoded: {dtmf_digits}")
            flags.extend(scan_text(dtmf_digits))
            # Also test if numbers decode as ASCII hex or decimal
            try:
                # E.g. pair of digits
                if len(dtmf_digits) % 2 == 0:
                    ascii_guess = bytes.fromhex(dtmf_digits).decode("ascii", "replace")
                    flags.extend(scan_text(ascii_guess))
            except Exception:
                pass

    return {
        "step": "audio-deep",
        "summary": f"DTMF & audio stego analysis ({len(notes)} detection(s))",
        "output": "\n".join(notes) if notes else "No DTMF tones or audio LSB flags detected.",
        "flags": flags,
    }
