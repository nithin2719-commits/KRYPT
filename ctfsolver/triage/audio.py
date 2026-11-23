"""Triage for audio files (stego / forensics): metadata, strings, steghide on
WAV, and a spectrogram render (flags are frequently hidden in the spectrogram)."""
from __future__ import annotations

import os

from ..flags import scan_text
from ..runner import have, run


def triage(path: str, workdir: str) -> list[dict]:
    steps: list[dict] = []
    lower = path.lower()

    # metadata
    r = run(["exiftool", path], timeout=30)
    if r.ok():
        steps.append({"step": "exiftool", "summary": "audio metadata",
                      "output": r.stdout[:2500], "flags": scan_text(r.stdout)})

    # spectrogram — the #1 place flags hide in audio challenges
    if have("sox"):
        spec = os.path.join(workdir, "spectrogram.png")
        r = run(["sox", path, "-n", "spectrogram", "-o", spec], timeout=60)
        if not os.path.exists(spec) and have("ffmpeg"):
            wav = os.path.join(workdir, "_audio.wav")
            run(["ffmpeg", "-y", "-i", path, wav], timeout=60)
            if os.path.exists(wav):
                run(["sox", wav, "-n", "spectrogram", "-o", spec], timeout=60)
        if os.path.exists(spec):
            steps.append({"step": "spectrogram",
                          "summary": "rendered spectrogram — OPEN IT, flags often "
                                     "hide as text in the frequencies",
                          "output": spec, "flags": [], "artifacts": [spec]})

    # steghide on WAV (empty passphrase)
    if have("steghide") and lower.endswith(".wav"):
        out = os.path.join(workdir, "steghide_audio.bin")
        run(["steghide", "extract", "-sf", path, "-p", "", "-xf", out, "-f"],
            timeout=30)
        if os.path.exists(out):
            steps.append({"step": "steghide", "summary": "steghide payload extracted",
                          "output": "", "flags": [], "artifacts": [out]})

    # Deep audio analysis (DTMF touch-tone sequence & Audio LSB extraction)
    wav_to_test = path if lower.endswith(".wav") else os.path.join(workdir, "_audio.wav")
    if os.path.exists(wav_to_test):
        try:
            from ..solvers import audio_deep
            deep_step = audio_deep.solve(wav_to_test, workdir)
            if deep_step.get("flags") or "No DTMF" not in deep_step.get("output", ""):
                steps.append(deep_step)
        except Exception:
            pass

    steps.append({"step": "next",
                  "summary": "Open the spectrogram. Also check for DTMF/Morse "
                             "tones (multimon-ng), slow-scan TV (QSSTV), or LSB "
                             "on WAV samples.", "output": "", "flags": []})
    return steps
