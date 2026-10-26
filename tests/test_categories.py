"""Tests for the domain category map and the no-file text pipeline."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfsolver import categories  # noqa: E402


def test_every_category_has_arsenal():
    for name, c in categories.CATEGORIES.items():
        assert c["local"] and c["mcp"] and c["skills"], name
        assert c["hint"], name


def test_toolset_defaults_to_auto():
    assert categories.toolset("nonsense")["label"] == "AUTO"


def test_toolset_step_names_domain():
    step = categories.toolset_step("web")
    assert step["step"] == "arsenal[WEB]"
    assert "sqlmap" in step["output"]


def test_text_triage_finds_flag_in_prompt():
    steps = categories.text_triage("the admin left flag{osint_win} here")
    flags = [f["flag"] for s in steps for f in s.get("flags", [])]
    assert "flag{osint_win}" in flags


def test_image_overlay_carving(tmp_path):
    from ctfsolver.triage import image
    # Fake PNG ending with IEND chunk followed by appended flag
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00IEND\xae\x42\x60\x82flag{png_overlay_found}"
    img_file = tmp_path / "chal.png"
    img_file.write_bytes(png_data)
    workdir = str(tmp_path / "work")
    os.makedirs(workdir, exist_ok=True)
    steps = image.triage(str(img_file), workdir)
    overlay_step = next((s for s in steps if s["step"] == "image-overlay"), None)
    assert overlay_step is not None
    assert any(f["flag"] == "flag{png_overlay_found}" for f in overlay_step["flags"])



if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all category tests passed")
