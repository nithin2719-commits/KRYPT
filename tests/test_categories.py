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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok", name)
    print("all category tests passed")
