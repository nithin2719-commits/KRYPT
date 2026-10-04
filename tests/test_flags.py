"""Regression tests: the flag scanner must not match code / arbitrary word{...}."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ctfsolver.flags import scan_text  # noqa: E402


def _f(t):
    return [x["flag"] for x in scan_text(t)]


def test_ignores_code_and_generic():
    assert _f("void win(){ return 0; }") == []
    assert _f("struct data { int x; }") == []
    assert _f("random token{hello world}") == []
    assert _f("flag{...}") == []          # placeholder


def test_finds_real_flags():
    assert _f("here is flag{elf_strings_win}") == ["flag{elf_strings_win}"]
    assert _f("HTB{pwned}") == ["HTB{pwned}"]


def test_dedupes_substring_wrappers():
    assert _f("picoCTF{sym_exec}") == ["picoCTF{sym_exec}"]      # not also CTF{x}
    assert _f("myflag{custom_ok}") == ["myflag{custom_ok}"]        # not also flag{x}


if __name__ == "__main__":
    for n, fn in sorted(globals().items()):
        if n.startswith("test_") and callable(fn):
            fn(); print("ok", n)
    print("all flag tests passed")


def test_custom_event_formats():
    assert _f("CSSA{m3mbership_card}") == ["CSSA{m3mbership_card}"]
    assert _f("DUCTF{w1n}") == ["DUCTF{w1n}"]


def test_rejects_plain_word_braces():
    assert _f("card{active}") == []
    assert _f("style{color}") == []
    assert _f('int main(){char buf[64];}') == []


def test_rejects_code_with_underscore_or_digit():
    # The old fallback flagged any word{...} whose body had a '_' or digit,
    # inventing flags from ordinary code/markup. These must stay empty.
    assert _f("struct Point{x_0}") == []
    assert _f("d = dict{key_1}") == []
    assert _f(r"\frac{a_1}{b_2}") == []
    assert _f("config{debug_mode}") == []
    assert _f("s = set{a_1}") == []
    assert _f("div{margin_0}") == []
    assert _f("arr{i_0}") == []


def test_rejects_allcaps_macro_braces():
    # An uppercase wrapper alone isn't enough — the body must have a lowercase
    # letter, and an underscore in the wrapper means a macro, not an acronym.
    assert _f("#define MAX{BUF_SIZE}") == []
    assert _f("TODO{FIXME}") == []
    assert _f("#define MAX_BUF{SIZE_256}") == []
