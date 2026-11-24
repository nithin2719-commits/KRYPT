"""
Tests for ctfsolver/solvers/symbolic.py.

Fixtures are tiny C programs compiled at test time (gcc) rather than
binary blobs committed to git -- one dynamically-linked crackme (the
thing this tier is for), one statically-linked copy of the same logic
(regression coverage for the static-linking false-positive described in
symbolic.py's _dynamic_imports docstring), and one real networked binary
(negative case -- this tier must skip it).

ADJUST: the import below assumes `ctfsolver.solvers.symbolic` as the
module path, matching the package layout the rest of the repo's
test_*.py files already use. If those import solvers a different way,
match that instead.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("angr", reason="angr not installed in this environment")
pytest.importorskip("z3", reason="z3-solver not installed in this environment")

from ctfsolver.solvers import symbolic  # ADJUST if your package import path differs

GCC = shutil.which("gcc")
pytestmark = pytest.mark.skipif(GCC is None, reason="gcc not available to build test fixtures")

KNOWN_SECRET = b"CTF{ok}1"
_KEY = bytes([0x41, 0x12, 0x33, 0x04, 0x55, 0x16, 0x77, 0x08])

_XOR_CRACKME_TEMPLATE = """
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    char *input = argv[1];
    if (strlen(input) != 8) {{ printf("Wrong!\\n"); return 1; }}
    unsigned char key[8]    = {{ {key} }};
    unsigned char target[8] = {{ {target} }};
    for (int i = 0; i < 8; i++)
        if ((unsigned char)(input[i] ^ key[i]) != target[i]) {{ printf("Wrong!\\n"); return 1; }}
    printf("Correct!\\n");
    return 0;
}}
"""

_NET_SRC = """
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    printf("done\\n");
    return 0;
}
"""


def _xor_crackme_source() -> str:
    target = bytes(s ^ k for s, k in zip(KNOWN_SECRET, _KEY))
    key_lit = ", ".join(f"0x{b:02x}" for b in _KEY)
    target_lit = ", ".join(f"0x{b:02x}" for b in target)
    return _XOR_CRACKME_TEMPLATE.format(key=key_lit, target=target_lit)


def _compile(tmp_path: Path, name: str, source: str, static: bool = False) -> Path:
    src = tmp_path / f"{name}.c"
    src.write_text(source)
    out = tmp_path / name
    cmd = ["gcc", "-O0", "-o", str(out), str(src)]
    if static:
        cmd.insert(1, "-static")
    subprocess.run(cmd, check=True, capture_output=True)
    return out


@pytest.fixture(scope="module")
def xor_crackme(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("symbolic_fixtures")
    return _compile(tmp, "xor_crackme", _xor_crackme_source())


@pytest.fixture(scope="module")
def xor_crackme_static(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("symbolic_fixtures_static")
    return _compile(tmp, "xor_crackme_static", _xor_crackme_source(), static=True)


@pytest.fixture(scope="module")
def net_binary(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("symbolic_fixtures_net")
    return _compile(tmp, "netbin", _NET_SRC)


def test_static_precheck_rejects_non_elf(tmp_path):
    f = tmp_path / "notelf.txt"
    f.write_text("hello")
    assert symbolic.static_precheck(f)["candidate"] is False


def test_static_precheck_accepts_dynamic_crackme(xor_crackme):
    result = symbolic.static_precheck(xor_crackme)
    assert result["candidate"] is True
    assert result["statically_linked"] is False


def test_static_precheck_flags_static_without_false_network_positive(xor_crackme_static):
    """Regression test: an earlier version of this heuristic substring-
    searched raw file bytes for network function names and wrongly
    flagged every statically-linked binary as a service binary, because
    a static libc embeds those symbol strings even when unused."""
    result = symbolic.static_precheck(xor_crackme_static)
    assert result["candidate"] is True
    assert result["statically_linked"] is True


def test_static_precheck_rejects_networked_binary(net_binary):
    result = symbolic.static_precheck(net_binary)
    assert result["candidate"] is False
    assert "network" in result["reason"]


def test_recover_input_finds_known_secret(xor_crackme):
    result = symbolic.recover_input(str(xor_crackme), timeout_s=60)
    assert result.success is True
    assert result.recovered_input == KNOWN_SECRET


def test_recover_input_fails_cleanly_on_wrong_length(xor_crackme):
    result = symbolic.recover_input(str(xor_crackme), lengths=(5,), timeout_s=15)
    assert result.success is False


def test_simplify_obfuscated_expr():
    import z3
    x = z3.BitVec("x", 32)
    assert str(symbolic.simplify_obfuscated_expr((x ^ 0xFF) ^ 0xFF)) == "x"


def test_expressions_equivalent_true_case():
    import z3
    x, y = z3.BitVecs("x y", 32)
    assert symbolic.expressions_equivalent((x & y) + (x | y), x + y) is True


def test_expressions_equivalent_false_case():
    import z3
    x, y = z3.BitVecs("x y", 32)
    assert symbolic.expressions_equivalent(x * y, x + y) is False
