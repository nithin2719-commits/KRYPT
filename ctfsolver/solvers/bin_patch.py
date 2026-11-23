"""Anti-debug bypass and binary patcher for CTF ELF binaries."""
from __future__ import annotations

import os
import shutil
from typing import Any


def patch_anti_debug(binary_path: str, workdir: str = "") -> dict[str, Any]:
    """Detect and patch ptrace anti-debugging and alarm timeout checks."""
    try:
        from pwn import ELF
    except ImportError:
        return {"patched": False, "output": "pwntools not available for patching."}

    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as e:
        return {"patched": False, "output": f"Could not parse ELF: {e}"}

    patches_applied: list[str] = []
    target_workdir = workdir if workdir else os.path.dirname(binary_path)
    patched_path = os.path.join(target_workdir, os.path.basename(binary_path) + ".patched")

    # Copy binary to patch target
    shutil.copy2(binary_path, patched_path)
    p_elf = ELF(patched_path, checksec=False)

    # 1. Patch alarm(n) -> xor eax, eax; ret (or nop)
    if "alarm" in p_elf.plt:
        alarm_plt = p_elf.plt["alarm"]
        # In x86/x64: xor eax, eax (31 c0); ret (c3)
        if p_elf.bits == 64:
            p_elf.write(alarm_plt, b"\x31\xc0\xc3")
        else:
            p_elf.write(alarm_plt, b"\x31\xc0\xc3")
        patches_applied.append("Patched alarm() in PLT to ret 0")

    # 2. Patch ptrace(PTRACE_TRACEME, ...) -> xor eax, eax; ret
    if "ptrace" in p_elf.plt:
        ptrace_plt = p_elf.plt["ptrace"]
        p_elf.write(ptrace_plt, b"\x31\xc0\xc3")
        patches_applied.append("Patched ptrace() anti-debug in PLT to ret 0")

    # 3. Patch sleep / usleep if present to speed up execution
    for fn in ["sleep", "usleep"]:
        if fn in p_elf.plt:
            p_elf.write(p_elf.plt[fn], b"\x31\xc0\xc3")
            patches_applied.append(f"Patched {fn}() in PLT to ret 0 (instant execution)")

    if patches_applied:
        p_elf.save(patched_path)
        os.chmod(patched_path, 0o755)
        return {
            "patched": True,
            "patched_file": patched_path,
            "patches": patches_applied,
            "output": "\n".join(patches_applied),
        }

    return {"patched": False, "output": "No alarm() or ptrace() anti-debug routines found to patch."}
