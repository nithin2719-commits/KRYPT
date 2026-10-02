"""Subprocess helper: run external tools safely with a timeout and captured output."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolResult:
    tool: str
    argv: list[str]
    found: bool          # was the binary available?
    rc: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    note: str = ""

    def ok(self) -> bool:
        return self.found and not self.timed_out and (self.rc == 0)


def have(tool: str) -> bool:
    """Is a binary on PATH?"""
    return shutil.which(tool) is not None


def run(argv: list[str], *, timeout: int = 60, input_bytes: bytes | None = None,
        cwd: str | None = None) -> ToolResult:
    """Run argv, capturing text output. Never raises on tool failure."""
    tool = argv[0]
    if not have(tool):
        return ToolResult(tool=tool, argv=argv, found=False,
                          note=f"{tool} not installed")
    try:
        proc = subprocess.run(
            argv, input=input_bytes, capture_output=True,
            timeout=timeout, cwd=cwd,
        )
        return ToolResult(
            tool=tool, argv=argv, found=True, rc=proc.returncode,
            stdout=proc.stdout.decode("utf-8", "replace"),
            stderr=proc.stderr.decode("utf-8", "replace"),
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace")
        err = (e.stderr or b"").decode("utf-8", "replace")
        return ToolResult(tool=tool, argv=argv, found=True, timed_out=True,
                          stdout=out, stderr=err,
                          note=f"timed out after {timeout}s")
    except Exception as e:  # pragma: no cover - defensive
        return ToolResult(tool=tool, argv=argv, found=True, rc=-1,
                          note=f"error: {e}")
