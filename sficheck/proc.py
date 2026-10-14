"""Subprocess helper: run a tool if it exists, never raise."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120


def which(tool: str) -> str | None:
    """The tool's path on PATH.

    On Windows, shutil.which looks in the current directory first unless NoDefaultCurrentDirectoryInExePath
    is set, so a same-named file there (a cloned repo's ``git.cmd``) would run instead. Windows gets a
    search of PATH alone.
    """
    if sys.platform != "win32":
        return shutil.which(tool)
    exts = [ext for ext in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if ext]
    names = [tool] if tool.lower().endswith(tuple(ext.lower() for ext in exts)) else [tool + ext for ext in exts]
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        for name in names:
            if folder and (candidate := Path(folder, name)).is_file():
                return str(candidate)
    return None


def run(cmd: list[str], timeout: float = DEFAULT_TIMEOUT, ok_codes: tuple[int, ...] = (0,)) -> str | None:
    """Run ``cmd`` and return stdout, or None if the tool is missing, times out or fails.

    The executable is resolved with which() so Windows ``.cmd``/``.bat`` shims
    (npm, yarn, ...) work without ``shell=True``.
    """
    exe = which(cmd[0])
    if exe is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 -- an argument list, never a shell; cmd[0] comes from which()
            [exe, *cmd[1:]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("%s failed: %s", cmd, exc)
        return None
    if proc.returncode not in ok_codes:
        log.debug("%s exited %d: %s", cmd, proc.returncode, proc.stderr.strip()[:200])
        return None
    return proc.stdout
