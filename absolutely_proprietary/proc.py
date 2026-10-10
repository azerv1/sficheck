"""Subprocess helper: run a tool if it exists, never raise."""

from __future__ import annotations

import logging
import shutil
import subprocess

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120


def which(tool: str) -> str | None:
    return shutil.which(tool)


def run(cmd: list[str], timeout: float = DEFAULT_TIMEOUT, ok_codes: tuple[int, ...] = (0,)) -> str | None:
    """Run ``cmd`` and return stdout, or None if the tool is missing, times out or fails.

    The executable is resolved with shutil.which so Windows ``.cmd``/``.bat`` shims
    (npm, yarn, ...) work without ``shell=True``.
    """
    exe = shutil.which(cmd[0])
    if exe is None:
        return None
    try:
        proc = subprocess.run(
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
