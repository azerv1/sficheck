"""The programs running right now, for --in-use."""

from __future__ import annotations

from pathlib import Path

import psutil


def running_paths() -> set[Path]:
    """Executable paths of the running processes.

    Another user's process may hide its executable; its command line's first word is used
    instead when that is an absolute path. Kernel threads have neither and are skipped.
    """
    paths: set[Path] = set()
    for process in psutil.process_iter(["exe", "cmdline"]):
        exe = process.info.get("exe")
        if not exe:
            cmdline = process.info.get("cmdline") or []
            exe = cmdline[0] if cmdline and Path(cmdline[0]).is_absolute() else None
        if exe:
            paths.add(Path(exe))
    return paths


def under(path: Path, folder: str) -> bool:
    """Whether ``path`` is inside ``folder``, ignoring case (install folders on Windows)."""
    prefix = folder.rstrip("\\/").casefold()
    text = str(path).casefold()
    return bool(prefix) and text.startswith(prefix) and text[len(prefix) : len(prefix) + 1] in ("\\", "/")
