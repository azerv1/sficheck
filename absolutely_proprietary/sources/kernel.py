"""The kernel itself: loaded Linux modules."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from absolutely_proprietary.models import Finding, Package, Ring, Status
from absolutely_proprietary.sources.base import Source

PROC_MODULES = Path("/proc/modules")
SYS_MODULE = Path("/sys/module")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _linux_modules() -> Iterator[tuple[str, str, str]]:
    """(name, version, taint flags) for every loaded module."""
    for line in _read(PROC_MODULES).splitlines():
        name = line.split(" ", 1)[0]
        yield name, _read(SYS_MODULE / name / "version"), _read(SYS_MODULE / name / "taint")


class Kernel(Source):
    name = "kernel"
    kind = "system"
    description = "Kernel modules and drivers running in ring 0"
    lists = ("common",)
    default_ring = Ring.KERNEL
    default_enabled = False

    def available(self) -> bool:
        return PROC_MODULES.is_file()

    def packages(self) -> Iterable[Package]:
        for name, version, taint in _linux_modules():
            yield self.pkg(name, version, taint=taint)

    def fallback(self, package: Package) -> Finding:
        # The kernel taints itself with P when a module's MODULE_LICENSE isn't GPL-compatible.
        if "P" in package.extra.get("taint", ""):
            return Finding(package, Status.NONFREE, reason="kernel taint P", description="Non-GPL-compatible module")
        return Finding(package, Status.FREE, reason="GPL-compatible module")
