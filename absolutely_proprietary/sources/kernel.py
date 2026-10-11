"""The kernel itself: loaded Linux modules and third-party Windows drivers."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from absolutely_proprietary.models import Finding, Package, Ring, Status
from absolutely_proprietary.sources import _registry
from absolutely_proprietary.sources.base import IS_WINDOWS, Source

PROC_MODULES = Path("/proc/modules")
SYS_MODULE = Path("/sys/module")
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
KERNEL_DRIVER, FILE_SYSTEM_DRIVER = 1, 2  # service Type values
SYSTEM_START, AUTO_START = 1, 2  # service Start values; 0 = boot, 3 = on demand


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


def _windows_driver_services() -> Iterator[tuple[str, str, int, int]]:
    """(service name, ImagePath, Start, devices bound to it) for every kernel driver service."""
    for name in _registry.subkeys(SERVICES_KEY):
        values = _registry.values(rf"{SERVICES_KEY}\{name}")
        if values.get("Type") not in (KERNEL_DRIVER, FILE_SYSTEM_DRIVER):
            continue
        bound = int(_registry.value(rf"{SERVICES_KEY}\{name}\Enum", "Count") or 0)
        yield name, str(values.get("ImagePath", "")), int(str(values.get("Start", 3))), bound


def _image_path(service: str, image_path: str, system_root: str) -> str:
    """Turn a service's ImagePath (often NT-style, sometimes empty) into a normal file path."""
    path = image_path.strip('"')
    lower = path.lower()
    if not path:
        return rf"{system_root}\System32\drivers\{service}.sys"
    if lower.startswith("\\??\\"):
        return path[4:]
    if lower.startswith("\\systemroot\\"):
        return system_root + path[11:]
    if lower.startswith("system32\\"):
        return rf"{system_root}\{path}"
    return path


def _file_info(path: str) -> dict[str, str] | None:
    """CompanyName, ProductName and FileVersion from a file's version resource; None if the file is missing."""
    if not Path(path).is_file():
        return None
    if sys.platform != "win32":
        return {}
    import ctypes
    from ctypes import wintypes

    version = ctypes.WinDLL("version")
    size = version.GetFileVersionInfoSizeW(path, None)
    buf = ctypes.create_string_buffer(size)
    if not size or not version.GetFileVersionInfoW(path, 0, size, buf):
        return {}
    ptr, length = ctypes.c_void_p(), wintypes.UINT()
    if not version.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(length)):
        return {}
    lang, codepage = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort * 2)).contents
    info = {}
    for field in ("CompanyName", "ProductName", "FileVersion"):
        query = rf"\StringFileInfo\{lang:04x}{codepage:04x}\{field}"
        if version.VerQueryValueW(buf, query, ctypes.byref(ptr), ctypes.byref(length)) and length.value:
            info[field] = ctypes.wstring_at(ptr, length.value - 1).strip()
    return info


def _windows_drivers(jobs: int) -> Iterator[tuple[str, dict[str, str]]]:
    """(service name, version info) for third-party drivers that are actually in use.

    Windows registers hundreds of inbox drivers for hardware the machine doesn't have. A
    driver counts when a device is bound to it, it loads at system or auto start, or it was
    installed outside the Windows directory (anticheats loaded on demand by a game).
    Microsoft's own drivers are part of Windows, which the windows source already reports.
    """
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    candidates = []
    for name, image_path, start, bound in _windows_driver_services():
        path = _image_path(name, image_path, system_root)
        outside = not path.lower().startswith(system_root.lower())
        if bound or start in (SYSTEM_START, AUTO_START) or outside:
            candidates.append((name, path, outside))
    with ThreadPoolExecutor(max(1, jobs)) as pool:
        infos = list(pool.map(lambda c: _file_info(c[1]), candidates))
    for (name, _, outside), info in zip(candidates, infos, strict=True):
        if info is None or "microsoft" in info.get("CompanyName", "").lower():
            continue
        if info or outside:  # inbox files without version info are Windows' own
            yield name, info


class Kernel(Source):
    name = "kernel"
    kind = "system"
    description = "Kernel modules and drivers running in ring 0"
    lists = ("common", "kernel")
    default_ring = Ring.KERNEL
    default_enabled = False

    def available(self) -> bool:
        return IS_WINDOWS or PROC_MODULES.is_file()

    def packages(self) -> Iterable[Package]:
        if IS_WINDOWS:
            for name, info in _windows_drivers(self.ctx.jobs):
                company, product = info.get("CompanyName", ""), info.get("ProductName", "")
                yield self.pkg(name, info.get("FileVersion", ""), company=company, product=product)
            return
        for name, version, taint in _linux_modules():
            yield self.pkg(name, version, taint=taint)

    def fallback(self, package: Package) -> Finding:
        if "company" in package.extra:
            # Third-party Windows drivers ship as binaries; the free ones are listed as such.
            vendor = package.extra["company"] or "an unnamed vendor"
            product = package.extra["product"]
            description = f"{product} ({vendor})" if product else f"Driver from {vendor}"
            return Finding(package, Status.NONFREE, reason="third-party driver", description=description)
        # The kernel taints itself with P when a module's MODULE_LICENSE isn't GPL-compatible.
        if "P" in package.extra.get("taint", ""):
            return Finding(package, Status.NONFREE, reason="kernel taint P", description="Non-GPL-compatible module")
        return Finding(package, Status.FREE, reason="GPL-compatible module")
