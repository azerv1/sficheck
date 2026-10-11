"""Hardware that needs nonfree software to work: a proprietary driver, or firmware blobs loaded into it."""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from pathlib import Path

from absolutely_proprietary import proc
from absolutely_proprietary.blacklist import Blacklist, load_bundled
from absolutely_proprietary.models import Finding, Package, Ring, Status
from absolutely_proprietary.sources.base import Source
from absolutely_proprietary.sources.kernel import PROC_MODULES, SYS_MODULE, _read

SYS_BUS = Path("/sys/bus")
FIRMWARE_DIR = Path("/lib/firmware")
BLOB_SUFFIXES = ("", ".xz", ".zst")  # distros often compress linux-firmware


@cache
def _curated_drivers() -> Blacklist:
    return load_bundled("common", "kernel")


def _uevent(path: Path) -> dict[str, str]:
    return {key: value for key, _, value in (line.partition("=") for line in _read(path / "uevent").splitlines())}


def _lspci_names() -> dict[str, str]:
    """PCI slot -> "vendor device", from the pci.ids names lspci knows."""
    names = {}
    for line in (proc.run(["lspci", "-mmD"]) or "").splitlines():
        fields = shlex.split(line)  # slot "class" "vendor" "device" ...
        if len(fields) >= 4:
            names[fields[0]] = f"{fields[2]} {fields[3]}"
    return names


def _linux_pci() -> Iterator[tuple[str, str]]:
    names = _lspci_names()
    for path in sorted((SYS_BUS / "pci" / "devices").glob("*")):
        event = _uevent(path)
        if (driver := event.get("DRIVER")) and driver != "pcieport":  # bridges, not devices
            yield names.get(event.get("PCI_SLOT_NAME", "")) or f"PCI device {event.get('PCI_ID', path.name)}", driver


def _linux_usb() -> Iterator[tuple[str, str]]:
    """Drivers bind to a USB device's interfaces; the device itself holds the name."""
    entries = [_uevent(path) | {"path": str(path)} for path in sorted((SYS_BUS / "usb" / "devices").glob("*"))]
    names = {}
    for event in entries:
        if event.get("DEVTYPE") == "usb_device":
            path = Path(event["path"])
            names[event.get("PRODUCT")] = f"{_read(path / 'manufacturer')} {_read(path / 'product')}".strip()
    for event in entries:
        if event.get("DEVTYPE") == "usb_interface" and (driver := event.get("DRIVER")) and driver != "hub":
            yield names.get(event.get("PRODUCT")) or f"USB device {event.get('PRODUCT', '')}", driver


def _blobs(driver: str) -> list[str]:
    """Firmware files the driver's module asks for that are installed here."""
    declared = (proc.run(["modinfo", "-F", "firmware", driver]) or "").split()
    return [blob for blob in declared if any((FIRMWARE_DIR / (blob + s)).is_file() for s in BLOB_SUFFIXES)]


class Hardware(Source):
    name = "hardware"
    kind = "system"
    description = "Devices that need a nonfree driver or firmware blobs"
    lists = ()  # devices are judged by their driver, in verdict
    default_ring = Ring.KERNEL
    default_enabled = False

    def available(self) -> bool:
        return PROC_MODULES.is_file()

    def packages(self) -> Iterable[Package]:
        devices = list(dict.fromkeys([*_linux_pci(), *_linux_usb()]))
        drivers = sorted({driver for _, driver in devices})
        with ThreadPoolExecutor(max(1, self.ctx.jobs)) as pool:
            blobs = dict(zip(drivers, pool.map(_blobs, drivers), strict=True))
        for name, driver in devices:
            taint = _read(SYS_MODULE / driver / "taint")
            yield self.pkg(name, driver=driver, taint=taint, blobs=" ".join(blobs[driver]))

    def verdict(self, package: Package) -> Finding | None:
        """A driver the curated lists name (nvidia, a free Windows driver) decides for its device."""
        if entry := _curated_drivers().lookup(package.extra["driver"]):
            return Finding.from_entry(package, entry)
        return None

    def fallback(self, package: Package) -> Finding:
        driver = package.extra["driver"]
        if "P" in package.extra.get("taint", ""):
            return Finding(
                package, Status.NONFREE, reason="kernel taint P", description=f"Needs the nonfree {driver} module"
            )
        if blobs := package.extra.get("blobs", "").split():
            shown = ", ".join(blobs[:3]) + (f" and {len(blobs) - 3} more" if len(blobs) > 3 else "")
            return Finding(package, Status.USES_NONFREE, reason="firmware blobs", description=f"{driver} loads {shown}")
        return Finding(package, Status.FREE, reason=f"free driver {driver}")
