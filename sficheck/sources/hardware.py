"""Hardware that needs nonfree software to work: a proprietary driver, or firmware blobs loaded into it."""

from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from pathlib import Path
from typing import Any

from sficheck import proc
from sficheck.blacklist import Blacklist, load_bundled
from sficheck.models import Finding, Package, Ring, Status
from sficheck.sources import _registry
from sficheck.sources.base import IS_WINDOWS, Source
from sficheck.sources.kernel import PROC_MODULES, SYS_MODULE, _read, _windows_drivers

FIRMWARE_DIR = Path("/lib/firmware")
BLOB_SUFFIXES = ("", ".xz", ".zst")  # distros often compress linux-firmware
ENUM_KEY = r"SYSTEM\CurrentControlSet\Enum"
WINDOWS_BUSES = ("PCI", "USB", "HDAUDIO")


@cache
def _curated_drivers() -> Blacklist:
    return load_bundled("common", "kernel")


def _udev() -> Any:
    """A pyudev context, or None without libudev (minimal containers, systems without udev)."""
    try:
        import pyudev

        return pyudev.Context()
    except (ImportError, OSError):
        return None


def _udev_name(device: Any, fallback: str) -> str:
    """ "Vendor Model" from the udev hardware database (the names lspci and lsusb show)."""
    vendor, model = (device.properties.get(f"ID_{key}_FROM_DATABASE") for key in ("VENDOR", "MODEL"))
    return f"{vendor} {model or 'device ' + fallback}" if vendor else f"device {fallback}"


def _linux_devices() -> list[tuple[str, str]]:
    """(device name, driver) for PCI devices and USB interfaces with a driver bound."""
    udev, devices = _udev(), []
    for pci in udev.list_devices(subsystem="pci"):
        if pci.driver and pci.driver != "pcieport":  # bridges, not devices
            devices.append((_udev_name(pci, pci.properties.get("PCI_ID", pci.sys_name)), pci.driver))
    # Drivers bind to a USB device's interfaces; the device itself holds the name.
    for interface in udev.list_devices(subsystem="usb", DEVTYPE="usb_interface"):
        if interface.driver and interface.driver != "hub":
            usb = interface.find_parent("usb", "usb_device") or interface
            devices.append((_udev_name(usb, usb.properties.get("PRODUCT", usb.sys_name)), interface.driver))
    return list(dict.fromkeys(devices))


def _blobs(driver: str) -> list[str]:
    """Firmware files the driver's module asks for that are installed here."""
    declared = (proc.run(["modinfo", "-F", "firmware", driver]) or "").split()
    return [blob for blob in declared if any((FIRMWARE_DIR / (blob + s)).is_file() for s in BLOB_SUFFIXES)]


def _windows_devices() -> Iterator[tuple[str, str]]:
    """(device name, driver service) for every PCI, USB and HD Audio device plugged in now."""
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    locate, node = ctypes.WinDLL("cfgmgr32").CM_Locate_DevNodeW, wintypes.DWORD()
    for bus in WINDOWS_BUSES:
        for device in _registry.subkeys(rf"{ENUM_KEY}\{bus}"):
            for instance in _registry.subkeys(rf"{ENUM_KEY}\{bus}\{device}"):
                path = rf"{bus}\{device}\{instance}"
                if locate(ctypes.byref(node), path, 0) != 0:  # the registry remembers unplugged devices too
                    continue
                values = _registry.values(rf"{ENUM_KEY}\{path}")
                if service := str(values.get("Service", "")):
                    # "@oem12.inf,%desc%;Intel(R) Wi-Fi 6 AX201" -> the part after the last ;
                    yield str(values.get("DeviceDesc", device)).rpartition(";")[2], service


class Hardware(Source):
    name = "hardware"
    kind = "system"
    description = "Devices that need a nonfree driver or firmware blobs"
    lists = ()  # devices are judged by their driver, in verdict
    default_ring = Ring.KERNEL
    default_enabled = False
    always_in_use = True

    def available(self) -> bool:
        return IS_WINDOWS or (PROC_MODULES.is_file() and _udev() is not None)

    def packages(self) -> Iterable[Package]:
        if IS_WINDOWS:
            # Devices on Microsoft's inbox drivers are covered by Windows itself.
            third_party = {service.lower(): info for service, info in _windows_drivers(self.ctx.jobs)}
            for name, service in dict.fromkeys(_windows_devices()):
                if (info := third_party.get(service.lower())) is not None:
                    yield self.pkg(name, driver=service, company=info.get("CompanyName", ""))
            return
        devices = _linux_devices()
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
        if "company" in package.extra:
            vendor = package.extra["company"] or "an unnamed vendor"
            return Finding(
                package, Status.NONFREE, reason="third-party driver", description=f"Needs {driver} from {vendor}"
            )
        if "P" in package.extra.get("taint", ""):
            return Finding(
                package, Status.NONFREE, reason="kernel taint P", description=f"Needs the nonfree {driver} module"
            )
        if blobs := package.extra.get("blobs", "").split():
            shown = ", ".join(blobs[:3]) + (f" and {len(blobs) - 3} more" if len(blobs) > 3 else "")
            return Finding(package, Status.USES_NONFREE, reason="firmware blobs", description=f"{driver} loads {shown}")
        return Finding(package, Status.FREE, reason=f"free driver {driver}")
