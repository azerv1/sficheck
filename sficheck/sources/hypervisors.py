"""Hypervisors in ring -1: the one this OS runs on, and the ones installed here."""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from sficheck.models import Package, Ring
from sficheck.sources import _registry
from sficheck.sources.base import IS_WINDOWS, Source
from sficheck.sources.kernel import PROC_MODULES, SERVICES_KEY, _read

CPUINFO = Path("/proc/cpuinfo")
DMI = Path("/sys/class/dmi/id")
XEN = Path("/sys/hypervisor/type")
OSRELEASE = Path("/proc/sys/kernel/osrelease")
SYSTEM_INFO_KEY = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
SYSTEM_HYPERVISOR_INFORMATION = 0x5B  # NtQuerySystemInformation class

# (text in the machine's manufacturer and model, the hypervisor that presents it)
VM_VENDORS = (
    ("vmware", "vmware"),
    ("innotek", "virtualbox"),
    ("virtualbox", "virtualbox"),
    ("qemu", "qemu"),
    ("parallels", "parallels"),
    ("xen", "xen"),
    ("microsoft corporation virtual machine", "hyper-v"),
    ("microsoft-standard", "hyper-v"),  # WSL 2's kernel release; WSL has no DMI
)
# The kernel driver (Windows service or Linux module) each hypervisor installs.
UNDERNEATH = "running underneath this OS"
ENGINES = {"vmx86": "vmware", "vmmon": "vmware", "VBoxSup": "virtualbox", "vboxdrv": "virtualbox", "kvm": "kvm"}


def _vm_vendor(machine: str) -> str:
    machine = machine.lower()
    return next((hypervisor for text, hypervisor in VM_VENDORS if text in machine), "unidentified")


def _windows_hypervisor_present() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    info = ctypes.create_string_buffer(16)  # SYSTEM_HYPERVISOR_QUERY_INFORMATION
    status = ctypes.windll.ntdll.NtQuerySystemInformation(SYSTEM_HYPERVISOR_INFORMATION, info, len(info), None)
    return status == 0 and bool(info.raw[2])  # HypervisorPresent


def _windows_services() -> set[str]:
    return {name for name in ENGINES if _registry.value(rf"{SERVICES_KEY}\{name}", "Type")}


def _underneath() -> str | None:
    """The hypervisor this OS runs on, if any."""
    if IS_WINDOWS:
        if not _windows_hypervisor_present():
            return None
        machine = " ".join(_registry.value(SYSTEM_INFO_KEY, v) for v in ("SystemManufacturer", "SystemProductName"))
        vendor = _vm_vendor(machine)
        # On real hardware Windows runs as Hyper-V's root partition (VBS, WSL 2, Hyper-V).
        return "hyper-v" if vendor == "unidentified" else vendor
    if xen := _read(XEN):
        return xen
    flags = (line.split() for line in _read(CPUINFO).splitlines() if line.startswith("flags"))
    if not any("hypervisor" in f for f in flags):
        return None
    return _vm_vendor(f"{_read(DMI / 'sys_vendor')} {_read(DMI / 'product_name')} {_read(OSRELEASE)}")


def _installed() -> list[str]:
    drivers = (
        _windows_services() if IS_WINDOWS else {line.split(" ", 1)[0] for line in _read(PROC_MODULES).splitlines()}
    )
    return sorted({hypervisor for driver, hypervisor in ENGINES.items() if driver in drivers})


class Hypervisors(Source):
    name = "hypervisors"
    kind = "system"
    description = "The hypervisor this OS runs on, and hypervisors installed here (ring -1)"
    lists = ("hypervisors",)
    default_ring = Ring.HYPERVISOR
    default_enabled = False

    def available(self) -> bool:
        return IS_WINDOWS or CPUINFO.is_file()

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        # An installed hypervisor may sit idle; the one this OS runs on never does.
        return {p.name for p in packages if p.extra.get("role") == UNDERNEATH}

    def packages(self) -> Iterable[Package]:
        underneath = _underneath()
        if underneath:
            yield self.pkg(underneath, role=UNDERNEATH)
        for hypervisor in _installed():
            if hypervisor != underneath:
                yield self.pkg(hypervisor, role="installed")
