"""Firmware below the OS: the BIOS/UEFI (ring -2), the Intel ME / AMD PSP and CPU microcode (ring -3)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sficheck.models import Finding, Package, Ring, Status
from sficheck.sources import _registry
from sficheck.sources.base import IS_WINDOWS, Source
from sficheck.sources.hypervisors import CPUINFO, DMI
from sficheck.sources.kernel import _read

MEI_FW_VER = Path("/sys/class/mei/mei0/fw_ver")
BIOS_KEY = r"HARDWARE\DESCRIPTION\System\BIOS"
CPU_KEY = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
# CPU vendor -> the coprocessor every current chip of theirs ships, and their microcode.
COPROCESSORS = {"GenuineIntel": "intel-me", "AuthenticAMD": "amd-psp"}
MICROCODE = {"GenuineIntel": "intel-microcode", "AuthenticAMD": "amd-microcode"}


def _revision(raw: object) -> str:
    """Windows' "Update Revision": the microcode revision, in the high half when it's 8 bytes long."""
    if not isinstance(raw, bytes) or not any(raw):
        return ""
    value = int.from_bytes(raw, "little")
    return hex(value >> 32 if len(raw) == 8 else value)


def _windows_platform() -> dict[str, str]:
    bios, cpu = _registry.values(BIOS_KEY), _registry.values(CPU_KEY)
    return {
        "bios_vendor": str(bios.get("BIOSVendor", "")),
        "bios_version": str(bios.get("BIOSVersion", "")),
        "cpu_vendor": str(cpu.get("VendorIdentifier", "")),
        "microcode": _revision(cpu.get("Update Revision")),
        "me_version": "",  # needs the ME driver's own interface
    }


def _linux_platform() -> dict[str, str]:
    cpu: dict[str, str] = {}
    for line in _read(CPUINFO).splitlines():
        if not line.strip():
            break  # the first processor is enough
        key, _, value = line.partition(":")
        cpu[key.strip()] = value.strip()
    me_version = (_read(MEI_FW_VER).splitlines() or [""])[0]  # "0:16.1.25.1885"
    return {
        "bios_vendor": _read(DMI / "bios_vendor"),
        "bios_version": _read(DMI / "bios_version"),
        "cpu_vendor": cpu.get("vendor_id", ""),
        "microcode": cpu.get("microcode", "").replace("0xffffffff", ""),  # what VMs show instead of the real one
        "me_version": me_version.rpartition(":")[2],
    }


class Firmware(Source):
    name = "firmware"
    kind = "system"
    description = "BIOS/UEFI (ring -2), Intel ME / AMD PSP and CPU microcode (ring -3)"
    lists = ("firmware",)
    default_ring = Ring.FIRMWARE
    default_enabled = False
    always_in_use = True

    def available(self) -> bool:
        return IS_WINDOWS or CPUINFO.is_file()

    def packages(self) -> Iterable[Package]:
        found = _windows_platform() if IS_WINDOWS else _linux_platform()
        if found["bios_vendor"]:
            yield self.pkg(found["bios_vendor"], found["bios_version"], part="bios")
        if coprocessor := COPROCESSORS.get(found["cpu_vendor"]):
            yield self.pkg(coprocessor, found["me_version"])
        if microcode := MICROCODE.get(found["cpu_vendor"]):
            yield self.pkg(microcode, found["microcode"])

    def fallback(self, package: Package) -> Finding:
        if package.extra.get("part") == "bios":
            # Vendor BIOSes (AMI, Insyde, Phoenix, OEMs) ship as binaries; the free ones are listed.
            description = f"BIOS/UEFI firmware from {package.name}"
            return Finding(
                package, Status.NONFREE, reason="vendor firmware", description=description, alternatives=("libreboot",)
            )
        return super().fallback(package)
