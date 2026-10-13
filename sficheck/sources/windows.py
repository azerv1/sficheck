"""Windows: installed programs from the registry, winget, scoop and Chocolatey."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PureWindowsPath

from sficheck import proc
from sficheck.models import Package
from sficheck.running import under
from sficheck.sources import _registry, meta
from sficheck.sources.base import IS_WINDOWS, Source

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
# Package-manager ids get id-based lists; display-name regexes would misfire on ids.
PACKAGE_LISTS = ("common", "windows-packages")
_SHARED_FOLDERS = {"", "program files", "program files (x86)", "programs", "appdata", "local"}


def _install_folder(values: dict[str, object]) -> str:
    """Where a program lives: InstallLocation, else the folder of its .exe icon; "" when unknown."""
    folder = str(values.get("InstallLocation", "")).strip().strip('"')
    # Some installers record a shared parent such as C:\Program Files, which would match everything.
    if PureWindowsPath(folder).name.lower() in _SHARED_FOLDERS:
        folder = ""
    if folder:
        return folder
    icon = str(values.get("DisplayIcon", "")).split(",")[0].strip().strip('"')
    # Icons under C:\Windows (the MSI cache, system tools) say nothing about the program's own folder.
    if icon.lower().endswith(".exe") and "\\windows\\" not in icon.lower():
        return str(PureWindowsPath(icon).parent)
    return ""


def _registry_programs() -> Iterator[tuple[str, str, str]]:
    """(DisplayName, DisplayVersion, install folder) for every visible Uninstall entry."""
    for hive, view in (("HKLM", _registry.WOW64_64), ("HKLM", _registry.WOW64_32), ("HKCU", 0)):
        for subkey in _registry.subkeys(UNINSTALL_KEY, hive, view):
            values = _registry.values(rf"{UNINSTALL_KEY}\{subkey}", hive, view)
            name = str(values.get("DisplayName", "")).strip()
            # Hidden components and updates belonging to another product aren't "programs".
            if not name or values.get("SystemComponent") == 1 or values.get("ParentKeyName"):
                continue
            yield name, str(values.get("DisplayVersion", "")), _install_folder(values)


def _windows_edition() -> tuple[str, str]:
    if sys.platform != "win32":
        return "", ""
    values = _registry.values(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    if not values:
        return "Microsoft Windows", ""
    product, build = str(values.get("ProductName", "")), str(values.get("CurrentBuild", ""))
    # Windows 11 still reports "Windows 10" in ProductName; the build number tells them apart.
    if build.isdigit() and int(build) >= 22000:
        product = product.replace("Windows 10", "Windows 11")
    return f"Microsoft {product}", build


class WindowsRegistry(Source):
    name = "windows"
    kind = "system"
    description = "Installed programs from the Windows registry (+ Windows itself)"
    lists = ("common", "windows")

    def available(self) -> bool:
        return IS_WINDOWS

    def packages(self) -> Iterable[Package]:
        edition, build = _windows_edition()
        if edition:
            # Windows' own processes run from here, so --in-use always keeps it.
            yield self.pkg(edition, build, folder=os.environ.get("SYSTEMROOT", r"C:\Windows"))
        programs: dict[tuple[str, str], str] = {}
        for name, version, folder in _registry_programs():
            programs.setdefault((name, version), folder)
        for (name, version), folder in programs.items():
            yield self.pkg(name, version, folder=folder)

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        return {p.name for p in packages if any(under(r, p.extra.get("folder", "")) for r in running)}


_WINGET_LICENSE = re.compile(r"^\s*License:\s*(.+)$", re.MULTILINE)


class Winget(Source):
    name = "winget"
    kind = "system"
    description = "winget packages (license from `winget show`, cached; first run is slow)"
    lists = PACKAGE_LISTS

    def available(self) -> bool:
        return IS_WINDOWS and proc.which("winget") is not None

    def _installed(self) -> list[tuple[str, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "winget.json"
            # Exits non-zero when some packages can't be mapped to a source; the file is still written.
            proc.run(
                [
                    "winget",
                    "export",
                    "-o",
                    str(out),
                    "--include-versions",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ],
                timeout=600,
            )
            data = meta.read_json(out) if out.is_file() else None
        if not isinstance(data, dict):
            return []
        return [
            (p["PackageIdentifier"], p.get("Version", ""))
            for src in data.get("Sources", [])
            for p in src.get("Packages", [])
        ]

    def _license(self, package_id: str, version: str) -> str | None:
        def show() -> str | None:
            text = proc.run(
                [
                    "winget",
                    "show",
                    "--id",
                    package_id,
                    "--exact",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ]
            )
            if text is None:
                return None
            match = _WINGET_LICENSE.search(text)
            return match.group(1).strip() if match else ""

        lic = self.ctx.fetcher.memo(f"winget-show:{package_id}:{version}", show)
        return lic or None

    def packages(self) -> Iterable[Package]:
        installed = self._installed()
        with ThreadPoolExecutor(self.ctx.jobs) as pool:
            found = pool.map(lambda item: self._license(*item), installed)
        for (package_id, version), lic in zip(installed, found, strict=True):
            yield self.pkg(package_id, version, lic)


def _scoop_root() -> Path:
    return Path(os.environ.get("SCOOP") or Path.home() / "scoop")


class Scoop(Source):
    name = "scoop"
    kind = "system"
    description = "Scoop apps (license from the installed manifest)"
    lists = PACKAGE_LISTS

    def available(self) -> bool:
        return (_scoop_root() / "apps").is_dir()

    def _roots(self) -> list[Path]:
        roots = [_scoop_root()]
        if global_root := os.environ.get("SCOOP_GLOBAL"):
            roots.append(Path(global_root))
        return roots

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        return {
            p.name
            for p in packages
            if any(under(r, str(root / "apps" / p.name)) for root in self._roots() for r in running)
        }

    def packages(self) -> Iterable[Package]:
        for root in self._roots():
            for manifest_path in root.glob("apps/*/current/manifest.json"):
                manifest = meta.read_json(manifest_path)
                if not isinstance(manifest, dict):
                    continue
                lic = manifest.get("license")
                if isinstance(lic, dict):
                    lic = lic.get("identifier")
                app = manifest_path.parent.parent.name
                if app != "scoop":
                    yield self.pkg(app, str(manifest.get("version", "")), lic if isinstance(lic, str) else None)


def _choco_root() -> Path:
    return Path(os.environ.get("CHOCOLATEYINSTALL") or r"C:\ProgramData\chocolatey")


class Chocolatey(Source):
    name = "choco"
    kind = "system"
    description = "Chocolatey packages (nuspec license/licenseUrl + curated list)"
    lists = PACKAGE_LISTS

    def available(self) -> bool:
        return IS_WINDOWS and (_choco_root() / "lib").is_dir()

    def packages(self) -> Iterable[Package]:
        for nuspec in _choco_root().glob("lib/*/*.nuspec"):
            package_id, version, lic = meta.nuspec(nuspec)
            if package_id.lower() not in {
                "chocolatey",
                "chocolatey-core.extension",
                "chocolatey-compatibility.extension",
            }:
                yield self.pkg(package_id, version, lic)
