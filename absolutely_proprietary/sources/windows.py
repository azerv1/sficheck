"""Windows: installed programs from the registry, winget, scoop and Chocolatey."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from absolutely_proprietary import proc
from absolutely_proprietary.models import Package
from absolutely_proprietary.sources import meta
from absolutely_proprietary.sources.base import IS_WINDOWS, Source

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
# Package-manager ids get id-based lists; display-name regexes would misfire on ids.
PACKAGE_LISTS = ("common", "windows-packages")


def _registry_programs() -> Iterator[tuple[str, str]]:
    """(DisplayName, DisplayVersion) for every visible Uninstall entry."""
    if sys.platform != "win32":
        return
    import winreg

    views = [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, 0),
    ]
    for hive, view in views:
        try:
            root = winreg.OpenKey(hive, UNINSTALL_KEY, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, i)) as key:
                        values = {}
                        for j in range(winreg.QueryInfoKey(key)[1]):
                            vname, value, _ = winreg.EnumValue(key, j)
                            values[vname] = value
                except OSError:
                    continue
                name = str(values.get("DisplayName", "")).strip()
                # Hidden components and updates belonging to another product aren't "programs".
                if not name or values.get("SystemComponent") == 1 or values.get("ParentKeyName"):
                    continue
                yield name, str(values.get("DisplayVersion", ""))


def _windows_edition() -> tuple[str, str]:
    if sys.platform != "win32":
        return "", ""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product = str(winreg.QueryValueEx(key, "ProductName")[0])
            build = str(winreg.QueryValueEx(key, "CurrentBuild")[0])
    except OSError:
        return "Microsoft Windows", ""
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
            yield self.pkg(edition, build)
        for name, version in dict.fromkeys(_registry_programs()):
            yield self.pkg(name, version)


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

    def packages(self) -> Iterable[Package]:
        roots = [_scoop_root()]
        if global_root := os.environ.get("SCOOP_GLOBAL"):
            roots.append(Path(global_root))
        for root in roots:
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
