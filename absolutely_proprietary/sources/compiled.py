"""Compiled-language ecosystems: Rust, Go, .NET, C/C++ (vcpkg, conan), Swift (mint)."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from pathlib import Path

from absolutely_proprietary import licenses, proc
from absolutely_proprietary.models import Package
from absolutely_proprietary.sources import meta
from absolutely_proprietary.sources.base import Source, env_path

_CARGO_LINE = re.compile(r"^(\S+) v(\S+?)(?: \(.*\))?:$")


class Cargo(Source):
    name = "cargo"
    description = "Crates installed with `cargo install` (Cargo.toml license)"
    registry = "cargo"

    def available(self) -> bool:
        return proc.which("cargo") is not None

    def packages(self) -> Iterable[Package]:
        registry_src = env_path("CARGO_HOME", Path.home() / ".cargo") / "registry" / "src"
        for line in (proc.run(["cargo", "install", "--list"]) or "").splitlines():
            if match := _CARGO_LINE.match(line):
                name, version = match.groups()
                manifest = next(registry_src.glob(f"*/{name}-{version}/Cargo.toml"), None)
                yield self.pkg(name, version, meta.cargo_license(manifest) if manifest else None)


def _go_escape(module: str) -> str:
    """Go module cache paths escape upper-case letters as '!' + lower-case."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


class Go(Source):
    name = "go"
    description = "Binaries installed with `go install` (module cache LICENSE)"
    registry = "go"

    def available(self) -> bool:
        return proc.which("go") is not None

    def packages(self) -> Iterable[Package]:
        gobin, gopath, modcache = (
            [*(proc.run(["go", "env", "GOBIN", "GOPATH", "GOMODCACHE"]) or "").splitlines(), "", "", ""]
        )[:3]
        bin_dir = Path(gobin) if gobin else Path(gopath) / "bin"
        binaries = [str(p) for p in bin_dir.iterdir() if p.is_file()] if bin_dir.is_dir() else []
        if not binaries:
            return
        out = proc.run(["go", "version", "-m", *binaries]) or ""
        for block in re.split(r"^(?=\S)", out, flags=re.MULTILINE):
            mod = re.search(r"^\s+mod\s+(\S+)\s+(\S+)", block, re.MULTILINE)
            if not mod:
                continue
            module, version = mod.groups()
            lic = licenses.sniff_dir(Path(modcache) / f"{_go_escape(module)}@{version}") if modcache else None
            yield self.pkg(module, version, lic)


class DotnetTools(Source):
    name = "dotnet"
    description = "Global .NET tools (nuspec license)"
    registry = "nuget"

    def available(self) -> bool:
        return (Path.home() / ".dotnet" / "tools" / ".store").is_dir()

    def packages(self) -> Iterable[Package]:
        store = Path.home() / ".dotnet" / "tools" / ".store"
        # .store/<id>/<version>/<id>/<version>/<id>.nuspec
        for nuspec in store.glob("*/*/*/*/*.nuspec"):
            yield self.pkg(*meta.nuspec(nuspec))


class NugetCache(Source):
    name = "nuget"
    description = "Every package in the NuGet cache (can be large)"
    registry = "nuget"
    default_enabled = False

    def _root(self) -> Path:
        return env_path("NUGET_PACKAGES", Path.home() / ".nuget" / "packages")

    def available(self) -> bool:
        return self._root().is_dir()

    def packages(self) -> Iterable[Package]:
        for nuspec in self._root().glob("*/*/*.nuspec"):
            yield self.pkg(*meta.nuspec(nuspec))


class Vcpkg(Source):
    name = "vcpkg"
    description = "vcpkg packages (port vcpkg.json license)"

    def available(self) -> bool:
        return proc.which("vcpkg") is not None

    def packages(self) -> Iterable[Package]:
        exe = proc.which("vcpkg")
        root = Path(os.environ.get("VCPKG_ROOT") or (Path(exe).parent if exe else "."))
        out = proc.run(["vcpkg", "list", "--x-json"])
        seen: set[str] = set()
        for item in (json.loads(out) if out else {}).values():
            name = item.get("package_name", "")
            if not name or name in seen:
                continue
            seen.add(name)
            port = meta.read_json(root / "ports" / name / "vcpkg.json")
            lic = port.get("license") if isinstance(port, dict) else None
            yield self.pkg(name, item.get("version", ""), lic)


_CONAN_LICENSE = re.compile(r"^\s*license\s*=\s*(.+)$", re.MULTILINE)


class Conan(Source):
    name = "conan"
    description = "Recipes in the local Conan 2 cache (conanfile license)"

    def available(self) -> bool:
        return proc.which("conan") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["conan", "list", "*", "--format=json"])
        cache = (json.loads(out) if out else {}).get("Local Cache", {})
        for ref in cache:
            name, _, version = ref.partition("/")
            export = (proc.run(["conan", "cache", "path", ref]) or "").strip()
            lic = None
            if export and (conanfile := Path(export) / "conanfile.py").is_file():
                text = conanfile.read_text(encoding="utf-8", errors="replace")
                if match := _CONAN_LICENSE.search(text):
                    lic = " OR ".join(f"({x})" for x in re.findall(r"[\"']([^\"']+)[\"']", match.group(1)))
            yield self.pkg(name, version.split("@")[0], lic)


class Mint(Source):
    name = "mint"
    description = "Swift command-line tools installed with Mint (license via GitHub)"
    registry = "github"

    def available(self) -> bool:
        return proc.which("mint") is not None

    def packages(self) -> Iterable[Package]:
        current = ""
        for line in (proc.run(["mint", "list"]) or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("- ") and current:
                yield self.pkg(current, stripped[2:].strip(" *"))
            elif "/" in stripped and " " not in stripped:
                current = stripped
