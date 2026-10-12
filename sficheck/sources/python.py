"""Python: the default interpreter's site-packages, uv tools and pipx apps."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from sficheck import proc
from sficheck.models import Package
from sficheck.sources import meta
from sficheck.sources.base import IS_WINDOWS, Source

_SITE_SCRIPT = "import json, site; print(json.dumps(site.getsitepackages() + [site.getusersitepackages()]))"


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def venv_site_packages(venv: Path) -> list[Path]:
    return [p for p in (venv / "Lib" / "site-packages", *venv.glob("lib/python*/site-packages")) if p.is_dir()]


def tool_venv_packages(venvs_dir: Path) -> Iterator[tuple[str, str, str | None]]:
    """For each tool venv (named after its main package), yield that package's metadata."""
    if not venvs_dir.is_dir():
        return
    for venv in sorted(p for p in venvs_dir.iterdir() if p.is_dir()):
        wanted = _normalize(venv.name)
        for site in venv_site_packages(venv):
            match = next((d for d in meta.site_packages_dists(site) if _normalize(d[0]) == wanted), None)
            if match:
                yield match
                break


class Pip(Source):
    name = "pip"
    description = "Packages in the default Python interpreter (core metadata licenses)"
    registry = "pypi"

    def _interpreter(self) -> list[str]:
        return ["py"] if IS_WINDOWS and proc.which("py") else ["python3"]

    def available(self) -> bool:
        return proc.which(self._interpreter()[0]) is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run([*self._interpreter(), "-c", _SITE_SCRIPT])
        seen: set[str] = set()
        for site in json.loads(out) if out else []:
            for name, version, lic in meta.site_packages_dists(Path(site)):
                if _normalize(name) not in seen:
                    seen.add(_normalize(name))
                    yield self.pkg(name, version, lic)


class UvTools(Source):
    name = "uv"
    description = "Tools installed with `uv tool install`"
    registry = "pypi"

    def available(self) -> bool:
        return proc.which("uv") is not None

    def packages(self) -> Iterable[Package]:
        tool_dir = (proc.run(["uv", "tool", "dir"]) or "").strip()
        for name, version, lic in tool_venv_packages(Path(tool_dir)) if tool_dir else ():
            yield self.pkg(name, version, lic)


class Pipx(Source):
    name = "pipx"
    description = "Apps installed with pipx"
    registry = "pypi"

    def available(self) -> bool:
        return proc.which("pipx") is not None

    def packages(self) -> Iterable[Package]:
        venvs = (proc.run(["pipx", "environment", "--value", "PIPX_LOCAL_VENVS"]) or "").strip()
        for name, version, lic in tool_venv_packages(Path(venvs)) if venvs else ():
            yield self.pkg(name, version, lic)
