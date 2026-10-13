"""Unix system package managers: pacman, dpkg, rpm, nix, flatpak, snap, brew."""

from __future__ import annotations

import gzip
import json
import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from sficheck import blacklist, proc
from sficheck.models import Finding, Package, Status
from sficheck.sources.base import Context, Source

log = logging.getLogger(__name__)


class Pacman(Source):
    name = "pacman"
    kind = "system"
    description = "Arch-based distros, checked against Parabola's blacklists (+AUR)"
    lists = ("common",)
    fallback_status = Status.FREE

    def __init__(self, ctx: Context) -> None:
        super().__init__(ctx)
        self._parabola: blacklist.Blacklist | None = None

    def available(self) -> bool:
        return proc.which("pacman") is not None

    def packages(self) -> Iterable[Package]:
        self._parabola = blacklist.load_parabola(self.ctx.fetcher, include_privacy=self.ctx.include_privacy)
        foreign = set((proc.run(["pacman", "-Qqm"], ok_codes=(0, 1)) or "").split())
        out = proc.run(["pacman", "-Q"]) or ""
        for line in out.splitlines():
            name, _, version = line.partition(" ")
            yield self.pkg(name, version, repo="aur" if name in foreign else "repo")

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        # Exits 1 when some paths belong to no package; the owned ones are still printed.
        return set((proc.run(["pacman", "-Qqo", *map(str, running)], ok_codes=(0, 1)) or "").split())

    def verdict(self, package: Package) -> Finding | None:
        entry = self._parabola.lookup(package.name) if self._parabola else None
        return Finding.from_entry(package, entry) if entry else None


# Archive areas: Debian (non-free, non-free-firmware, contrib) and Ubuntu (restricted, multiverse).
DEB_SECTIONS = {
    "non-free": (Status.NONFREE, "in Debian's non-free archive area"),
    "non-free-firmware": (Status.NONFREE, "nonfree firmware"),
    "restricted": (Status.NONFREE, "in Ubuntu's restricted component (proprietary drivers)"),
    "multiverse": (Status.NONFREE, "in Ubuntu's multiverse component (not free software)"),
    "contrib": (Status.USES_NONFREE, "free, but depends on or installs nonfree software (contrib)"),
}


class Dpkg(Source):
    name = "dpkg"
    kind = "system"
    description = "Debian, Ubuntu, Mint, Pop!_OS... (archive section + curated list)"
    lists = ("common", "debian")
    fallback_status = Status.FREE

    def available(self) -> bool:
        return proc.which("dpkg-query") is not None

    def packages(self) -> Iterable[Package]:
        fmt = r"${db:Status-Abbrev}\t${Package}\t${Version}\t${Section}\n"
        out = proc.run(["dpkg-query", "-W", "-f", fmt]) or ""
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 4 and parts[0].startswith("ii"):
                yield self.pkg(parts[1], parts[2], section=parts[3])

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        out = proc.run(["dpkg", "-S", *map(str, running)], ok_codes=(0, 1)) or ""
        # "pkg1, pkg2:amd64: /usr/bin/x" -> pkg1, pkg2
        owners = (line.rpartition(": ")[0] for line in out.splitlines() if ": " in line)
        return {name.strip().split(":")[0] for names in owners for name in names.split(",")}

    def verdict(self, package: Package) -> Finding | None:
        area = package.extra.get("section", "").split("/")[0]
        if area in DEB_SECTIONS:
            status, why = DEB_SECTIONS[area]
            return Finding(package, status, reason=f"section:{package.extra['section']}", description=why)
        return None


class Rpm(Source):
    name = "rpm"
    kind = "system"
    description = "Fedora, RHEL, openSUSE, Mageia... (rpm License tag + curated list)"
    lists = ("common",)

    def available(self) -> bool:
        return proc.which("rpm") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["rpm", "-qa", "--qf", r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\n"]) or ""
        for line in out.splitlines():
            parts = line.split("\t")
            # gpg-pubkey entries are the signing keys rpm imported, not software.
            if len(parts) == 3 and parts[0] != "gpg-pubkey":
                yield self.pkg(parts[0], parts[1], None if parts[2] == "(none)" else parts[2])

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        out = proc.run(["rpm", "-qf", "--qf", r"%{NAME}\n", *map(str, running)], ok_codes=(0, 1)) or ""
        # Unowned paths print "file /x is not owned by any package" on the same stream.
        return {line for line in out.splitlines() if line and " " not in line}


def nix_license_status(meta: dict[str, Any]) -> tuple[Status, str] | None:
    """nixpkgs meta → status. ``license`` is an attrset or a list of them, each with ``free``."""
    lic = meta.get("license")
    lics = lic if isinstance(lic, list) else [lic] if lic else []
    lics = [x for x in lics if isinstance(x, dict)]
    names = ", ".join(str(x.get("spdxId") or x.get("shortName") or "?") for x in lics)
    if meta.get("unfree") or any(x.get("free") is False for x in lics):
        if any(x.get("free") is True for x in lics):
            return Status.SEMIFREE, names
        return Status.NONFREE, names or "unfree"
    if lics and all(x.get("free") is True for x in lics):
        return Status.FREE, names
    return None


_NIXOS_EXPR = """
let sys = import <nixpkgs/nixos> {}; in
map (p: { name = p.pname or p.name or "?"; version = p.version or "";
          meta = { license = p.meta.license or null; unfree = p.meta.unfree or false; }; })
    sys.config.environment.systemPackages
"""


class Nix(Source):
    name = "nix"
    kind = "system"
    description = "nix-env and nix profile installs, NixOS systemPackages (nixpkgs meta.license)"
    lists = ("common",)

    def available(self) -> bool:
        return proc.which("nix-env") is not None or proc.which("nix") is not None

    def packages(self) -> Iterable[Package]:
        seen: set[str] = set()
        for name, version, meta in self._entries():
            if name in seen:
                continue
            seen.add(name)
            verdict = nix_license_status(meta)
            extra = {"nix_status": verdict[0].value, "nix_license": verdict[1]} if verdict else {}
            yield self.pkg(name, version, **extra)

    def _entries(self) -> Iterator[tuple[str, str, dict[str, Any]]]:
        if out := proc.run(["nix-env", "-q", "--json", "--meta"]):
            for item in json.loads(out).values():
                yield item.get("pname") or item.get("name", "?"), item.get("version", ""), item.get("meta", {})
        if out := proc.run(["nix", "profile", "list", "--json"]):
            elements = json.loads(out).get("elements", {})
            items = elements.items() if isinstance(elements, dict) else enumerate(elements)
            for key, element in items:
                url, attr = element.get("originalUrl"), element.get("attrPath")
                if not (url and attr):
                    continue
                meta_out = proc.run(["nix", "eval", "--json", f"{url}#{attr}.meta"])
                meta = json.loads(meta_out) if meta_out else {}
                yield str(key if isinstance(key, str) else attr.split(".")[-1]), "", meta
        if Path("/etc/NIXOS").exists() and (
            out := proc.run(["nix-instantiate", "--eval", "--json", "--strict", "-E", _NIXOS_EXPR], timeout=300)
        ):
            for item in json.loads(out):
                yield item["name"], item.get("version", ""), item.get("meta", {})

    def verdict(self, package: Package) -> Finding | None:
        if status := package.extra.get("nix_status"):
            return Finding(package, Status(status), reason=f"nixpkgs:{package.extra.get('nix_license', '')}")
        return None


def flatpak_appstream_licenses() -> dict[str, str]:
    """Map app id → project_license from every locally cached appstream catalogue."""
    roots = [Path("/var/lib/flatpak"), Path.home() / ".local/share/flatpak"]
    result: dict[str, str] = {}
    for root in roots:
        for path in root.glob("appstream/*/*/active/appstream.xml*"):
            try:
                opener = gzip.open if path.suffix == ".gz" else open
                with opener(path, "rb") as fh:
                    tree = ET.parse(fh)
            except (OSError, ET.ParseError) as exc:
                log.debug("skip %s: %s", path, exc)
                continue
            for comp in tree.getroot().iter("component"):
                app_id, lic = comp.findtext("id"), comp.findtext("project_license")
                if app_id and lic:
                    result.setdefault(app_id.removesuffix(".desktop"), lic)
    return result


class Flatpak(Source):
    name = "flatpak"
    kind = "system"
    description = "Flatpak apps (license from the local appstream catalogue)"
    lists = ("common",)

    def available(self) -> bool:
        return proc.which("flatpak") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["flatpak", "list", "--app", "--columns=application,version,origin"]) or ""
        licenses_by_id = flatpak_appstream_licenses()
        for line in out.splitlines():
            app_id, version, origin = ([*line.split("\t"), "", ""])[:3]
            if app_id:
                yield self.pkg(app_id, version, licenses_by_id.get(app_id), origin=origin)

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        # Sandboxed apps run from paths the host can't map back, so ask flatpak itself.
        return set((proc.run(["flatpak", "ps", "--columns=application"]) or "").split())


class Snap(Source):
    name = "snap"
    kind = "system"
    description = "Snap packages (license from `snap info`)"
    lists = ("common",)

    def available(self) -> bool:
        return proc.which("snap") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["snap", "list"]) or ""
        rows = [line.split() for line in out.splitlines()[1:] if line.strip()]
        names = [(r[0], r[1]) for r in rows if len(r) >= 2]

        def info(name: str) -> str | None:
            text = proc.run(["snap", "info", name]) or ""
            match = re.search(r"^license:\s*(.+)$", text, re.MULTILINE)
            return match.group(1).strip() if match else None

        with ThreadPoolExecutor(self.ctx.jobs) as pool:
            found = pool.map(info, [n for n, _ in names])
        for (name, version), lic in zip(names, found, strict=True):
            yield self.pkg(name, version, lic)

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        # Snaps run from /snap/<name>/<revision>/; /snap/bin only holds launchers.
        parts = (p.as_posix().split("/") for p in running)
        return {x[2] for x in parts if len(x) > 3 and x[:2] == ["", "snap"] and x[2] != "bin"}


class Brew(Source):
    name = "brew"
    kind = "system"
    description = "Homebrew formulae (license field) and casks (curated list)"
    lists = ("common",)

    def available(self) -> bool:
        return proc.which("brew") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["brew", "info", "--json=v2", "--installed"], timeout=300)
        if not out:
            return
        data = json.loads(out)
        for formula in data.get("formulae", []):
            installed = formula.get("installed") or [{}]
            yield self.pkg(formula["name"], installed[-1].get("version", ""), formula.get("license"), type="formula")
        for cask in data.get("casks", []):
            yield self.pkg(cask["token"], cask.get("installed") or cask.get("version", ""), None, type="cask")

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        # Formulae run from <prefix>/Cellar/<name>/<version>/; casks are apps brew can't map.
        return {p.parts[p.parts.index("Cellar") + 1] for p in running if "Cellar" in p.parts[:-1]}
