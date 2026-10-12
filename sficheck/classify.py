"""Turn a source's packages into findings, in order of decreasing authority."""

from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from sficheck import licenses, registries
from sficheck.blacklist import Blacklist, load_bundled
from sficheck.models import Finding, Package, Status
from sficheck.net import Fetcher
from sficheck.sources.base import Source


def _from_license(package: Package, license_expr: str | None, origin: str) -> Finding | None:
    status = licenses.classify(license_expr)
    if status is Status.UNKNOWN:
        return None
    return Finding(package, status, reason=origin, description=license_expr or "")


def _with_ring(source: Source, finding: Finding) -> Finding:
    """Proprietary findings without a ring from their entry get the source's default."""
    if finding.ring is None and finding.status.is_proprietary:
        return replace(finding, ring=source.default_ring)
    return finding


@dataclass(slots=True)
class Classifier:
    """Decides each package's status. The first step with an answer wins:

    1. user blacklists  2. the source's own verdict (Parabola, Debian section, nixpkgs meta)
    3. bundled curated lists  4. declared license  5. online registry (opt-in)
    6. the source's fallback (free for vetted distro archives, unknown otherwise; see Source.fallback)
    """

    fetcher: Fetcher
    user: Blacklist = field(default_factory=Blacklist)
    ignore: frozenset[str] = frozenset()
    use_bundled: bool = True
    online: bool = False
    jobs: int = 8
    _bundled: dict[tuple[str, ...], Blacklist] = field(default_factory=dict)

    def _curated(self, names: tuple[str, ...]) -> Blacklist:
        if not self.use_bundled:
            return Blacklist()
        if names not in self._bundled:
            self._bundled[names] = load_bundled(*names)
        return self._bundled[names]

    def _offline(self, source: Source, package: Package, curated: Blacklist) -> Finding | None:
        if entry := self.user.lookup(package.name):
            return Finding.from_entry(package, entry)
        if finding := source.verdict(package):
            return finding
        if entry := curated.lookup(package.name):
            return Finding.from_entry(package, entry)
        return _from_license(package, package.license, "license")

    def _online(self, source: Source, package: Package) -> Finding | None:
        assert source.registry is not None
        found = registries.lookup_license(self.fetcher, source.registry, package.name, package.version)
        return _from_license(package, found, f"online:{source.registry}")

    def run(self, source: Source, packages: Iterable[Package]) -> list[Finding]:
        curated = self._curated(source.lists)
        findings: list[Finding] = []
        pending: list[Package] = []
        for package in packages:
            if package.name.lower() in self.ignore:
                continue
            if finding := self._offline(source, package, curated):
                findings.append(finding)
            elif self.online and source.registry:
                pending.append(package)
            else:
                findings.append(source.fallback(package))
        if pending:
            with ThreadPoolExecutor(self.jobs) as pool:
                for package, finding in zip(pending, pool.map(lambda p: self._online(source, p), pending), strict=True):
                    findings.append(finding or source.fallback(package))
        return [_with_ring(source, f) for f in findings]
