"""The Source base class every package-manager integration derives from."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from sficheck.models import Finding, Package, Ring, Status
from sficheck.net import Fetcher


@dataclass(slots=True)
class Context:
    """Run-wide settings sources may need."""

    fetcher: Fetcher
    include_privacy: bool = False
    jobs: int = 8


class Source:
    """A place packages get installed from.

    Subclasses set the class attributes and implement ``available`` and ``packages``.
    ``verdict`` is for ecosystems with their own authoritative notion of freedom
    (Parabola's blacklist, Debian's archive sections, nixpkgs' ``meta.unfree``).
    """

    name: ClassVar[str]
    kind: ClassVar[str] = "lang"  # "system" | "lang"
    description: ClassVar[str] = ""
    # Bundled curated lists (data/lists/<name>.json) consulted for this source.
    lists: ClassVar[tuple[str, ...]] = ("lang",)
    # Registry key for online license lookups (see registries.py), if any.
    registry: ClassVar[str | None] = None
    # Status for packages nothing else could classify. Distros that vet their
    # main archive (Arch/Parabola, Debian main) treat unflagged packages as free.
    fallback_status: ClassVar[Status] = Status.UNKNOWN
    # Ring for proprietary findings whose curated entry doesn't name one.
    default_ring: ClassVar[Ring] = Ring.USER
    # Caches (maven, gradle, nuget) can hold thousands of entries; only scan on request.
    default_enabled: ClassVar[bool] = True
    # Everything the source reports is loaded or present right now (drivers, firmware, devices).
    always_in_use: ClassVar[bool] = False

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    def available(self) -> bool:
        raise NotImplementedError

    def packages(self) -> Iterable[Package]:
        raise NotImplementedError

    def verdict(self, package: Package) -> Finding | None:
        return None

    def in_use(self, packages: Sequence[Package], running: set[Path]) -> set[str] | None:
        """Names of these packages that own one of the ``running`` programs (--in-use).

        None means this source can't tell, and --in-use hides its findings.
        """
        return {p.name for p in packages} if self.always_in_use else None

    def lookup_name(self, package: Package) -> str | None:
        """The name to look up in ``registry``; None skips the online lookup for this package."""
        return package.name

    def fallback(self, package: Package) -> Finding:
        """The finding for a package nothing else could classify."""
        reason = "not blacklisted" if self.fallback_status is Status.FREE else "no license information"
        return Finding(package, self.fallback_status, reason=reason, description=package.license or "")

    def pkg(self, name: str, version: str = "", license: str | None = None, **extra: str) -> Package:
        return Package(name=name, source=self.name, version=version, license=license or None, extra=extra)


def env_path(var: str, default: Path) -> Path:
    value = os.environ.get(var)
    return Path(value) if value else default


IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
