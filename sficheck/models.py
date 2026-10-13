"""Core data types shared by sources, classifiers and renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class Status(StrEnum):
    NONFREE = "nonfree"
    SEMIFREE = "semifree"
    USES_NONFREE = "uses-nonfree"
    FREE = "free"
    UNKNOWN = "unknown"

    @property
    def is_proprietary(self) -> bool:
        return self in (Status.NONFREE, Status.SEMIFREE, Status.USES_NONFREE)


class Antifeature(StrEnum):
    """Why a finding matters beyond its license; F-Droid's anti-features (minus NSFW) plus DRM.

    Tags never change a status or the Freedom Index.
    """

    ADS = "ads"
    TRACKING = "tracking"
    NONFREE_NET = "nonfree-net"  # promotes or depends on a nonfree network service
    NONFREE_ADD = "nonfree-add"  # promotes nonfree add-ons
    NONFREE_DEP = "nonfree-dep"  # needs nonfree software to work
    NONFREE_ASSETS = "nonfree-assets"
    UPSTREAM_NONFREE = "upstream-nonfree"  # the upstream release contains nonfree parts
    TETHERED_NET = "tethered-net"  # only works with the developer's own servers
    KNOWN_VULN = "known-vuln"
    DISABLED_ALGORITHM = "disabled-algorithm"
    NO_SOURCE_SINCE = "no-source-since"
    DRM = "drm"


# F-Droid's index names for the anti-features above.
FDROID_ANTIFEATURES = {
    "Ads": Antifeature.ADS,
    "Tracking": Antifeature.TRACKING,
    "NonFreeNet": Antifeature.NONFREE_NET,
    "NonFreeAdd": Antifeature.NONFREE_ADD,
    "NonFreeDep": Antifeature.NONFREE_DEP,
    "NonFreeAssets": Antifeature.NONFREE_ASSETS,
    "UpstreamNonFree": Antifeature.UPSTREAM_NONFREE,
    "TetheredNet": Antifeature.TETHERED_NET,
    "KnownVuln": Antifeature.KNOWN_VULN,
    "DisabledAlgorithm": Antifeature.DISABLED_ALGORITHM,
    "NoSourceSince": Antifeature.NO_SOURCE_SINCE,
}


class Ring(IntEnum):
    """The CPU protection ring a program runs in; lower rings see and control more.

    Rings 1 and 2 go unused by mainstream OSes. The negative rings are the usual names
    for what sits below the kernel.
    """

    ME = -3  # Intel ME, AMD PSP, CPU microcode: runs even while the OS is off
    FIRMWARE = -2  # BIOS/UEFI and System Management Mode
    HYPERVISOR = -1
    KERNEL = 0  # kernel modules and drivers, kernel-level anticheat
    USER = 3


@dataclass(frozen=True, slots=True)
class Package:
    """One installed thing reported by a source."""

    name: str
    source: str
    version: str = ""
    license: str | None = None
    # Free-form hints a source wants to pass to its own verdict() (e.g. Debian section).
    extra: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True, slots=True)
class Entry:
    """A blacklist / curated-list record describing a known package."""

    name: str
    status: Status
    alternatives: tuple[str, ...] = ()
    description: str = ""
    origin: str = ""
    reference: str = ""
    ring: Ring | None = None  # None: the scanning source's default
    antifeatures: tuple[Antifeature, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """The classification result for one package."""

    package: Package
    status: Status
    reason: str = ""
    alternatives: tuple[str, ...] = ()
    description: str = ""
    # Where the status claim comes from (license page, Parabola issue, ...).
    reference: str = ""
    # Set on proprietary findings: how deep into the machine the software reaches.
    ring: Ring | None = None
    antifeatures: tuple[Antifeature, ...] = ()

    @classmethod
    def from_entry(cls, package: Package, entry: Entry) -> Finding:
        return cls(
            package=package,
            status=entry.status,
            reason=entry.origin,
            alternatives=entry.alternatives,
            description=entry.description,
            reference=entry.reference,
            ring=entry.ring,
            antifeatures=entry.antifeatures,
        )


@dataclass(slots=True)
class SourceReport:
    """All findings for one source, plus anything that went wrong while scanning it."""

    source: str
    kind: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    def count(self, *statuses: Status) -> int:
        return sum(1 for f in self.findings if f.status in statuses)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def proprietary(self) -> int:
        return sum(1 for f in self.findings if f.status.is_proprietary)

    @property
    def unknown(self) -> int:
        return self.count(Status.UNKNOWN)

    def freedom_index(self, unknown_as_nonfree: bool = False) -> float | None:
        """Percentage of classified packages that are free; None when nothing is classified."""
        bad = self.proprietary + (self.unknown if unknown_as_nonfree else 0)
        considered = self.total if unknown_as_nonfree else self.total - self.unknown
        if considered == 0:
            return None
        return (considered - bad) * 100 / considered
