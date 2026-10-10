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
