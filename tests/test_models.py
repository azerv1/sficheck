from __future__ import annotations

from sficheck.models import Entry, Finding, Package, Ring, Status


def test_lower_rings_sort_first() -> None:
    assert sorted([Ring.USER, Ring.ME, Ring.KERNEL, Ring.FIRMWARE, Ring.HYPERVISOR]) == [
        Ring.ME,
        Ring.FIRMWARE,
        Ring.HYPERVISOR,
        Ring.KERNEL,
        Ring.USER,
    ]


def test_finding_from_entry_carries_ring() -> None:
    package = Package("vanguard", "windows")
    entry = Entry("vanguard", Status.NONFREE, ring=Ring.KERNEL)
    assert Finding.from_entry(package, entry).ring is Ring.KERNEL
    assert Finding.from_entry(package, Entry("calendar", Status.NONFREE)).ring is None
