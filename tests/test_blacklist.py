from __future__ import annotations

import json
from pathlib import Path

import pytest

from sficheck.blacklist import (
    Blacklist,
    bundled_names,
    load_bundled,
    load_user,
    parse_parabola,
    parse_parabola_line,
)
from sficheck.models import Entry, Ring, Status
from sficheck.net import Fetcher

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def parsed() -> dict[str, Entry]:
    text = (FIXTURES / "blacklist_sample.txt").read_text(encoding="utf-8")
    return {e.name: e for e in parse_parabola(text)}


def test_ref_and_id_are_not_alternatives(parsed: dict[str, Entry]) -> None:
    # The old parser reported "winetricks-libre,parabola,366" as alternatives.
    entry = parsed["winetricks"]
    assert entry.alternatives == ("winetricks-libre",)
    assert entry.status is Status.USES_NONFREE
    assert entry.reference == "https://labs.parabola.nu/issues/366"
    assert entry.description == "recommends and installs nonfree software"


def test_fixme_tags_with_colons_are_kept_out_of_description(parsed: dict[str, Entry]) -> None:
    entry = parsed["archlinux-appstream-data"]
    assert entry.status is Status.USES_NONFREE
    assert entry.description == "promotes nonfree packages and Arch repositories"


def test_extra_colon_before_tags(parsed: dict[str, Entry]) -> None:
    entry = parsed["discord"]
    assert entry.status is Status.NONFREE
    assert entry.description.startswith("No source code available")


def test_colon_after_tags(parsed: dict[str, Entry]) -> None:
    assert parsed["archinstall"].description == "archlinux CLI installer"


def test_same_name_replacement_means_parabola_build(parsed: dict[str, Entry]) -> None:
    assert parsed["abiword"].alternatives == ("abiword (Parabola build)",)
    assert parsed["firefox"].alternatives == ("iceweasel",)
    assert parsed["unrar"].alternatives == ()


def test_non_freedom_tags_are_skipped(parsed: dict[str, Entry]) -> None:
    assert "acpi_call" not in parsed  # [technical]
    assert "archey3" not in parsed  # [branding]


def test_untagged_lines_use_default_status() -> None:
    entry = parse_parabola_line("acroread::::", default_status=Status.NONFREE)
    assert entry is not None and entry.status is Status.NONFREE
    privacy = parse_parabola_line("bti:bti::: supports Twitter service", default_status=Status.USES_NONFREE)
    assert privacy is not None and privacy.status is Status.USES_NONFREE
    assert privacy.description == "supports Twitter service"


@pytest.mark.parametrize("line", ["", "   ", "# comment"])
def test_blank_and_comment_lines(line: str) -> None:
    assert parse_parabola_line(line) is None


def test_lookup_exact_then_pattern() -> None:
    bl = Blacklist()
    bl.add(Entry("Foo", Status.NONFREE))
    bl.add(Entry("bar-family", Status.SEMIFREE), pattern=r"^bar-")
    assert bl.lookup("foo") is not None  # case-insensitive
    hit = bl.lookup("bar-baz")
    assert hit is not None and hit.status is Status.SEMIFREE
    assert bl.lookup("qux") is None


def test_json_patterns_keep_file_order_and_newer_lists_win() -> None:
    bl = Blacklist()
    bl.load_json({"entries": [{"name": "general", "pattern": "^Micro", "status": "nonfree"}]}, "old")
    bl.load_json(
        {
            "entries": [
                {"name": "specific", "pattern": "^Microsoft PowerToys", "status": "free"},
                {"name": "catch-all", "pattern": "^Microsoft", "status": "semifree"},
            ]
        },
        "new",
    )
    assert [e.name for _, e in bl.patterns] == ["specific", "catch-all", "general"]
    hit = bl.lookup("Microsoft PowerToys")
    assert hit is not None and hit.status is Status.FREE


def test_json_ring_is_optional_and_validated() -> None:
    bl = Blacklist()
    bl.load_json({"entries": [{"name": "vgk", "ring": 0}, {"name": "calendar"}]}, "test")
    assert bl.by_name["vgk"].ring is Ring.KERNEL
    assert bl.by_name["calendar"].ring is None
    with pytest.raises(ValueError):
        Blacklist().load_json({"entries": [{"name": "bad", "ring": 2}]}, "test")


def test_kernel_anticheat_is_ring_zero() -> None:
    hit = load_bundled("windows").lookup("Riot Vanguard")
    assert hit is not None and hit.status is Status.NONFREE and hit.ring is Ring.KERNEL


def test_kernel_list_names_anticheat_and_free_drivers() -> None:
    drivers = load_bundled("kernel")
    vgk, tap = drivers.lookup("vgk"), drivers.lookup("tap0901")
    assert vgk is not None and vgk.status is Status.NONFREE and vgk.ring is Ring.KERNEL
    assert tap is not None and tap.status is Status.FREE


def test_hypervisor_list_rings_the_nonfree_ones() -> None:
    hypervisors = load_bundled("hypervisors")
    hyperv, kvm = hypervisors.lookup("hyper-v"), hypervisors.lookup("kvm")
    assert hyperv is not None and hyperv.status is Status.NONFREE and hyperv.ring is Ring.HYPERVISOR
    assert kvm is not None and kvm.status is Status.FREE


def test_firmware_list_puts_the_me_below_the_bios() -> None:
    firmware = load_bundled("firmware")
    me, coreboot, seabios = firmware.lookup("intel-me"), firmware.lookup("coreboot"), firmware.lookup("SeaBIOS")
    assert me is not None and me.status is Status.NONFREE and me.ring is Ring.ME
    assert coreboot is not None and coreboot.status is Status.USES_NONFREE and coreboot.ring is Ring.FIRMWARE
    assert seabios is not None and seabios.status is Status.FREE


def test_merged_overrides() -> None:
    a, b = Blacklist(), Blacklist()
    a.add(Entry("x", Status.NONFREE))
    b.add(Entry("x", Status.FREE))
    merged = a.merged(b)
    hit = merged.lookup("x")
    assert hit is not None and hit.status is Status.FREE


def test_every_bundled_list_loads() -> None:
    names = bundled_names()
    assert {"common", "debian", "windows", "windows-packages", "lang"} <= set(names)
    bl = load_bundled(*names)
    assert len(bl) > 200
    assert all(e.status in Status for e in bl.by_name.values())


@pytest.mark.parametrize("name", bundled_names())
def test_every_nonfree_curated_entry_cites_a_source(name: str) -> None:
    bl = load_bundled(name)
    entries = [*bl.by_name.values(), *(entry for _, entry in bl.patterns)]
    unsourced = [e.name for e in entries if e.status is not Status.FREE and not e.reference]
    assert unsourced == [], f"{name}.json entries need a 'reference': {unsourced}"


def test_load_user_json_and_text(tmp_path: Path) -> None:
    fetcher = Fetcher(root=tmp_path / "cache", offline=True)
    js = tmp_path / "mine.json"
    js.write_text(json.dumps({"entries": [{"name": "evil", "status": "nonfree", "alternatives": ["good"]}]}))
    hit = load_user(str(js), fetcher).lookup("evil")
    assert hit is not None and hit.alternatives == ("good",)
    txt = tmp_path / "mine.txt"
    txt.write_text("other:libre-other:::[semifree] partly bad\n")
    hit = load_user(str(txt), fetcher).lookup("other")
    assert hit is not None and hit.status is Status.SEMIFREE and hit.origin == "user:mine.txt"


def test_list_files_reject_typos_with_the_field_path() -> None:
    with pytest.raises(ValueError, match=r"unknown field `stauts` - at `\$\.entries\[0\]`"):
        Blacklist().load_json({"entries": [{"name": "x", "stauts": "free"}]}, "mine.json")
    with pytest.raises(ValueError, match=r"mine.json: JSON is malformed"):
        Blacklist().load_json('{"entries": [}', "mine.json")
