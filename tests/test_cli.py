from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from pathlib import Path

import msgspec
import pytest

from sficheck import cli, render
from sficheck.models import Antifeature, Finding, Package, Ring, SourceReport, Status
from sficheck.sources.base import Source

SCHEMA = Path(__file__).resolve().parent.parent / "docs" / "output.schema.json"


class FakeSource(Source):
    name = "fake"
    kind = "lang"
    description = "test source"

    def available(self) -> bool:
        return True

    def packages(self) -> Iterable[Package]:
        yield self.pkg("good", "1.0", "MIT")
        yield self.pkg("evil|pipe", "2.0", "Proprietary")
        yield self.pkg("half", "3.0", "MIT AND Proprietary")
        yield self.pkg("mystery", "4.0")


class BrokenSource(FakeSource):
    name = "broken"

    def packages(self) -> Iterable[Package]:
        raise RuntimeError("boom")


class FakeKernel(FakeSource):
    name = "kernel"
    default_enabled = False
    default_ring = Ring.KERNEL

    def packages(self) -> Iterable[Package]:
        yield self.pkg("vgk", "1.0", "Proprietary")


class FakeHypervisors(FakeKernel):
    name = "hypervisors"
    default_ring = Ring.HYPERVISOR

    def packages(self) -> Iterable[Package]:
        yield self.pkg("hyper-v", "", "Proprietary")


class FakeFirmware(FakeKernel):
    name = "firmware"
    default_ring = Ring.ME

    def packages(self) -> Iterable[Package]:
        yield self.pkg("intel-me", "", "Proprietary")


class FakeHardware(FakeKernel):
    name = "hardware"

    def packages(self) -> Iterable[Package]:
        yield self.pkg("Wi-Fi 6 AX201", "", "Proprietary")


class FakeBrowser(FakeSource):
    name = "browser"
    default_enabled = False

    def packages(self) -> Iterable[Package]:
        yield self.pkg("widevine", "", "Proprietary")


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        cli,
        "ALL_SOURCES",
        (FakeSource, BrokenSource, FakeKernel, FakeHypervisors, FakeFirmware, FakeHardware, FakeBrowser),
    )
    monkeypatch.setattr(
        cli,
        "BY_NAME",
        {
            "fake": FakeSource,
            "broken": BrokenSource,
            "kernel": FakeKernel,
            "hypervisors": FakeHypervisors,
            "firmware": FakeFirmware,
            "hardware": FakeHardware,
            "browser": FakeBrowser,
        },
    )
    monkeypatch.setattr(cli, "config_path", lambda: tmp_path / "config.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))


def run_json(capsys: pytest.CaptureFixture[str], *args: str) -> dict[str, object]:
    assert cli.main(["-q", "--format", "json", *args]) == 0
    data: dict[str, object] = json.loads(capsys.readouterr().out)
    return data


def names(doc: dict[str, object]) -> list[str]:
    return [f["name"] for f in doc["findings"]]  # type: ignore[attr-defined]


def test_default_shows_only_nonfree(capsys: pytest.CaptureFixture[str]) -> None:
    doc = run_json(capsys, "--sources", "fake")
    assert names(doc) == ["evil|pipe"]
    summary = doc["summary"]
    assert isinstance(summary, dict)
    assert summary["total"] == 4 and summary["proprietary"] == 2 and summary["unknown"] == 1
    assert summary["freedom_index"] == pytest.approx(100 / 3)


def test_full_unknown_and_all(capsys: pytest.CaptureFixture[str]) -> None:
    assert sorted(names(run_json(capsys, "--sources", "fake", "-f"))) == ["evil|pipe", "half"]
    assert "mystery" in names(run_json(capsys, "--sources", "fake", "--show-unknown"))
    assert len(names(run_json(capsys, "--sources", "fake", "--all"))) == 4


def test_unknown_as_nonfree_changes_index(capsys: pytest.CaptureFixture[str]) -> None:
    summary = run_json(capsys, "--sources", "fake", "--unknown-as-nonfree")["summary"]
    assert isinstance(summary, dict) and summary["freedom_index"] == pytest.approx(25)


def test_sort_and_reverse(capsys: pytest.CaptureFixture[str]) -> None:
    assert names(run_json(capsys, "--sources", "fake", "--all", "--sort", "name")) == [
        "evil|pipe",
        "good",
        "half",
        "mystery",
    ]
    assert names(run_json(capsys, "--sources", "fake", "--all", "--sort", "name", "-r"))[0] == "mystery"


def test_broken_source_is_reported_not_fatal(capsys: pytest.CaptureFixture[str]) -> None:
    summary = run_json(capsys)["summary"]
    assert isinstance(summary, dict)
    errors = {s["source"]: s["error"] for s in summary["sources"]}
    assert errors == {
        "fake": None,
        "broken": "boom",
        "kernel": None,
        "hypervisors": None,
        "firmware": None,
        "hardware": None,
    }


def test_ignore_and_user_blacklist(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    custom = tmp_path / "mine.txt"
    custom.write_text("good::::[nonfree] I disagree\n")
    found = names(run_json(capsys, "--sources", "fake", "--blacklist", str(custom), "--ignore", "evil|pipe"))
    assert found == ["good"]


def test_max_ring_and_ring_sort(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    custom = tmp_path / "mine.json"
    custom.write_text(json.dumps({"entries": [{"name": "half", "status": "nonfree", "ring": 0}]}))
    base = ("--sources", "fake", "--blacklist", str(custom))
    assert names(run_json(capsys, *base, "-f", "--max-ring", "0")) == ["half"]
    assert names(run_json(capsys, *base, "-f", "--max-ring", "3")) == ["evil|pipe", "half"]
    assert names(run_json(capsys, *base, "--all", "--sort", "ring")) == ["half", "evil|pipe", "good", "mystery"]


def test_default_scans_every_layer(capsys: pytest.CaptureFixture[str]) -> None:
    found = names(run_json(capsys, "--skip", "broken", "--sort", "ring"))
    assert found == ["intel-me", "hyper-v", "vgk", "Wi-Fi 6 AX201", "evil|pipe"]


def test_layer_flags_scan_only_those_layers(capsys: pytest.CaptureFixture[str]) -> None:
    assert names(run_json(capsys, "--firmware")) == ["intel-me"]
    assert names(run_json(capsys, "--kernel", "--hypervisors", "--sort", "ring")) == ["hyper-v", "vgk"]
    assert names(run_json(capsys, "--software", "--skip", "broken")) == ["evil|pipe"]
    assert names(run_json(capsys, "--software", "--kernel", "--skip", "broken", "--sort", "ring")) == [
        "vgk",
        "evil|pipe",
    ]


def test_browser_is_scanned_only_when_asked_for(capsys: pytest.CaptureFixture[str]) -> None:
    assert "widevine" not in names(run_json(capsys, "--skip", "broken"))
    assert names(run_json(capsys, "--browser")) == ["widevine"]
    assert names(run_json(capsys, "--browser", "--firmware", "--sort", "ring")) == ["intel-me", "widevine"]
    cli.main(["--list-sources"])
    assert "(opt-in)" in next(line for line in capsys.readouterr().out.splitlines() if line.startswith("browser"))


def test_kind_narrows_the_software_layer(capsys: pytest.CaptureFixture[str]) -> None:
    assert names(run_json(capsys, "--kind", "lang", "--skip", "broken")) == ["evil|pipe"]
    assert names(run_json(capsys, "--kind", "lang", "--firmware", "--skip", "broken", "--sort", "ring")) == [
        "intel-me",
        "evil|pipe",
    ]
    assert cli.main(["-q", "--kind", "system"]) == 2  # no system package manager, and no layer flag


def test_kernel_flag_adds_to_named_sources(capsys: pytest.CaptureFixture[str]) -> None:
    assert names(run_json(capsys, "--sources", "fake", "--kernel", "--max-ring", "0")) == ["vgk"]


def test_layer_flags_combine(capsys: pytest.CaptureFixture[str]) -> None:
    assert "hyper-v" not in names(run_json(capsys, "--skip", "broken", "--kernel"))
    found = names(
        run_json(capsys, "--sources", "fake", "--kernel", "--hypervisors", "--max-ring", "0", "--sort", "ring")
    )
    assert found == ["hyper-v", "vgk"]
    assert names(run_json(capsys, "--sources", "fake", "--firmware", "--max-ring", "0")) == ["intel-me"]
    assert names(run_json(capsys, "--sources", "fake", "--hardware", "--max-ring", "0")) == ["Wi-Fi 6 AX201"]


def test_json_output_is_versioned_and_matches_its_types(capsys: pytest.CaptureFixture[str]) -> None:
    doc = run_json(capsys, "--skip", "broken", "--all")
    assert next(iter(doc)) == "schema_version" and doc["schema_version"] == render.SCHEMA_VERSION
    msgspec.json.decode(json.dumps(doc), type=render.Report)  # raises if a field is missing or mistyped


def test_published_schema_is_current() -> None:
    assert json.loads(SCHEMA.read_text(encoding="utf-8")) == render.output_schema(), "run `make schema`"


def test_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["-q", "--sources", "fake", "--exit-code", "--format", "csv"]) == 1
    assert cli.main(["-q", "--sources", "fake", "--format", "csv"]) == 0


def test_output_file_markdown(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out = tmp_path / "sub" / "report.md"
    assert cli.main(["-q", "--sources", "fake", "--format", "markdown", "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "evil\\|pipe" in text  # pipes escaped so the table survives
    assert capsys.readouterr().out == ""


def test_config_file_defaults(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(json.dumps({"sources": ["fake"], "full": True}))
    assert sorted(names(run_json(capsys))) == ["evil|pipe", "half"]


def test_unknown_source_is_an_error() -> None:
    with pytest.raises(SystemExit):
        cli.main(["--sources", "nope"])


def test_list_sources(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--list-sources"]) == 0
    out = capsys.readouterr().out
    assert "fake" in out and "available" in out


def test_csv_round_trip(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["-q", "--sources", "fake", "--all", "--format", "csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert {r["Name"]: r["Status"] for r in rows}["half"] == "semifree"


def test_table_fits_terminal_width() -> None:
    long = "x" * 300
    findings = [
        Finding(
            Package("averyveryverylongpackagename-" * 3, "fake", "1.0"),
            Status.NONFREE,
            description=long,
            alternatives=("alt " * 20,),
        )
    ]
    text = render.table(findings, render.Palette(False), max_width=100)
    assert max(len(line) for line in text.splitlines()) <= 100
    reports = [SourceReport("fake", "lang", findings)]
    assert "1 ABSOLUTELY PROPRIETARY" in render.summary_text(reports, render.Palette(False), False)


def test_table_color_keeps_alignment() -> None:
    findings = [Finding(Package("a", "fake"), Status.NONFREE), Finding(Package("b", "fake"), Status.FREE)]
    plain = render.table(findings, render.Palette(False), 200)
    colored = render.table(findings, render.Palette(True), 200)
    assert "\033[31m" in colored
    assert colored.replace("\033[31m", "").replace("\033[32m", "").replace("\033[0m", "") == plain


def test_ring_in_every_format() -> None:
    findings = [
        Finding(Package("microcode", "fake", "0"), Status.NONFREE, ring=Ring.ME),
        Finding(Package("vgk", "fake"), Status.NONFREE, ring=Ring.KERNEL),
        Finding(Package("bash", "fake"), Status.FREE),
    ]
    reports = [SourceReport("fake", "lang", findings)]
    plain = render.table(findings, render.Palette(False), 200)
    assert "-3 ME" in plain and "0 kernel" in plain
    colored = render.table(findings, render.Palette(True), 200)
    assert "\033[1;31m-3 ME" in colored  # below the kernel: bold red
    for code in ("\033[1;31m", "\033[31m", "\033[32m", "\033[0m"):
        colored = colored.replace(code, "")
    assert colored == plain
    summary = render.summary_text(reports, render.Palette(False), False)
    assert "By protection ring: -3 ME: 1, 0 kernel: 1" in summary
    doc = json.loads(render.as_json(findings, reports, False))
    assert [f["ring"] for f in doc["findings"]] == [-3, 0, None]
    assert doc["summary"]["by_ring"] == {"-3": 1, "0": 1}
    rows = list(csv.DictReader(io.StringIO(render.as_csv(findings))))
    assert [r["Ring"] for r in rows] == ["-3", "0", ""]
    assert "| -3 ME |" in render.markdown(findings, reports, False)


def test_antifeatures_in_every_format() -> None:
    tags = (Antifeature.TRACKING, Antifeature.DRM)
    findings = [
        Finding(Package("spyware", "fake"), Status.NONFREE, description="phones home", antifeatures=tags),
        Finding(Package("bash", "fake"), Status.FREE),
    ]
    reports = [SourceReport("fake", "lang", findings)]
    assert "phones home [tracking, drm]" in render.table(findings, render.Palette(False), 200)
    doc = json.loads(render.as_json(findings, reports, False))
    assert [f["antifeatures"] for f in doc["findings"]] == [["tracking", "drm"], []]
    rows = list(csv.DictReader(io.StringIO(render.as_csv(findings))))
    assert [r["Anti-features"] for r in rows] == ["tracking; drm", ""]
    md = render.markdown(findings, reports, False)
    assert "| phones home | tracking, drm |" in md  # its own column, not repeated in the description


def test_empty_sources_are_left_out_of_the_summaries() -> None:
    findings = [Finding(Package("vgk", "fake"), Status.NONFREE)]
    reports = [
        SourceReport("fake", "lang", findings),
        SourceReport("pnpm", "lang"),
        SourceReport("yarn", "lang", error="boom"),
    ]
    summary = render.summary_text(reports, render.Palette(False), False)
    assert "| fake" in summary and "| yarn" in summary and "pnpm" not in summary
    assert "across 2 sources" in summary
    md = render.markdown(findings, reports, False)
    assert "| fake |" in md and "| yarn |" in md and "pnpm" not in md
    assert "pnpm" in render.as_json(findings, reports, False)  # machine output keeps every source
