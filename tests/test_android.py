from __future__ import annotations

import json
from pathlib import Path

import pytest

from sficheck.classify import Classifier
from sficheck.models import Antifeature, Finding, Status
from sficheck.sources.android import FDROID_INDEX, Android, fdroid_summary
from sficheck.sources.base import Context
from tests.conftest import FakeRun, StubFetcher

FIXTURES = Path(__file__).parent / "fixtures" / "android"


def version(code: int, *antifeatures: str) -> dict[str, object]:
    return {"manifest": {"versionCode": code}, "antiFeatures": {a: {"en-US": "why"} for a in antifeatures}}


INDEX = {
    "repo": {"name": "F-Droid"},
    "packages": {
        "org.fdroid.fdroid": {"metadata": {"license": "GPL-3.0-or-later"}, "versions": {"a": version(1)}},
        # Anti-features come from the newest version only.
        "org.schabi.newpipe": {
            "metadata": {"license": "GPL-3.0-or-later"},
            "versions": {"old": version(1, "Ads"), "new": version(1003, "NonFreeNet")},
        },
        "org.mozilla.fennec_fdroid": {"metadata": {"license": "MPL-2.0"}, "versions": {"b": version(2, "Tracking")}},
    },
}


def test_fdroid_summary_keeps_the_newest_versions_antifeatures() -> None:
    summary = json.loads(fdroid_summary(json.dumps(INDEX)))
    assert summary["org.schabi.newpipe"] == ["GPL-3.0-or-later", ["NonFreeNet"]]
    assert summary["org.fdroid.fdroid"] == ["GPL-3.0-or-later", []]


@pytest.fixture
def phone(fake_run: FakeRun, fetcher: StubFetcher) -> dict[str, Finding]:
    fake_run({"adb shell pm list packages": (FIXTURES / "pm_list_packages.txt").read_text(encoding="utf-8")})
    fetcher.bodies[FDROID_INDEX] = json.dumps(INDEX)
    fetcher.offline = False  # let memo build the summary from the stubbed index
    source = Android(Context(fetcher=fetcher))
    return {f.package.name: f for f in Classifier(fetcher=fetcher).run(source, list(source.packages()))}


def test_fdroid_apps_are_free_and_carry_their_antifeatures(phone: dict[str, Finding]) -> None:
    fdroid = phone["org.fdroid.fdroid"]
    assert fdroid.status is Status.FREE and fdroid.reason == "f-droid" and fdroid.description == "GPL-3.0-or-later"
    assert fdroid.reference == "https://f-droid.org/packages/org.fdroid.fdroid/"
    assert fdroid.package.version == "1020050" and fdroid.package.extra == {"installer": "null"}
    newpipe = phone["org.schabi.newpipe"]
    assert newpipe.status is Status.USES_NONFREE and newpipe.antifeatures == (Antifeature.NONFREE_NET,)
    fennec = phone["org.mozilla.fennec_fdroid"]
    assert fennec.status is Status.FREE and fennec.antifeatures == (Antifeature.TRACKING,)
    assert "installed from Google Play" in fennec.description


def test_other_apps_use_the_curated_list_or_stay_unknown(phone: dict[str, Finding]) -> None:
    gms = phone["com.google.android.gms"]
    assert gms.status is Status.NONFREE and gms.reason == "bundled:android"
    assert gms.package.extra == {"installer": "preinstalled"}
    assert phone["com.whatsapp"].status is Status.UNKNOWN


def test_without_the_index_only_the_curated_list_applies(fake_run: FakeRun, fetcher: StubFetcher) -> None:
    fake_run({"adb shell pm list packages": (FIXTURES / "pm_list_packages.txt").read_text(encoding="utf-8")})
    source = Android(Context(fetcher=fetcher))
    found = {f.package.name: f for f in Classifier(fetcher=fetcher).run(source, list(source.packages()))}
    assert found["org.fdroid.fdroid"].status is Status.UNKNOWN
    assert found["com.google.android.gms"].status is Status.NONFREE


@pytest.mark.parametrize(
    ("devices", "serial", "available"),
    [
        ("List of devices attached\n\n", "", False),
        ("List of devices attached\nR58M123\tdevice\n\n", "", True),
        ("List of devices attached\nR58M123\tunauthorized\n\n", "", False),  # the phone hasn't allowed debugging
        ("List of devices attached\nR58M123\tdevice\nemulator-5554\tdevice\n", "", False),
        ("List of devices attached\nR58M123\tdevice\nemulator-5554\tdevice\n", "R58M123", True),
    ],
)
def test_available_needs_one_authorized_device(
    devices: str, serial: str, available: bool, fake_run: FakeRun, ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_run({"adb devices": devices})
    monkeypatch.setenv("ANDROID_SERIAL", serial)
    assert Android(ctx).available() is available
    assert not Android.default_enabled
