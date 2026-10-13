from __future__ import annotations

import json
from pathlib import Path

import pytest

from sficheck.classify import Classifier
from sficheck.models import Antifeature, Finding, Status
from sficheck.sources.base import Context
from sficheck.sources.browser import Browser
from tests.conftest import StubFetcher


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake home folder; the Windows and XDG locations point inside it too."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    return tmp_path


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def firefox_profile(home: Path, name: str = "abc.default") -> Path:
    profile = home / ".mozilla" / "firefox" / name
    addons = [
        {"id": "uBlock0@raymondhill.net", "type": "extension", "location": "app-profile", "version": "1.75.0",
         "defaultLocale": {"name": "uBlock Origin"}},
        {"id": "formautofill@mozilla.org", "type": "extension", "location": "app-builtin-addons", "version": "1.0"},
        {"id": "en-US@dictionaries.addons.mozilla.org", "type": "dictionary", "location": "app-profile"},
    ]  # fmt: skip
    write(profile / "extensions.json", {"addons": addons})
    return profile


def scan(fetcher: StubFetcher, ctx: Context, online: bool = False) -> dict[str, Finding]:
    source = Browser(ctx)
    return {f.package.name: f for f in Classifier(fetcher=fetcher, online=online).run(source, list(source.packages()))}


def test_firefox_keeps_only_user_installed_extensions(home: Path, fetcher: StubFetcher, ctx: Context) -> None:
    firefox_profile(home)
    found = scan(fetcher, ctx)
    assert list(found) == ["uBlock Origin"]
    assert found["uBlock Origin"].package.extra == {"id": "uBlock0@raymondhill.net", "browser": "firefox"}
    assert found["uBlock Origin"].status is Status.UNKNOWN  # no license without the online lookup
    assert not Browser.default_enabled


def test_chromium_names_come_from_the_default_locale(home: Path, fetcher: StubFetcher, ctx: Context) -> None:
    ext = home / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Extensions" / "abcdefgh"
    write(ext / "1.0_0" / "manifest.json", {"name": "old", "version": "1.0"})
    write(ext / "2.0_0" / "manifest.json", {"name": "__MSG_appName__", "version": "2.0", "default_locale": "fr"})
    write(ext / "2.0_0" / "_locales" / "fr" / "messages.json", {"APPNAME": {"message": "Bloqueur"}})
    found = scan(fetcher, ctx)
    assert found["Bloqueur"].package.version == "2.0"  # the newest version folder wins
    assert found["Bloqueur"].package.extra == {"id": "abcdefgh", "browser": "chrome"}


def test_widevine_is_nonfree_drm_and_reported_once(home: Path, fetcher: StubFetcher, ctx: Context) -> None:
    (firefox_profile(home) / "gmp-widevinecdm" / "4.10.2830.0").mkdir(parents=True)
    (firefox_profile(home, "other.default") / "gmp-widevinecdm" / "4.10.2830.0").mkdir(parents=True)
    (home / ".config" / "chromium" / "WidevineCdm" / "4.10.2891.0").mkdir(parents=True)
    packages = list(Browser(ctx).packages())
    assert [p.name for p in packages] == ["uBlock Origin", "widevine"]  # one extension, one module
    widevine = scan(fetcher, ctx)["widevine"]
    assert widevine.status is Status.NONFREE and widevine.antifeatures == (Antifeature.DRM,)
    assert widevine.reference


def test_online_lookup_only_asks_amo_about_firefox(home: Path, tmp_path: Path, ctx: Context) -> None:
    firefox_profile(home)
    write(home / ".config" / "chromium" / "Default" / "Extensions" / "xyz" / "1_0" / "manifest.json", {"name": "C"})
    amo = {"current_version": {"license": {"slug": "GPL-3.0-only", "is_custom": False}}}
    fetcher = StubFetcher(tmp_path / "cache", {"addons.mozilla.org/api/v5/addons/addon/uBlock0": json.dumps(amo)})
    found = scan(fetcher, Context(fetcher=fetcher), online=True)
    assert found["uBlock Origin"].status is Status.FREE and found["uBlock Origin"].reason == "online:amo"
    assert found["C"].status is Status.UNKNOWN and found["C"].reason == "no license information"


def test_custom_amo_licenses_stay_unknown(home: Path, tmp_path: Path) -> None:
    firefox_profile(home)
    amo = {"current_version": {"license": {"slug": None, "is_custom": True}}}
    fetcher = StubFetcher(tmp_path / "cache", {"addons.mozilla.org": json.dumps(amo)})
    assert scan(fetcher, Context(fetcher=fetcher), online=True)["uBlock Origin"].status is Status.UNKNOWN


def test_not_available_without_profiles(home: Path, ctx: Context) -> None:
    assert not Browser(ctx).available()
    firefox_profile(home)
    assert Browser(ctx).available()
