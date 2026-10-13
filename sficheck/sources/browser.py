"""Browser extensions and DRM modules, read from local profile folders (opt-in: --browser)."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from sficheck.models import Package
from sficheck.sources.base import Source

# Profile roots relative to the home folder (Linux, flatpak, snap, macOS). Missing ones are skipped.
FIREFOX_HOME_ROOTS = (
    ".mozilla/firefox",
    ".var/app/org.mozilla.firefox/.mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
    "Library/Application Support/Firefox/Profiles",
)
# Chromium-family "User Data" folders: (browser, Linux ~/.config path, macOS path, Windows %LOCALAPPDATA% path).
CHROMIUM_ROOTS = (
    ("chrome", "google-chrome", "Google/Chrome", "Google/Chrome/User Data"),
    ("chromium", "chromium", "Chromium", "Chromium/User Data"),
    ("brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser/User Data"),
    ("edge", "microsoft-edge", "Microsoft Edge", "Microsoft/Edge/User Data"),
    ("vivaldi", "vivaldi", "Vivaldi", "Vivaldi/User Data"),
)
_MSG = re.compile(r"^__MSG_(\w+)__$")


def _firefox_roots() -> list[Path]:
    home = Path.home()
    roots = [home / r for r in FIREFOX_HOME_ROOTS]
    roots.append(Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming") / "Mozilla" / "Firefox" / "Profiles")
    return roots


def _chromium_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
    support = home / "Library" / "Application Support"
    return [
        (browser, root)
        for browser, linux, mac, windows in CHROMIUM_ROOTS
        for root in (config / linux, support / mac, local / windows)
    ]


def _dirs(path: Path) -> list[Path]:
    try:
        return sorted(p for p in path.iterdir() if p.is_dir())
    except OSError:
        return []


def _load(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))  # Chromium manifests may start with a BOM
    except (OSError, ValueError):
        return None


def _firefox_extensions(profile: Path) -> Iterator[tuple[str, str, str]]:
    """(id, name, version) of the add-ons the user installed; built-ins, themes and dictionaries are skipped."""
    data = _load(profile / "extensions.json")
    addons = data.get("addons", []) if isinstance(data, dict) else []
    for addon in addons:
        if addon.get("type") == "extension" and addon.get("location") == "app-profile":
            name = (addon.get("defaultLocale") or {}).get("name") or addon["id"]
            yield addon["id"], name, addon.get("version", "")


def _chromium_name(manifest: dict[str, object], folder: Path) -> str:
    """The manifest name, with a ``__MSG_key__`` placeholder resolved from the default locale."""
    name = str(manifest.get("name", ""))
    match = _MSG.match(name)
    if not match:
        return name
    locale = str(manifest.get("default_locale", "en"))
    messages = _load(folder / "_locales" / locale / "messages.json")
    if isinstance(messages, dict):
        key = match.group(1).lower()
        for k, v in messages.items():
            if k.lower() == key and isinstance(v, dict):
                return str(v.get("message", name))
    return name


def _chromium_extensions(profile: Path) -> Iterator[tuple[str, str, str]]:
    for ext in _dirs(profile / "Extensions"):
        versions = _dirs(ext)
        if not versions:
            continue
        manifest = _load(versions[-1] / "manifest.json")
        if isinstance(manifest, dict):
            yield ext.name, _chromium_name(manifest, versions[-1]), str(manifest.get("version", ""))


def _latest(path: Path) -> str | None:
    """The newest version folder's name, or None when the module isn't there."""
    versions = _dirs(path)
    return versions[-1].name if versions else None


class Browser(Source):
    name = "browser"
    kind = "system"
    description = "Browser extensions and DRM modules (Firefox and Chromium-based browsers)"
    lists = ("browser",)
    registry = "amo"
    default_enabled = False

    def available(self) -> bool:
        return any(root.is_dir() for root in _firefox_roots()) or any(r.is_dir() for _, r in _chromium_roots())

    def lookup_name(self, package: Package) -> str | None:
        # Only addons.mozilla.org publishes licenses; Chrome Web Store doesn't.
        return package.extra.get("id") if package.extra.get("browser") == "firefox" else None

    def packages(self) -> Iterable[Package]:
        seen: set[str] = set()

        def once(key: str, package: Package) -> Iterator[Package]:
            if key not in seen:
                seen.add(key)
                yield package

        for root in _firefox_roots():
            for profile in _dirs(root):
                for ext_id, name, version in _firefox_extensions(profile):
                    yield from once(ext_id, self.pkg(name, version, id=ext_id, browser="firefox"))
                if cdm := _latest(profile / "gmp-widevinecdm"):
                    yield from once("widevine", self.pkg("widevine", cdm, browser="firefox"))
        for browser, root in _chromium_roots():
            for profile in _dirs(root):
                for ext_id, name, version in _chromium_extensions(profile):
                    yield from once(ext_id, self.pkg(name, version, id=ext_id, browser=browser))
            if cdm := _latest(root / "WidevineCdm"):
                yield from once("widevine", self.pkg("widevine", cdm, browser=browser))
