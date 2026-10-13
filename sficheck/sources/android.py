"""Apps on an Android phone connected over adb (opt-in: --android), checked against F-Droid."""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterable

import msgspec

from sficheck import proc
from sficheck.models import FDROID_ANTIFEATURES, Antifeature, Finding, Package, Status
from sficheck.sources.base import Context, Source

log = logging.getLogger(__name__)

FDROID_INDEX = "https://f-droid.org/repo/index-v2.json"
FDROID_PAGE = "https://f-droid.org/packages/{}/"
PLAY_STORE = "com.android.vending"
# "package:/data/app/~~x==/org.fdroid.fdroid-y==/base.apk=org.fdroid.fdroid versionCode:1020050 installer=null"
_LINE = re.compile(
    r"^package:(?:(?P<path>.*\.apk)=)?(?P<id>[\w.]+)\s+versionCode:(?P<code>\d+)(?:\s+installer=(?P<by>\S+))?"
)
# F-Droid ships only free software; these anti-features mean it leans on something that isn't.
_USES_NONFREE = {Antifeature.NONFREE_NET, Antifeature.NONFREE_DEP, Antifeature.NONFREE_ADD, Antifeature.TETHERED_NET}


class _Manifest(msgspec.Struct, rename="camel"):
    version_code: int = 0


class _Version(msgspec.Struct, rename="camel"):
    manifest: _Manifest = msgspec.field(default_factory=_Manifest)
    anti_features: dict[str, object] = {}


class _Metadata(msgspec.Struct):
    license: str = ""


class _App(msgspec.Struct):
    metadata: _Metadata = msgspec.field(default_factory=_Metadata)
    versions: dict[str, _Version] = {}


class _Index(msgspec.Struct):
    packages: dict[str, _App] = {}


def fdroid_summary(index_json: str) -> str:
    """Shrink F-Droid's index (tens of MB) to {app id: [license, anti-features of the newest version]}."""
    index = msgspec.json.decode(index_json, type=_Index)
    summary = {}
    for app_id, app in index.packages.items():
        newest = max(app.versions.values(), key=lambda v: v.manifest.version_code, default=_Version())
        summary[app_id] = [app.metadata.license, sorted(newest.anti_features)]
    return json.dumps(summary, separators=(",", ":"))


def _devices() -> list[str]:
    out = proc.run(["adb", "devices"]) or ""
    return [line.split("\t")[0] for line in out.splitlines()[1:] if line.endswith("\tdevice")]


class Android(Source):
    name = "android"
    kind = "device"  # another device: it gets its own index, outside the machine's
    description = "Apps on an Android phone connected over adb (checked against F-Droid)"
    lists = ("android",)
    default_enabled = False

    def __init__(self, ctx: Context) -> None:
        super().__init__(ctx)
        self._fdroid: dict[str, tuple[str, list[str]]] = {}  # app id -> (license, F-Droid anti-features)

    def available(self) -> bool:
        # With several devices connected, adb's own ANDROID_SERIAL says which one to use.
        devices = _devices()
        return len(devices) == 1 or (bool(devices) and bool(os.environ.get("ANDROID_SERIAL")))

    def _load_fdroid(self) -> None:
        def produce() -> str | None:
            body = self.ctx.fetcher.get(FDROID_INDEX)
            return fdroid_summary(body) if body else None

        text = self.ctx.fetcher.memo(f"fdroid-summary:{FDROID_INDEX}", produce)
        if text is None:
            log.warning("F-Droid's index is unavailable; Android apps will only be checked against the curated list")
        self._fdroid = msgspec.json.decode(text, type=dict[str, tuple[str, list[str]]]) if text else {}

    def packages(self) -> Iterable[Package]:
        self._load_fdroid()
        out = proc.run(["adb", "shell", "pm", "list", "packages", "-f", "-i", "--show-versioncode"]) or ""
        for line in out.splitlines():
            if match := _LINE.match(line.strip()):
                path, installer = match["path"] or "", match["by"] or "null"
                preinstalled = not path.startswith("/data/")
                yield self.pkg(
                    match["id"],
                    match["code"],
                    installer="preinstalled" if preinstalled and installer == "null" else installer,
                )

    def verdict(self, package: Package) -> Finding | None:
        found = self._fdroid.get(package.name)
        if found is None:
            return None
        license_, tags = found
        antifeatures = tuple(FDROID_ANTIFEATURES[t] for t in tags if t in FDROID_ANTIFEATURES)
        status = Status.FREE
        if Antifeature.NONFREE_ASSETS in antifeatures:
            status = Status.SEMIFREE
        elif _USES_NONFREE.intersection(antifeatures):
            status = Status.USES_NONFREE
        description = license_
        if package.extra.get("installer") == PLAY_STORE:
            description += " (installed from Google Play, whose build can differ from F-Droid's)"
        return Finding(
            package,
            status,
            reason="f-droid",
            description=description.strip(),
            reference=FDROID_PAGE.format(package.name),
            antifeatures=antifeatures,
        )
