"""Online license lookups for packages whose local metadata has no license (opt-in)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from sficheck.net import Fetcher

DEPS_DEV = "https://api.deps.dev/v3/systems/{system}/packages/{name}"
DEPS_DEV_SYSTEMS = {
    "pypi": "PYPI",
    "npm": "NPM",
    "cargo": "CARGO",
    "go": "GO",
    "maven": "MAVEN",
    "nuget": "NUGET",
    "rubygems": "RUBYGEMS",
}
# pub.dev score tags that describe approval rather than a specific license.
_PUB_META_TAGS = {"license:osi-approved", "license:fsf-libre", "license:unknown"}


def _join(lics: list[Any]) -> str | None:
    names = [str(x) for x in lics if x]
    return " OR ".join(f"({n})" for n in names) or None


def _deps_dev(fetcher: Fetcher, system: str, name: str, version: str) -> str | None:
    base = DEPS_DEV.format(system=DEPS_DEV_SYSTEMS[system], name=quote(name, safe=""))
    if version:
        data = fetcher.get_json(f"{base}/versions/{quote(version, safe='')}")
        if isinstance(data, dict):
            return _join(data.get("licenses", []))
    # No version, or one the registry never saw (Go pseudo-versions, local builds): use the default release.
    info = fetcher.get_json(base)
    versions = info.get("versions", []) if isinstance(info, dict) else []
    default = next((v for v in versions if v.get("isDefault")), versions[-1] if versions else None)
    if not default:
        return None
    data = fetcher.get_json(f"{base}/versions/{quote(default['versionKey']['version'], safe='')}")
    return _join(data.get("licenses", [])) if isinstance(data, dict) else None


def _packagist(fetcher: Fetcher, name: str, version: str) -> str | None:
    data = fetcher.get_json(f"https://repo.packagist.org/p2/{name}.json")
    releases = data.get("packages", {}).get(name, []) if isinstance(data, dict) else []
    release = next((r for r in releases if r.get("version") == version), releases[0] if releases else None)
    return _join(release.get("license", [])) if release else None


def _pub(fetcher: Fetcher, name: str, version: str) -> str | None:
    data = fetcher.get_json(f"https://pub.dev/api/packages/{quote(name)}/score")
    tags = data.get("tags", []) if isinstance(data, dict) else []
    found = [t.removeprefix("license:") for t in tags if t.startswith("license:") and t not in _PUB_META_TAGS]
    return _join(found)


def _hex(fetcher: Fetcher, name: str, version: str) -> str | None:
    data = fetcher.get_json(f"https://hex.pm/api/packages/{quote(name)}")
    return _join(data.get("meta", {}).get("licenses", [])) if isinstance(data, dict) else None


def _metacpan(fetcher: Fetcher, name: str, version: str) -> str | None:
    data = fetcher.get_json(f"https://fastapi.metacpan.org/v1/release/{quote(name.replace('::', '-'))}")
    return _join(data.get("license", [])) if isinstance(data, dict) else None


def _github(fetcher: Fetcher, name: str, version: str) -> str | None:
    repo = name.removeprefix("https://").removeprefix("github.com/").removesuffix(".git")
    data = fetcher.get_json(f"https://api.github.com/repos/{repo}/license")
    spdx = data.get("license", {}).get("spdx_id") if isinstance(data, dict) else None
    return spdx if spdx and spdx != "NOASSERTION" else None


_LOOKUPS: dict[str, Callable[[Fetcher, str, str], str | None]] = {
    "packagist": _packagist,
    "pub": _pub,
    "hex": _hex,
    "metacpan": _metacpan,
    "github": _github,
}


def lookup_license(fetcher: Fetcher, registry: str, name: str, version: str) -> str | None:
    if registry in DEPS_DEV_SYSTEMS:
        return _deps_dev(fetcher, registry, name, version)
    lookup = _LOOKUPS.get(registry)
    return lookup(fetcher, name, version) if lookup else None
