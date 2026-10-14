"""Readers for package metadata files shared by several sources."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from email.parser import HeaderParser
from pathlib import Path
from typing import Any

from sficheck import licenses
from sficheck.models import Status

_LICENSE_URL_ID = re.compile(
    r"(?:opensource\.org/licenses?|spdx\.org/licenses|choosealicense\.com/licenses)/([A-Za-z0-9.+-]+?)(?:\.html|\.php|/)?$",
    re.IGNORECASE,
)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def license_from_url(url: str | None) -> str | None:
    """Turn https://opensource.org/licenses/MIT style URLs into an SPDX-ish id."""
    if not url:
        return None
    match = _LICENSE_URL_ID.search(url.strip())
    return match.group(1) if match else None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def read_xml_fields(path: Path) -> dict[str, str]:
    """Flatten an XML file into {local tag name: text} (first occurrence wins)."""
    try:
        root = ET.parse(path).getroot()  # noqa: S314 -- expat resolves no external entities and caps entity expansion (2.4.1+)
    except (OSError, ET.ParseError):
        return {}
    fields: dict[str, str] = {}
    for el in root.iter():
        if el.text and el.text.strip():
            fields.setdefault(_local(el.tag), el.text.strip())
    return fields


def nuspec(path: Path) -> tuple[str, str, str | None]:
    """(id, version, license) from a NuGet/Chocolatey .nuspec."""
    f = read_xml_fields(path)
    return f.get("id", path.stem), f.get("version", ""), f.get("license") or license_from_url(f.get("licenseUrl"))


def pom_licenses(path: Path) -> str | None:
    """License names from a Maven POM's <licenses> block."""
    try:
        root = ET.parse(path).getroot()  # noqa: S314 -- expat resolves no external entities and caps entity expansion (2.4.1+)
    except (OSError, ET.ParseError):
        return None
    names = [
        (child.text or "").strip()
        for lic in root.iter()
        if _local(lic.tag) == "license"
        for child in lic
        if _local(child.tag) == "name"
    ]
    names = [n for n in names if n]
    return " OR ".join(f"({n})" for n in names) if names else None


def package_json_license(data: Any) -> str | None:
    """npm's license field: "MIT", {"type": "MIT"}, or legacy "licenses": [{"type": ...}]."""
    if not isinstance(data, dict):
        return None
    lic = data.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    if isinstance(lic, str) and lic:
        return lic
    legacy = data.get("licenses")
    if isinstance(legacy, list):
        types = [x.get("type") if isinstance(x, dict) else x for x in legacy]
        types = [t for t in types if isinstance(t, str)]
        return " OR ".join(f"({t})" for t in types) or None
    return None


def node_modules(root: Path) -> list[tuple[str, str, str | None, Path]]:
    """Top-level packages in a node_modules dir: (name, version, license, dir)."""
    result: list[tuple[str, str, str | None, Path]] = []
    if not root.is_dir():
        return result
    dirs: list[Path] = []
    for child in root.iterdir():
        if child.name.startswith("@") and child.is_dir():
            dirs.extend(child.iterdir())
        elif not child.name.startswith("."):
            dirs.append(child)
    for pkg_dir in dirs:
        data = read_json(pkg_dir / "package.json")
        if isinstance(data, dict) and data.get("name"):
            lic = package_json_license(data) or licenses.sniff_dir(pkg_dir)
            result.append((data["name"], str(data.get("version", "")), lic, pkg_dir))
    return result


def dist_info(path: Path) -> tuple[str, str, str | None] | None:
    """(name, version, license) from a Python ``*.dist-info`` / ``*.egg-info`` directory."""
    meta_file = path / "METADATA" if (path / "METADATA").is_file() else path / "PKG-INFO"
    try:
        msg = HeaderParser().parsestr(meta_file.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    name = msg.get("Name")
    if not name:
        return None
    raw = (msg.get("License") or "").strip()
    classifiers = [c.rsplit("::", 1)[-1].strip() for c in msg.get_all("Classifier", []) if c.startswith("License ::")]
    candidates = [
        msg.get("License-Expression"),
        # Some projects paste the whole license text into this field.
        raw if len(raw) < 100 and "\n" not in raw else licenses.sniff_text(raw),
        " OR ".join(f"({c})" for c in classifiers),
        licenses.sniff_dir(path),
        licenses.sniff_dir(path / "licenses"),
    ]
    present = [c for c in candidates if c]
    # Prefer the first field we can classify: "Dual License" says nothing, the classifiers might.
    lic = next((c for c in present if licenses.classify(c) is not Status.UNKNOWN), present[0] if present else None)
    return name, msg.get("Version", ""), lic


def site_packages_dists(site: Path) -> list[tuple[str, str, str | None]]:
    found = []
    for info in [*site.glob("*.dist-info"), *site.glob("*.egg-info")]:
        if info.is_dir() and (dist := dist_info(info)):
            found.append(dist)
    return found


def cargo_license(path: Path) -> str | None:
    """``package.license`` from a Cargo.toml."""
    try:
        with path.open("rb") as fh:
            manifest = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    lic = manifest.get("package", {}).get("license")
    return lic if isinstance(lic, str) else None
