"""Check the bundled curated lists.

Offline (default): every non-free entry must cite a ``reference``; patterns must compile.
--online: also check that each reference URL resolves, and that each alternative exists
in its ecosystem under a free license (Repology for distro package names, Flathub for
flatpak ids, winget-pkgs for winget ids). Set GITHUB_TOKEN to avoid GitHub rate limits.

Exit status is 1 when any problem is reported; Repology misses are only warnings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from absolutely_proprietary import licenses
from absolutely_proprietary.models import Status

LISTS = Path(__file__).resolve().parent.parent / "absolutely_proprietary" / "data" / "lists"
USER_AGENT = "absolutely-proprietary-list-checker/1.0 (+https://github.com/vmavromatis/absolutely-proprietary)"
FLATPAK_TLDS = {
    "com",
    "org",
    "io",
    "net",
    "im",
    "md",
    "us",
    "app",
    "dev",
    "de",
    "fr",
    "eu",
    "info",
    "page",
    "me",
    "xyz",
}
_ID = re.compile(r"^[A-Za-z0-9][\w+-]*(\.[\w+-]+)+$")


def fetch(url: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    """(HTTP status, parsed JSON or None). Network errors are status 0."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body)
            except ValueError:
                return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, None


def check_offline(path: Path, entries: list[dict[str, Any]]) -> list[str]:
    problems = []
    for e in entries:
        if Status(e.get("status", "nonfree")) is not Status.FREE and not e.get("reference"):
            problems.append(f"{path.name}: {e['name']}: no reference")
        if pattern := e.get("pattern"):
            try:
                re.compile(pattern)
            except re.error as exc:
                problems.append(f"{path.name}: {e['name']}: bad pattern ({exc})")
    return problems


def ecosystem(alt: str) -> str | None:
    """Guess where an alternative's name lives; None for free-text suggestions."""
    if "(" in alt or "/" in alt or " " in alt:
        return None
    if _ID.match(alt):
        parts = alt.split(".")
        return "flatpak" if len(parts) >= 3 and parts[0] in FLATPAK_TLDS else "winget"
    return "repology"


def alt_license(alt: str, kind: str) -> tuple[bool, str | None]:
    """(exists, license string if known)."""
    if kind == "flatpak":
        status, data = fetch(f"https://flathub.org/api/v2/appstream/{alt}")
        return status == 200 and data is not None, (data or {}).get("project_license")
    if kind == "winget":
        token = os.environ.get("GITHUB_TOKEN")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        publisher, _, rest = alt.partition(".")
        path = f"manifests/{publisher[0].lower()}/{publisher}/{rest.replace('.', '/')}"
        status, _ = fetch(f"https://api.github.com/repos/microsoft/winget-pkgs/contents/{path}", headers)
        return status == 200, None
    time.sleep(1.1)  # Repology asks for at most one request per second
    status, data = fetch(f"https://repology.org/api/v1/project/{alt.lower()}")
    if status != 200 or not data:
        return False, None
    found = sorted({lic for pkg in data for lic in pkg.get("licenses", [])})
    return True, " OR ".join(f"({x})" for x in found) or None


def check_online(path: Path, entries: list[dict[str, Any]], seen: dict[str, str]) -> list[str]:
    problems = []
    for e in entries:
        if ref := e.get("reference"):
            if ref not in seen:
                status, _ = fetch(ref)
                seen[ref] = "ok" if 200 <= status < 400 else f"HTTP {status or 'error'}"
            if seen[ref] != "ok":
                problems.append(f"{path.name}: {e['name']}: reference {ref} -> {seen[ref]}")
        for alt in e.get("alternatives", []):
            kind = ecosystem(alt)
            if kind is None:
                continue
            key = f"{kind}:{alt}"
            if key not in seen:
                exists, lic = alt_license(alt, kind)
                if not exists:
                    seen[key] = f"not found on {kind}"
                elif lic and licenses.classify(lic) is not Status.FREE:
                    seen[key] = f"license {lic!r} is not clearly free"
                else:
                    seen[key] = "ok"
            if seen[key] != "ok":
                # Repology keys projects by normalized names (e.g. fonts:dejavu, not ttf-dejavu),
                # so a miss there needs a human look rather than failing the check.
                prefix = "warning: " if seen[key] == "not found on repology" else ""
                problems.append(f"{prefix}{path.name}: {e['name']}: alternative {alt!r} {seen[key]}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("files", nargs="*", help="list names (default: all)")
    args = parser.parse_args()
    paths = [LISTS / f"{n}.json" for n in args.files] or sorted(LISTS.glob("*.json"))
    problems: list[str] = []
    seen: dict[str, str] = {}
    for path in paths:
        entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
        problems += check_offline(path, entries)
        if args.online:
            problems += check_online(path, entries, seen)
    for line in problems:
        print(line)
    errors = [p for p in problems if not p.startswith("warning: ")]
    print(f"{len(errors)} problem(s), {len(problems) - len(errors)} warning(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
